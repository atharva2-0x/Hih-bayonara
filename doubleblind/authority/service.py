"""The Trial Authority: the Arbiter's orchestration logic.

The Arbiter is the only component attached to every zone. Every cross-zone
message goes through it, every step is authorised by the policy engine
against the trial's state, and every step is written to the ledger.

Blinding guarantees implemented here:

* **Pre-registration:** red and blue submit commitments before anything runs.
* **Sealed records:** case text, model output and verdicts are encrypted
  with a per-trial key the moment they exist. The ledger holds only *salted*
  hashes, so even someone holding a public benchmark cannot test which prompts
  were used.
* **Equalized responses:** red sees canonical, size- and time-bucketed
  responses only.
* **Containment:** a foreign canary heading to a tenant is withheld at the
  boundary; a foreign canary *arriving from* a tenant invalidates the trial.
* **Purity:** F_pre and F_post must match, otherwise the trial is INVALIDATED.
* **Reveal:** commitments are opened and checked, the salt is published and
  a signed Merkle checkpoint attests the trial.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any

import httpx

from ..common.crypto import (
    TokenError,
    canonical_json,
    salted_hash,
    seal,
    sha256_hex,
    unseal,
    verify_commitment,
)
from ..common.telemetry import Alert, TelemetryEvent
from ..drill.drill import DrillProvider, cert_hash
from ..observability.canary import scan
from ..zones.enclave.bundle import Bundle, BundleError
from .equalizer import Equalizer, EqualizerConfig
from .judge import judge
from .keybroker import KeyBroker
from .ledger import Ledger
from .policy import NO_TRIAL, PolicyDenied, PolicyEngine
from .trial import TERMINAL, State, Trial

EXPORT_FORMAT = "doubleblind-trial-export/v1"
PAYLOAD_FORMAT = "doubleblind-payload-set/v1"
TENANTS = ("red", "blue")


class AuthorityError(Exception):
    status = 400


class NotFound(AuthorityError):
    status = 404


class Conflict(AuthorityError):
    status = 409


class Unauthorized(AuthorityError):
    status = 401


class Invalid(AuthorityError):
    status = 422


class ZoneUnavailable(AuthorityError):
    status = 503


@dataclass
class AuthorityDeps:
    ledger: Ledger
    policy: PolicyEngine
    keys: KeyBroker
    enclave: httpx.AsyncClient
    model_admin: httpx.AsyncClient
    obs: httpx.AsyncClient
    drill: DrillProvider


DEFAULT_CONFIG = {
    "equalizer": EqualizerConfig().to_dict(),
    "case_budget": 1000,
    "max_tokens": 160,
    "seed": 7,
    "token_ttl_s": 3600,
    "accepted_risks": [],
    "require_isolation": False,
}


def _size_bucket(n: int) -> int:
    b = 256
    while b < n:
        b *= 2
    return b


class EventBus:
    """Metadata-only event feed for the War Room (never payloads or verdicts)."""

    def __init__(self, maxlen: int = 1000):
        self.history: deque[dict] = deque(maxlen=maxlen)
        self.subscribers: set[asyncio.Queue] = set()
        self._seq = 0

    def publish(self, ev: dict) -> None:
        self._seq += 1
        ev = {"n": self._seq, "ts": time.time(), **ev}
        self.history.append(ev)
        for q in list(self.subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)


class Authority:
    def __init__(self, deps: AuthorityDeps):
        self.d = deps
        self.trials: dict[str, Trial] = {}
        self.bus = EventBus()
        self._locks: dict[str, asyncio.Lock] = {}
        deps.ledger.on_append = self._on_ledger_append

    # ------------------------------------------------------------------ helpers

    def _on_ledger_append(self, ev: dict) -> None:
        self.bus.publish({"type": "ledger", "seq": ev["seq"], "etype": ev["type"], "trial_id": ev["trial_id"],
                          "hash": ev["hash"][:16]})

    def _state_event(self, t: Trial) -> None:
        self.bus.publish({"type": "state", "trial_id": t.id, "state": t.state.value, "name": t.name,
                          "reason": t.invalid_reason})

    def _get(self, trial_id: str) -> Trial:
        t = self.trials.get(trial_id)
        if t is None:
            raise NotFound(f"no such trial {trial_id}")
        return t

    def _lock(self, trial_id: str) -> asyncio.Lock:
        return self._locks.setdefault(trial_id, asyncio.Lock())

    def _dek(self, t: Trial) -> bytes:
        return self.d.keys.unwrap(t.dek_wrapped)

    def _log(self, t: Trial | None, etype: str, body: dict) -> dict:
        return self.d.ledger.append(t.id if t else "-", etype, body)

    async def _telemetry(self, **kw) -> dict:
        ev = TelemetryEvent(**kw)
        try:
            r = await self.d.obs.post("/v1/telemetry", json=ev.model_dump())
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as exc:
            if ev.canary_fps:
                # Fail closed: without the watcher we cannot tell whether this
                # message carries another tenant's secret.
                raise ZoneUnavailable("observability zone unavailable; boundary check failed closed") from exc
            return {"verdict": "unknown"}

    async def _authorize(self, role: str, action: str, t: Trial | None) -> None:
        state = t.state.value if t else NO_TRIAL
        try:
            self.d.policy.require(role, action, state)
        except PolicyDenied:
            if t is not None and role in TENANTS:
                await self._telemetry(kind="policy_denial", trial_id=t.id, zone_from=role, code=action)
            raise

    async def _zone(self, client: httpx.AsyncClient, path: str, payload: dict | None = None,
                    method: str = "POST") -> dict:
        try:
            r = await (client.post(path, json=payload) if method == "POST" else client.get(path))
        except httpx.HTTPError as exc:
            raise ZoneUnavailable(f"zone call {path} failed: {type(exc).__name__}") from exc
        if r.status_code >= 400:
            raise ZoneUnavailable(f"zone call {path} returned {r.status_code}: {r.text[:200]}")
        return r.json()

    # ------------------------------------------------------------------ lifecycle

    async def create_trial(self, role: str, name: str, config: dict | None = None) -> dict:
        await self._authorize(role, "trial:create", None)
        unknown = set(config or {}) - set(DEFAULT_CONFIG)
        if unknown:
            raise Invalid(f"unknown config keys: {sorted(unknown)}")
        cfg = {**DEFAULT_CONFIG, **(config or {})}
        cfg["equalizer"] = EqualizerConfig.from_dict(cfg.get("equalizer")).to_dict()
        if not 1 <= int(cfg["case_budget"]) <= 100_000:
            raise Invalid("case_budget out of range")
        t = Trial(name=name[:80] or "trial", config=cfg)
        _, t.dek_wrapped = self.d.keys.new_dek()
        self.trials[t.id] = t
        self._log(t, "CREATED", {"name": t.name, "config": cfg, "config_hash": sha256_hex(canonical_json(cfg)),
                                 "policy_hash": self.d.policy.hash})
        self._state_event(t)
        return t.public_view()

    async def submit_commitment(self, role: str, trial_id: str, body: dict) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "commitment:submit", t)
        async with self._lock(trial_id):
            if role in t.commitments:
                raise Conflict(f"{role} has already committed")
            entry = {"commitment": body["commitment"], "canary_fp": body["canary_fp"]}
            if role == "red":
                entry["mode"] = body.get("mode", "static")
                entry["declared_cases"] = body.get("declared_cases")
            await self._zone(self.d.obs, "/v1/canaries",
                             {"trial_id": t.id, "owner": role, "fingerprint": body["canary_fp"]})
            t.commitments[role] = entry
            self._log(t, "COMMITTED", {"role": role, "commitment": entry["commitment"]})
            if all(r in t.commitments for r in TENANTS):
                desc = await self._zone(self.d.model_admin, "/v1/admin/describe", method="GET")
                t.model_digest = desc["digest"]
                t.policy_hash = self.d.policy.hash
                t.transition(State.REGISTERED, "both commitments received")
                self._log(t, "REGISTERED", {
                    "c_red": t.commitments["red"]["commitment"],
                    "c_blue": t.commitments["blue"]["commitment"],
                    "red_mode": t.commitments["red"]["mode"],
                    "declared_cases": t.commitments["red"]["declared_cases"],
                    "model_digest": t.model_digest,
                    "model_backend": desc.get("backend"),
                    "policy_hash": t.policy_hash,
                    "equalizer": t.config["equalizer"],
                })
                self._state_event(t)
        return t.public_view()

    async def upload_bundle(self, role: str, trial_id: str, bundle_b64: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "bundle:upload", t)
        raw = base64.b64decode(bundle_b64)
        try:
            Bundle.parse(raw)
        except BundleError as exc:
            raise Invalid(f"bundle rejected: {exc}") from exc
        t.bundle_sha256 = sha256_hex(raw)
        t.bundle_sealed = seal(self._dek(t), raw, f"{t.id}:bundle".encode())
        # No hash of the bundle goes into the ledger before REVEAL (it would let
        # red confirm a guessed bundle); only its size bucket.
        self._log(t, "BUNDLE_SEALED", {"size_bucket": _size_bucket(len(raw))})
        return {"sealed": True}

    async def arm(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "trial:arm", t)
        if not t.bundle_sealed:
            raise Conflict("blue has not uploaded its defense bundle")
        cert = await self.d.drill.certificate()
        s = cert["summary"]
        accepted = set(t.config.get("accepted_risks", []))
        unaccepted = [i for i in s["failed_ids"] if i not in accepted]
        if t.config.get("require_isolation") and (cert["profile"] != "docker" or s["skip"]):
            unaccepted.append("require_isolation: certificate is not a full docker-profile certificate")
        if s["positive_controls"]["pass"] < s["positive_controls"]["total"]:
            unaccepted.append("positive controls failed: the drill itself is not trustworthy")
        t.cert = cert
        t.cert_hash = cert_hash(cert)
        if unaccepted:
            await self.invalidate("operator", t.id, f"breach drill failed: {', '.join(unaccepted)[:300]}",
                                  source="breach-drill")
            raise Conflict("breach drill failed; trial invalidated")
        await self._zone(self.d.model_admin, "/v1/admin/reset", {"trial_id": t.id})
        fp = await self._zone(self.d.model_admin, "/v1/admin/fingerprint", {"trial_id": t.id, "phase": "pre"})
        if fp["model_digest"] != t.model_digest:
            await self.invalidate("operator", t.id, "model digest changed after registration", source="arm")
            raise Conflict("model digest changed; trial invalidated")
        t.f_pre = fp["fingerprint"]
        raw = unseal(self._dek(t), t.bundle_sealed, f"{t.id}:bundle".encode())
        loaded = await self._zone(self.d.enclave, "/v1/load",
                                  {"trial_id": t.id, "bundle_b64": base64.b64encode(raw).decode()})
        if loaded["bundle_sha256"] != t.bundle_sha256:
            await self.invalidate("operator", t.id, "enclave loaded a different bundle", source="arm")
            raise Conflict("enclave bundle mismatch; trial invalidated")
        t.transition(State.ARMED, "drill passed, purity recorded, bundle sealed in enclave")
        self._log(t, "ARMED", {
            "cert_hash": t.cert_hash, "cert_profile": cert["profile"],
            "cert_summary": {k: s[k] for k in ("total", "pass", "fail", "skip", "positive_controls")},
            "accepted_risks": sorted(set(s["failed_ids"]) & accepted),
            "f_pre": t.f_pre, "model_digest": fp["model_digest"],
        })
        self._state_event(t)
        self.bus.publish({"type": "drill", "trial_id": t.id, "profile": cert["profile"], "summary": s})
        self.bus.publish({"type": "purity", "trial_id": t.id, "phase": "pre", "fingerprint": t.f_pre[:16]})
        return {**t.public_view(), "cert_summary": s, "f_pre": t.f_pre}

    async def start(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "trial:start", t)
        t.transition(State.RUNNING, "operator start")
        self._log(t, "RUNNING", {})
        self._state_event(t)
        return t.public_view()

    async def obtain_session(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "session:obtain", t)
        ttl = int(t.config["token_ttl_s"])
        token = self.d.keys.issue(t.id, role, ["case:submit"], ttl)
        self._log(t, "SESSION_ISSUED", {"role": role, "ttl_s": ttl})
        return {"token": token, "expires_in": ttl}

    # ------------------------------------------------------------------ the data path

    async def submit_case(self, role: str, trial_id: str, token: str, body: dict) -> dict:
        t0 = time.monotonic()
        t = self._get(trial_id)
        await self._authorize(role, "case:submit", t)
        try:
            self.d.keys.check(token, t.id, role, "case:submit")
        except TokenError as exc:
            await self._telemetry(kind="token_denial", trial_id=t.id, zone_from=role, code="case:submit")
            raise Unauthorized(str(exc)) from exc
        text: str = body["text"]
        eq = Equalizer(EqualizerConfig.from_dict(t.config["equalizer"]))

        async with self._lock(t.id):
            if t.case_count >= int(t.config["case_budget"]):
                raise Conflict("case budget exhausted")
            t.case_count += 1
            case_no = t.case_count

        # Boundary 1: inbound from the tenant.
        chk = await self._telemetry(kind="boundary", trial_id=t.id, zone_from=role, zone_to="authority",
                                    size_bytes=len(text.encode()), canary_fps=scan(text))
        if chk.get("verdict") == "breach":
            await self.invalidate("observability", t.id, f"foreign canary received from {role}", source="dlp")
            raise Conflict("isolation breach detected; trial invalidated")

        session = f"{role}.{body.get('session') or 'default'}"
        res = await self._zone(self.d.enclave, "/v1/process", {
            "trial_id": t.id, "session": session, "text": text,
            "max_tokens": int(t.config["max_tokens"]), "seed": int(t.config["seed"]),
        })
        verdict = judge(body["expect"], res["verdict"], res.get("output"))
        answered = verdict["answered"]
        red_text = res.get("output")

        # Boundary 2: outbound to the tenant. Scan exactly what red would see.
        visible = red_text if (answered or not eq.cfg.enabled) else None
        chk_out = await self._telemetry(kind="boundary", trial_id=t.id, zone_from="authority", zone_to=role,
                                        size_bytes=len((visible or "").encode()), canary_fps=scan(visible))
        contained = chk_out.get("verdict") in ("contained", "breach")
        if contained:
            answered, red_text = False, None
            t.leaks_contained += 1
            self._log(t, "LEAK_CONTAINED", {"case_no": case_no})
            self.bus.publish({"type": "leak_contained", "trial_id": t.id, "case_no": case_no})

        record = {
            "case_no": case_no, "case_id": body["case_id"], "expect": body["expect"],
            "verdict": res["verdict"], "reason_code": res.get("reason_code"),
            "outcome": verdict["outcome"], "attack_success": verdict["attack_success"] and not contained,
            "guard_blocked": verdict["guard_blocked"], "model_refused": verdict["model_refused"],
            "contained": contained, "output_sha256": sha256_hex((res.get("output") or "").encode()),
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        }
        sealed = seal(self._dek(t), canonical_json({"record": record, "text": text, "output": res.get("output")}),
                      f"{t.id}:{case_no}".encode())
        case_commit = salted_hash(t.salt_hex, text)
        t.sealed_records[case_no] = sealed
        t.case_commits[case_no] = case_commit
        self._log(t, "CASE", {
            "case_no": case_no,
            "case_commit": case_commit,
            "record_commit": salted_hash(t.salt_hex, canonical_json(record)),
            "sealed_sha256": sha256_hex(sealed.encode()),
        })
        await self._telemetry(kind="case_timing", trial_id=t.id, zone_from="enclave", zone_to="authority",
                              duration_ms=record["latency_ms"])

        view = eq.shape(answered, red_text, {"case_no": case_no})
        rel = await eq.release(t0)
        self.bus.publish({"type": "case", "trial_id": t.id, "case_no": case_no, "commit": case_commit[:12],
                          "buckets": rel["buckets"], "spilled": rel["spilled"]})
        return view

    # ------------------------------------------------------------------ conclude / reveal

    async def conclude(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "trial:conclude", t)
        self.d.keys.revoke_trial(t.id)
        fp = await self._zone(self.d.model_admin, "/v1/admin/fingerprint", {"trial_id": t.id, "phase": "post"})
        t.f_post = fp["fingerprint"]
        await self._zone(self.d.model_admin, "/v1/admin/reset", {"trial_id": t.id})
        await self._zone(self.d.enclave, "/v1/unload", {"trial_id": t.id})
        purity_ok = t.f_post == t.f_pre
        t.transition(State.CONCLUDED, "operator conclude")
        self._log(t, "CONCLUDED", {"cases": t.case_count, "f_post": t.f_post, "purity_ok": purity_ok,
                                   "leaks_contained": t.leaks_contained})
        self.bus.publish({"type": "purity", "trial_id": t.id, "phase": "post", "fingerprint": t.f_post[:16],
                          "ok": purity_ok})
        self._state_event(t)
        if not purity_ok:
            await self.invalidate("operator", t.id, "purity fingerprint drift: model behaviour changed during the trial",
                                  source="purity")
        return t.public_view()

    async def reveal(self, role: str, trial_id: str, artifact_b64: str, nonce_hex: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "artifact:reveal", t)
        async with self._lock(t.id):
            if role in t.reveals:
                raise Conflict(f"{role} has already revealed")
            artifact = base64.b64decode(artifact_b64)
            ok = verify_commitment(t.commitments[role]["commitment"], artifact, nonce_hex)
            detail: dict[str, Any] = {"commitment_ok": ok}
            if ok and role == "red":
                detail.update(self._check_red_membership(t, artifact))
                ok = detail["membership_ok"]
            if ok and role == "blue":
                detail["bundle_matches_loaded"] = sha256_hex(artifact) == t.bundle_sha256
                ok = detail["bundle_matches_loaded"]
            t.reveals[role] = {"ok": ok, "artifact_b64": artifact_b64, "nonce": nonce_hex, **detail}
            self._log(t, "REVEAL", {"role": role, **detail})
        if not ok:
            await self.invalidate("operator", t.id, f"reveal check failed for {role}: {detail}", source="reveal")
            raise Invalid(f"reveal failed for {role}: {detail}")
        if all(t.reveals.get(r, {}).get("ok") for r in TENANTS):
            t.transition(State.REVEALED, "both commitments opened and verified")
            self._log(t, "REVEALED", {"salt": t.salt_hex})
            self._state_event(t)
            cp = self.d.ledger.checkpoint(reason=f"reveal {t.id}")
            t.checkpoint = cp
            t.transition(State.ATTESTED, "signed Merkle checkpoint")
            self._log(t, "ATTESTED", {"upto_seq": cp["upto_seq"], "merkle_root": cp["merkle_root"],
                                      "signature": cp["signature"]})
            self._state_event(t)
            self.bus.publish({"type": "checkpoint", "trial_id": t.id, "upto_seq": cp["upto_seq"],
                              "root": cp["merkle_root"][:16]})
        return {**t.public_view(), "reveal": {k: v for k, v in detail.items()}}

    def _check_red_membership(self, t: Trial, artifact: bytes) -> dict:
        try:
            payload = json.loads(artifact)
            cases = payload["cases"]
            assert payload.get("format") == PAYLOAD_FORMAT
        except (ValueError, KeyError, AssertionError, TypeError):
            return {"membership_ok": False, "problem": "payload set is not a valid payload-set document"}
        mode = t.commitments["red"].get("mode", "static")
        if mode == "adaptive":
            return {"membership_ok": True, "mode": "adaptive", "cases_in_set": len(cases)}
        allowed = {c["text"]: c["expect"] for c in cases}
        dek = self._dek(t)
        bad = []
        for case_no, sealed in t.sealed_records.items():
            rec = json.loads(unseal(dek, sealed, f"{t.id}:{case_no}".encode()))
            if allowed.get(rec["text"]) != rec["record"]["expect"]:
                bad.append(case_no)
        return {"membership_ok": not bad, "mode": "static", "cases_in_set": len(cases),
                "cases_submitted": len(t.sealed_records), "not_in_committed_set": bad[:20]}

    # ------------------------------------------------------------------ invalidation + alerts

    async def invalidate(self, role: str, trial_id: str, reason: str, source: str = "operator") -> dict:
        t = self._get(trial_id)
        if t.state in TERMINAL:
            return t.public_view()
        await self._authorize(role, "trial:invalidate" if role != "observability" else "alert:raise", t)
        self.d.keys.revoke_trial(t.id)
        for client, path, payload in ((self.d.enclave, "/v1/unload", {"trial_id": t.id}),
                                      (self.d.model_admin, "/v1/admin/reset", {"trial_id": t.id})):
            try:
                await client.post(path, json=payload)
            except httpx.HTTPError:
                pass
        t.invalid_reason = reason
        t.transition(State.INVALIDATED, reason)
        self._log(t, "INVALIDATED", {"reason": reason, "source": source})
        t.checkpoint = self.d.ledger.checkpoint(reason=f"invalidated {t.id}")
        self._state_event(t)
        return t.public_view()

    async def handle_alert(self, alert: Alert) -> dict:
        self.bus.publish({"type": "alert", **alert.model_dump()})
        t = self.trials.get(alert.trial_id)
        if t is None:
            return {"action": "none"}
        if t.state not in TERMINAL:
            self._log(t, "ALERT", {"kind": alert.kind, "severity": alert.severity, "zone": alert.zone})
        if alert.severity == "critical" and t.state not in TERMINAL:
            await self.invalidate("observability", t.id, f"observability alert: {alert.kind}", source="observability")
            return {"action": "invalidated"}
        return {"action": "logged"}

    async def canary_drill(self, role: str, trial_id: str) -> dict:
        """Prove the canary path end to end: plant a synthetic blue canary and
        present it as if it arrived from red (i.e. red had seen blue's secret)."""
        t = self._get(trial_id)
        await self._authorize(role, "drill:canary", t)
        tok = (await self._zone(self.d.obs, "/v1/drill/canary", {"trial_id": t.id, "owner": "blue"}))["token"]
        self._log(t, "CANARY_DRILL", {"owner": "blue"})
        t0 = time.monotonic()
        chk = await self._telemetry(kind="boundary", trial_id=t.id, zone_from="red", zone_to="authority",
                                    canary_fps=scan(f"simulated inbound message {tok}"))
        detected = chk.get("verdict") == "breach"
        if detected:
            await self.invalidate("observability", t.id, "canary drill: foreign canary received from red",
                                  source="canary-drill")
        return {"detected": detected, "detection_ms": round((time.monotonic() - t0) * 1000, 2),
                "state": t.state.value}

    # ------------------------------------------------------------------ results

    def _records(self, t: Trial) -> list[dict]:
        dek = self._dek(t)
        out = []
        for case_no in sorted(t.sealed_records):
            out.append(json.loads(unseal(dek, t.sealed_records[case_no], f"{t.id}:{case_no}".encode())))
        return out

    async def report(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "report:read", t)
        recs = self._records(t)
        adv = [r["record"] for r in recs if r["record"]["expect"] == "refuse"]
        ctl = [r["record"] for r in recs if r["record"]["expect"] == "comply"]
        outcomes = Counter(r["record"]["outcome"] for r in recs)
        summary = {
            "cases": len(recs),
            "adversarial": len(adv),
            "controls": len(ctl),
            "outcomes": dict(outcomes),
            "attack_success_rate": round(sum(r["attack_success"] for r in adv) / len(adv), 4) if adv else None,
            "false_positive_rate": round(sum(r["outcome"].startswith("false_positive") for r in ctl) / len(ctl), 4)
            if ctl else None,
            "leaks_contained": t.leaks_contained,
        }
        rows = []
        for r in recs:
            rec = r["record"]
            row = {"case_no": rec["case_no"], "case_id": rec["case_id"], "expect": rec["expect"],
                   "outcome": rec["outcome"], "contained": rec["contained"]}
            if self.d.policy.decide(role, "verdicts:read", t.state.value).allowed:
                row["layer"] = "guard" if rec["guard_blocked"] else "model" if rec["model_refused"] else "none"
                row["reason_code"] = rec["reason_code"]
            if self.d.policy.decide(role, "red_cases:read", t.state.value).allowed:
                row["text"] = r["text"]
            rows.append(row)
        return {"trial": t.public_view(), "summary": summary, "cases": rows}

    async def export(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "export:read", t)
        revealed = t.state in (State.REVEALED, State.ATTESTED)
        return {
            "format": EXPORT_FORMAT,
            "ledger": self.d.ledger.export(),
            "trial": {
                "id": t.id, "name": t.name, "state": t.state.value, "config": t.config,
                "commitments": t.commitments, "model_digest": t.model_digest, "policy_hash": t.policy_hash,
                "cert": t.cert, "f_pre": t.f_pre, "f_post": t.f_post,
                "reveals": {r: {"artifact_b64": v["artifact_b64"], "nonce": v["nonce"]} for r, v in t.reveals.items()},
                "salt": t.salt_hex if revealed else None,
                "records": self._records(t) if revealed else None,
                "invalid_reason": t.invalid_reason,
            },
        }

    # ------------------------------------------------------------------ views

    async def status(self, role: str, trial_id: str) -> dict:
        t = self._get(trial_id)
        await self._authorize(role, "trial:status", t)
        return t.public_view()

    def overview(self) -> dict:
        trials = []
        for t in sorted(self.trials.values(), key=lambda x: x.created_at, reverse=True):
            v = t.public_view()
            v.update({
                "cert_profile": t.cert["profile"] if t.cert else None,
                "cert_summary": t.cert["summary"] if t.cert else None,
                "f_pre": t.f_pre[:16] if t.f_pre else None,
                "f_post": t.f_post[:16] if t.f_post else None,
                "leaks_contained": t.leaks_contained,
                "checkpoint": {k: t.checkpoint[k] for k in ("upto_seq", "merkle_root")} if t.checkpoint else None,
                "equalizer": t.config["equalizer"]["enabled"],
                "history": [{"to": h["to"], "ts": h["ts"]} for h in t.history],
            })
            trials.append(v)
        seq, head = self.d.ledger.head()
        return {"trials": trials, "ledger": {"seq": seq, "head": head[:16],
                                             "public_key": self.d.ledger.signer.public_key_hex},
                "policy_hash": self.d.policy.hash}
