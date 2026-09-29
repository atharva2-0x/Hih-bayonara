"""Offline verification of a trial export.

The verifier needs nothing from the platform except the export file (and,
optionally, the Authority's public key to pin). It recomputes everything:

1. ledger hash chain, sequence numbers, Merkle checkpoints, Ed25519 signatures
2. the lifecycle walk is legal
3. registered commitments == those in the trial record; revealed artifacts open them
4. every CASE event: salted case hash and salted record hash match the
   revealed records, and each record's output hash matches its output
5. every submitted case is in red's committed payload set (static mode)
6. purity: F_pre == F_post
7. isolation certificate hash matches ARMED, with no unaccepted failures
   (a local-sim certificate is reported as a warning, never a pass)
8. the ATTESTED checkpoint exists in the signed checkpoint list
9. optional deterministic **replay** of every case through a fresh enclave +
   model built from the revealed bundle, comparing output hashes and verdicts
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections import Counter
from dataclasses import dataclass, field

from ..authority.ledger import verify_ledger_export
from ..authority.trial import is_legal_path
from ..common.crypto import canonical_json, salted_hash, sha256_hex, verify_commitment
from ..drill.drill import cert_hash

LIFECYCLE = ("REGISTERED", "ARMED", "RUNNING", "CONCLUDED", "REVEALED", "ATTESTED", "INVALIDATED")


@dataclass
class Check:
    name: str
    status: str  # pass | fail | warn | skip
    detail: str


@dataclass
class Verification:
    trial_id: str
    trial_name: str
    state: str
    checks: list[Check] = field(default_factory=list)
    first_bad_seq: int | None = None

    def add(self, name: str, status: str, detail: str) -> None:
        self.checks.append(Check(name, status, detail))

    @property
    def ok(self) -> bool:
        return all(c.status != "fail" for c in self.checks)

    @property
    def warnings(self) -> int:
        return sum(c.status == "warn" for c in self.checks)

    def to_dict(self) -> dict:
        return {"trial_id": self.trial_id, "trial_name": self.trial_name, "state": self.state, "ok": self.ok,
                "warnings": self.warnings, "first_bad_seq": self.first_bad_seq,
                "checks": [c.__dict__ for c in self.checks]}


def _events_for(export: dict, trial_id: str) -> tuple[list[dict], list[str]]:
    evs, problems = [], []
    for e in export["ledger"]["events"]:
        if e["trial_id"] != trial_id:
            continue
        try:
            evs.append({**e, "body": json.loads(e["body_json"])})
        except ValueError:
            problems.append(f"seq {e['seq']}: body is not valid JSON")
    return evs, problems


def verify_export(export: dict, pinned_public_key: str | None = None, replay: str | None = None) -> Verification:
    tr = export["trial"]
    v = Verification(tr["id"], tr.get("name", ""), tr["state"])

    # 1. ledger
    lr = verify_ledger_export(export["ledger"], pinned_public_key)
    v.first_bad_seq = lr.first_bad_seq
    v.add("ledger integrity", "pass" if lr.ok else "fail",
          f"{lr.events} events, {lr.checkpoints} signed checkpoint{'s' * (lr.checkpoints != 1)}"
          + ("" if lr.ok else f"; first bad seq {lr.first_bad_seq}: {lr.problems[0]}"))
    evs, parse_problems = _events_for(export, tr["id"])
    if parse_problems:
        v.add("event bodies", "fail", parse_problems[0])
    by_type: dict[str, list[dict]] = {}
    for e in evs:
        by_type.setdefault(e["type"], []).append(e["body"])

    # 2. lifecycle
    path = [e["type"] for e in evs if e["type"] in LIFECYCLE]
    legal = is_legal_path(path)
    v.add("lifecycle", "pass" if legal and path and path[-1] == tr["state"] else "fail",
          " → ".join(["DRAFT"] + path))

    reg = (by_type.get("REGISTERED") or [None])[0]
    if reg is None:
        v.add("pre-registration", "fail", "no REGISTERED event")
        return v
    cm = tr["commitments"]
    same = reg["c_red"] == cm["red"]["commitment"] and reg["c_blue"] == cm["blue"]["commitment"]
    v.add("pre-registration", "pass" if same else "fail",
          f"C_red {reg['c_red'][:12]}…, C_blue {reg['c_blue'][:12]}… "
          + ("match the trial record" if same else "DO NOT match the trial record"))

    # 7. isolation certificate
    armed = (by_type.get("ARMED") or [None])[0]
    if armed and tr.get("cert"):
        cert = tr["cert"]
        s = cert["summary"]
        hash_ok = cert_hash(cert) == armed["cert_hash"]
        unaccepted = [i for i in s["failed_ids"] if i not in armed.get("accepted_risks", [])]
        pos_ok = s["positive_controls"]["pass"] == s["positive_controls"]["total"]
        detail = (f"profile {cert['profile']}: {s['pass']} pass / {s['fail']} fail / {s['skip']} skip, "
                  f"positive controls {s['positive_controls']['pass']}/{s['positive_controls']['total']}")
        if armed.get("accepted_risks"):
            detail += f", accepted risks: {', '.join(armed['accepted_risks'])}"
        if not hash_ok or unaccepted or not pos_ok:
            v.add("isolation certificate", "fail",
                  detail + ("" if hash_ok else "; certificate hash does not match ARMED"))
        elif cert["profile"] != "docker" or s["skip"]:
            v.add("isolation certificate", "warn", detail + "; isolation NOT enforced (simulation)")
        else:
            v.add("isolation certificate", "pass", detail)
    elif tr["state"] not in ("INVALIDATED",):
        v.add("isolation certificate", "fail", "trial was never armed with a certificate")

    # 6. purity
    concluded = (by_type.get("CONCLUDED") or [None])[0]
    if armed and concluded:
        same_fp = armed["f_pre"] == concluded["f_post"] == tr.get("f_pre") == tr.get("f_post")
        v.add("model purity", "pass" if same_fp else "fail",
              f"F_pre {armed['f_pre'][:12]}… {'==' if same_fp else '!='} F_post {concluded['f_post'][:12]}…")
        digest_ok = armed["model_digest"] == reg["model_digest"] == tr.get("model_digest")
        v.add("model digest pinned", "pass" if digest_ok else "fail", f"{reg['model_digest'][:16]}…")

    if tr["state"] == "INVALIDATED":
        inv = (by_type.get("INVALIDATED") or [{}])[0]
        v.add("invalidation recorded", "pass" if inv else "fail",
              f"reason: {inv.get('reason')} (source: {inv.get('source')})")
        return v

    if tr["state"] not in ("REVEALED", "ATTESTED"):
        v.add("reveal", "skip", "trial not revealed yet; sealed records cannot be checked")
        return v

    # 4. commitments open
    reveals = tr["reveals"]
    arts = {}
    for role, key in (("red", "c_red"), ("blue", "c_blue")):
        rv = reveals.get(role)
        art = base64.b64decode(rv["artifact_b64"]) if rv else b""
        arts[role] = art
        ok = bool(rv) and verify_commitment(reg[key], art, rv["nonce"])
        v.add(f"commitment opens ({role})", "pass" if ok else "fail",
              f"H(artifact ‖ nonce) {'==' if ok else '!='} {key}")

    # salted hashes vs records
    salt = (by_type.get("REVEALED") or [{}])[0].get("salt")
    if salt != tr.get("salt"):
        v.add("salt", "fail", "salt in ledger differs from export")
    records = {r["record"]["case_no"]: r for r in (tr.get("records") or [])}
    case_events = by_type.get("CASE", [])
    bad = []
    for ce in case_events:
        r = records.get(ce["case_no"])
        if (r is None or ce["case_commit"] != salted_hash(salt, r["text"])
                or ce["record_commit"] != salted_hash(salt, canonical_json(r["record"]))
                or r["record"]["output_sha256"] != sha256_hex((r["output"] or "").encode())):
            bad.append(ce["case_no"])
    v.add("sealed records", "pass" if not bad and len(case_events) == len(records) else "fail",
          f"{len(case_events)} CASE events vs {len(records)} revealed records"
          + (f"; mismatching case_no {bad[:5]}" if bad else "; every salted hash matches"))

    # 5. membership
    try:
        payload = json.loads(arts["red"])
        allowed = {c["text"]: c["expect"] for c in payload["cases"]}
        outside = [n for n, r in records.items() if allowed.get(r["text"]) != r["record"]["expect"]]
        mode = cm["red"].get("mode", "static")
        if mode == "adaptive":
            v.add("cases ⊆ committed set", "skip", "adaptive mode: red committed to a strategy, not a set")
        else:
            v.add("cases ⊆ committed set", "pass" if not outside else "fail",
                  f"{len(records)} submitted, {len(allowed)} committed"
                  + (f"; outside set: {outside[:5]}" if outside else ""))
    except (ValueError, KeyError, TypeError):
        v.add("cases ⊆ committed set", "fail", "red artifact is not a payload set")

    # 8. attestation
    att = (by_type.get("ATTESTED") or [None])[0]
    if att:
        cps = {(c["upto_seq"], c["merkle_root"]) for c in export["ledger"]["checkpoints"]}
        ok = (att["upto_seq"], att["merkle_root"]) in cps
        v.add("attestation", "pass" if ok else "fail",
              f"signed Merkle root {att['merkle_root'][:16]}… over seq 1..{att['upto_seq']}")

    counts = Counter(r["record"]["outcome"] for r in records.values())
    v.add("outcomes", "pass", ", ".join(f"{k}={n}" for k, n in sorted(counts.items())) or "no cases")

    # 9. replay
    if replay:
        v.add(*_replay(tr, arts["blue"], records, reg["model_digest"], replay))
    return v


def _replay(tr: dict, bundle: bytes, records: dict, digest: str, mode: str) -> tuple[str, str, str]:
    import httpx

    from ..zones.enclave.app import build_enclave_app
    from ..zones.model.app import build_model_data_app
    from ..zones.model.backends import LlamaCppBackend, StubBackend

    backend = StubBackend(time_scale=0.0) if mode == "stub" else LlamaCppBackend(mode)
    if backend.digest != digest:
        return ("deterministic replay", "fail", f"replay model digest {backend.digest[:16]}… != trial {digest[:16]}…")
    model = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_model_data_app(backend)), base_url="http://m")
    enclave = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_enclave_app(model)), base_url="http://e")
    cfg = tr["config"]

    async def go() -> list[int]:
        r = await enclave.post("/v1/load", json={"trial_id": tr["id"], "bundle_b64": base64.b64encode(bundle).decode()})
        r.raise_for_status()
        mism = []
        for n, rec in sorted(records.items()):
            rr = (await enclave.post("/v1/process", json={
                "trial_id": tr["id"], "session": "red.replay", "text": rec["text"],
                "max_tokens": cfg["max_tokens"], "seed": cfg["seed"]})).json()
            if rr["verdict"] != rec["record"]["verdict"] or \
                    sha256_hex((rr.get("output") or "").encode()) != rec["record"]["output_sha256"]:
                mism.append(n)
        return mism

    mism = asyncio.run(go())
    return ("deterministic replay", "pass" if not mism else "fail",
            f"{len(records) - len(mism)}/{len(records)} cases reproduced bit-for-bit"
            + (f"; diverged: {mism[:5]}" if mism else ""))
