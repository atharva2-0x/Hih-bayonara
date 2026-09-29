"""Scripted demo scenarios (terminal demo, War Room buttons, tests).

Scenarios:
    standard       full trial -> ATTESTED, export, verify (+ replay)
    canary         canary drill mid-trial -> INVALIDATED
    contamination  model state survives sessions -> purity drift -> INVALIDATED
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Callable

from .local import LocalStack
from .tools.tamper import tamper_export
from .verifier.core import verify_export

Log = Callable[[str], None]


async def _create(stack: LocalStack, name: str, equalizer: bool, bucket_ms: int) -> str:
    r = await stack.operator_http.post("/v1/trials", json={
        "name": name, "config": {"equalizer": {"enabled": equalizer, "bucket_ms": bucket_ms}}})
    r.raise_for_status()
    return r.json()["id"]


async def _pause(s: float) -> None:
    if s:
        await asyncio.sleep(s)


async def run_scenario(stack: LocalStack, scenario: str = "standard", *, name: str | None = None, equalizer: bool = True,
                       bucket_ms: int = 150, pace_s: float = 0.0, phase_pause_s: float = 0.0,
                       limit: int | None = None, exports_dir: str | Path | None = None,
                       log: Log = print) -> dict:
    op = stack.operator_http
    tid = await _create(stack, (name or f"{scenario}-demo")[:80], equalizer, bucket_ms)
    log(f"▸ trial {tid} created ({scenario}, equalizer {'on' if equalizer else 'off'}, bucket {bucket_ms} ms)")
    await _pause(phase_pause_s)

    await stack.red.commit(tid)
    log("▸ red committed H(payload_set ‖ nonce)")
    await stack.blue.commit(tid)
    log("▸ blue committed H(defense_bundle ‖ nonce) → REGISTERED")
    await stack.blue.upload(tid)
    log("▸ blue bundle uploaded and sealed with the trial key")
    await _pause(phase_pause_s)

    r = await op.post(f"/v1/trials/{tid}/arm")
    if r.status_code != 200:
        log(f"✖ arming refused: {r.json().get('detail')}")
        return {"trial_id": tid, "state": "INVALIDATED"}
    armed = r.json()
    s = armed["cert_summary"]
    log(f"▸ breach drill: {s['pass']} pass / {s['fail']} fail / {s['skip']} skip → isolation certificate issued")
    log(f"▸ purity fingerprint F_pre = {armed['f_pre'][:16]}…")
    await _pause(phase_pause_s)
    await op.post(f"/v1/trials/{tid}/start")
    log("▸ RUNNING: red submits cases; blue's lane stays sealed")

    if scenario == "contamination":
        stack.backend.persistent_memory = True  # type: ignore[attr-defined]

    n_seen = {"n": 0}

    def on_result(o: dict) -> None:
        n_seen["n"] += 1

    run_limit = limit if scenario == "standard" else (limit or 8)
    obs = await stack.red.run(tid, limit=run_limit, concurrency=1 if pace_s else 4, on_result=on_result, pace_s=pace_s)
    statuses = {st: sum(o["status"] == st for o in obs) for st in ("ANSWERED", "REFUSED")}
    sizes = sorted({o["size"] for o in obs})
    log(f"▸ {len(obs)} cases: red saw {statuses['ANSWERED']} answered / {statuses['REFUSED']} refused; "
        f"response sizes seen by red: {sizes}")

    if scenario == "canary":
        await _pause(phase_pause_s)
        d = (await op.post(f"/v1/trials/{tid}/drill/canary")).json()
        log(f"▸ canary drill: synthetic blue canary arrives from red → detected={d['detected']} in "
            f"{d['detection_ms']} ms → {d['state']}")
        return {"trial_id": tid, "state": d["state"], "canary": d}

    await _pause(phase_pause_s)
    await op.post(f"/v1/trials/{tid}/conclude")
    if scenario == "contamination":
        stack.backend.persistent_memory = False  # type: ignore[attr-defined]
        stack.backend._memory.clear()  # type: ignore[attr-defined]
    st = (await op.get(f"/v1/trials/{tid}")).json()
    if st["state"] == "INVALIDATED":
        log(f"✖ {st['invalid_reason']} → INVALIDATED")
        return {"trial_id": tid, "state": st["state"], "reason": st["invalid_reason"]}
    log("▸ CONCLUDED: tokens revoked, F_post == F_pre, replica reset")
    await _pause(phase_pause_s)

    await stack.red.reveal(tid)
    final = await stack.blue.reveal(tid)
    log(f"▸ REVEAL ceremony: both commitments opened and verified → {final['state']}")
    rep = await stack.blue.report(tid)
    sm = rep["summary"]
    log(f"▸ results: attack success {sm['attack_success_rate']}, false positives {sm['false_positive_rate']}, "
        f"leaks contained {sm['leaks_contained']}, outcomes {sm['outcomes']}")

    export = (await op.get(f"/v1/trials/{tid}/export")).json()
    out = {"trial_id": tid, "state": final["state"], "summary": sm}
    if exports_dir:
        p = Path(exports_dir) / f"{tid}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(export))
        out["export"] = str(p)
        log(f"▸ export written to {p}")
    return out


class Demo:
    """Attached to the operator listener in `serve` mode (War Room buttons)."""

    def __init__(self, stack: LocalStack | None = None, exports_dir: str | Path = "exports"):
        self.stack = stack
        self.exports_dir = Path(exports_dir)
        self.tasks: set = set()
        self._lock = asyncio.Lock()

    async def run(self, opts: dict) -> dict:
        assert self.stack is not None
        async with self._lock:
            opts = {k: v for k, v in opts.items() if k in ("scenario", "name", "equalizer", "bucket_ms", "limit")}
            if opts.get("scenario") not in (None, "standard", "canary", "contamination"):
                opts.pop("scenario")
            return await run_scenario(self.stack, pace_s=0.12, phase_pause_s=1.0, exports_dir=self.exports_dir,
                                      log=lambda m: self.stack.authority.bus.publish({"type": "log", "msg": m}),
                                      **opts)

    async def tamper(self) -> dict:
        exports = sorted(self.exports_dir.glob("t-*.json"), key=lambda p: p.stat().st_mtime)
        if not exports:
            return {"error": "run a standard trial first"}
        export = json.loads(exports[-1].read_text())
        original = verify_export(export)
        tampered, seq = tamper_export(export)
        broken = verify_export(tampered)
        return {"trial_id": export["trial"]["id"], "seq": seq,
                "original": {"ok": original.ok, "warnings": original.warnings},
                "tampered": {"ok": broken.ok, "first_bad_seq": broken.first_bad_seq,
                             "problem": next((c.detail for c in broken.checks if c.status == "fail"), None)}}
