"""Isolation overhead: latency of benign control prompts in three setups.

    bare      direct call to the model data API with the same system prompt
              (no isolation at all)
    isolated  full DOUBLE-BLIND path (Arbiter + DLP + enclave + ledger), Equalizer off
    equalized full path with the Equalizer on

All three use the *identical* defense bundle and prompts, so the model does
exactly the same work and the difference is the isolation layer alone.
Objective 01 asks us to isolate *without breaking function*; this reports the
price of each layer honestly.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path

from ..local import asgi_client, build_local_stack
from ..zones.blue.workbench import BlueClient, package_bundle
from ..zones.model.app import build_model_data_app
from ..zones.red.datasets import CONTROLS
from .stats import summary


def control_suite(reps: int = 5) -> list[dict]:
    return [{"id": f"c-{r}-{i:02d}", "text": t, "expect": "comply"}
            for r in range(reps) for i, t in enumerate(CONTROLS) if "restricted" not in t]


async def _isolated(workdir: Path, equalizer: bool, bucket_ms: int, cases: list[dict],
                    bundle: tuple[bytes, str]) -> list[float]:
    s = build_local_stack(workdir, cases=cases)
    s.blue = BlueClient(s.blue_http, workdir / "blue", fixed_bundle=bundle)
    op = s.operator_http
    tid = (await op.post("/v1/trials", json={"name": "overhead", "config": {
        "equalizer": {"enabled": equalizer, "bucket_ms": bucket_ms}}})).json()["id"]
    await s.red.commit(tid)
    await s.blue.commit(tid)
    await s.blue.upload(tid)
    (await op.post(f"/v1/trials/{tid}/arm")).raise_for_status()
    await op.post(f"/v1/trials/{tid}/start")
    obs = await s.red.run(tid, concurrency=1)
    return [o["latency_ms"] for o in obs]


async def _bare(workdir: Path, cases: list[dict], system: str) -> list[float]:
    s = build_local_stack(workdir, cases=cases)
    model = asgi_client(build_model_data_app(s.backend), "model")
    lat = []
    for c in cases:
        t0 = time.perf_counter()
        r = await model.post("/v1/generate", json={"trial_id": "t-000000000000", "session": "bare", "system": system,
                                                   "prompt": c["text"], "max_tokens": 160, "seed": 7})
        r.raise_for_status()
        lat.append((time.perf_counter() - t0) * 1000)
    return lat


async def run(bucket_ms: int = 150, out: str | Path | None = None, log=print) -> dict:
    cases = control_suite()
    bundle = package_bundle()
    system = json.loads(bundle[0])["system_prompt"]
    with tempfile.TemporaryDirectory() as td:
        log("overhead: bare model …")
        bare = summary(await _bare(Path(td) / "bare", cases, system))
        log("overhead: isolated path, Equalizer off …")
        iso = summary(await _isolated(Path(td) / "iso", False, bucket_ms, cases, bundle))
        log("overhead: isolated path, Equalizer on …")
        eq = summary(await _isolated(Path(td) / "eq", True, bucket_ms, cases, bundle))

    def pct(a, b):
        return round((a / b - 1) * 100, 1)

    res = {"benchmark": "isolation overhead", "environment": "local-sim (stub model, in-process zones)",
           "prompts": len(cases), "bucket_ms": bucket_ms,
           "bare": bare, "isolated": iso, "equalized": eq,
           "added_ms": {"isolated_p50": round(iso["p50"] - bare["p50"], 2),
                        "isolated_p95": round(iso["p95"] - bare["p95"], 2)},
           "overhead_pct": {"isolated_p50": pct(iso["p50"], bare["p50"]), "isolated_p95": pct(iso["p95"], bare["p95"]),
                            "equalized_p50": pct(eq["p50"], bare["p50"]), "equalized_p95": pct(eq["p95"], bare["p95"])},
           "note": "Equalizer cost is by design: every response waits for its time bucket. Size bucket_ms from the "
                   "model's measured p95 so answers rarely spill into a second bucket."}
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(res, indent=1))
    log(f"overhead: p50 bare {bare['p50']} ms → isolated {iso['p50']} ms ({res['overhead_pct']['isolated_p50']:+}%, "
        f"+{res['added_ms']['isolated_p50']} ms) → equalized {eq['p50']} ms")
    return res


if __name__ == "__main__":
    asyncio.run(run(out="docs/results/overhead.json"))
