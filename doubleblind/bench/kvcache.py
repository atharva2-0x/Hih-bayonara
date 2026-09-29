"""KV-cache isolation check (LLM-native side channel).

Serving stacks reuse the KV cache for repeated prompt prefixes, so a request
whose prefix was recently processed returns measurably faster. If that cache
is shared across tenants or sessions, one session's timing reveals what
*another* session recently sent.

This benchmark measures the effect on the clean-room model in two modes:

* ``global``: one shared prefix cache (the unsafe default of many servers)
* ``session``: cache scoped per trial/session (DOUBLE-BLIND default)

For each mode it runs pairs of observer requests: one whose prefix another
session sent just before ("seen") and one with a fresh prefix ("unseen"). It
then reports how well a simple threshold separates them. With scoped caches
the two are indistinguishable (≈50%).
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from pathlib import Path

from ..zones.model.backends import StubBackend
from .stats import stump_cv_accuracy, summary, wilson_ci


def _prompt(rng: random.Random, n_words: int = 64) -> str:
    words = "system context field signal pattern value layer sample method balance summary factor".split()
    return " ".join(rng.choice(words) + str(rng.randrange(100)) for _ in range(n_words))


async def _mode(cache_scope: str, pairs: int, seed: int) -> dict:
    be = StubBackend(cache_scope=cache_scope)
    rng = random.Random(seed)
    seen, unseen = [], []
    for i in range(pairs):
        victim = _prompt(rng)
        await be.generate(scope=f"t/other-session-{i}", prompt=victim, system=None, max_tokens=4, seed=1)
        for target, bucket in ((victim, seen), (_prompt(rng), unseen)):
            t0 = time.perf_counter()
            await be.generate(scope=f"t/observer-{i}", prompt=target, system=None, max_tokens=4, seed=1)
            bucket.append((time.perf_counter() - t0) * 1000)
        await be.reset("t/observer")
    X = [[v] for v in seen + unseen]
    y = [1] * len(seen) + [0] * len(unseen)
    acc = stump_cv_accuracy(X, y)
    lo, hi = wilson_ci(acc, len(X))
    return {"seen_prefix_ms": summary(seen), "unseen_prefix_ms": summary(unseen),
            "observer_accuracy": round(acc, 3), "ci95": [lo, hi], "consistent_with_chance": lo <= 0.5 <= hi}


async def run(pairs: int = 100, out: str | Path | None = None, log=print) -> dict:
    log("kvcache: shared (global) cache …")
    glob = await _mode("global", pairs, 1)
    log("kvcache: per-session cache …")
    sess = await _mode("session", pairs, 1)
    res = {"benchmark": "KV-cache cross-session timing", "environment": "stub model with simulated prefix cache",
           "question": "can one session tell, from latency alone, whether another session just sent a prefix?",
           "chance": 0.5, "global_cache": glob, "session_cache": sess}
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(res, indent=1))
    log(f"kvcache: observer accuracy {glob['observer_accuracy']:.0%} (shared cache) → "
        f"{sess['observer_accuracy']:.0%} (per-session cache); chance 50%")
    return res


if __name__ == "__main__":
    asyncio.run(run(out="docs/results/kvcache.json"))
