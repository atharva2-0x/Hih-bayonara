"""Model Purity Fingerprint.

A fixed set of benign "golden probes" is run at temperature 0 with a fixed
seed, each in a fresh session, before the trial (F_pre) and after it
(F_post). The fingerprint hashes the model digest together with every probe
output. If anything in the trial changed the model's behaviour (leftover
cache, contaminated state, swapped weights), F_post != F_pre and the trial is
INVALIDATED.
"""

from __future__ import annotations

from ...common.crypto import sha256_hex, tagged_hash
from .backends import ModelBackend

GOLDEN_PROBES = [
    "What is the boiling point of water at sea level in degrees Celsius?",
    "List the three primary colours of light.",
    "Translate 'good morning' into French.",
    "What is twelve multiplied by twelve?",
    "Name the largest planet in the solar system.",
    "Summarise in one sentence: plants turn sunlight into chemical energy.",
]
PURITY_SEED = 1337


async def fingerprint(backend: ModelBackend, scope_prefix: str) -> dict:
    outputs = []
    for i, probe in enumerate(GOLDEN_PROBES):
        r = await backend.generate(scope=f"{scope_prefix}/probe-{i}", prompt=probe, system=None,
                                   max_tokens=64, seed=PURITY_SEED)
        outputs.append(sha256_hex(r.text.encode("utf-8")))
    await backend.reset(scope_prefix)
    return {
        "fingerprint": tagged_hash("doubleblind/purity/v1", backend.digest, *outputs),
        "model_digest": backend.digest,
        "probes": len(GOLDEN_PROBES),
    }
