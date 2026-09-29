"""Equalizer: closes the timing and size side channels between blue and red.

Without it, red can tell *which layer* refused a request:

* a request blocked by blue's input guard returns almost instantly, with
  blue's own short block message;
* a model refusal takes prefill + a few decode steps and has a different length;
* an answer takes longer again.

That is exactly the "blue defensive logic must not be inferable" failure in
the brief. The Equalizer makes every response red sees:

1. **canonical**: any refusal, from any layer, is the same byte string;
2. **size-bucketed**: padded to the next size bucket;
3. **time-bucketed**: released at the next multiple of ``bucket_ms`` after
   the request arrived.

``bench/leakage`` measures how well it works: an attacker classifier on
(latency, size) goes from far above chance to about chance.
"""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import asdict, dataclass, field

from ..common.crypto import canonical_json

CANONICAL_REFUSAL = "This request was not answered."


@dataclass
class EqualizerConfig:
    enabled: bool = True
    bucket_ms: int = 250
    size_buckets: list[int] = field(default_factory=lambda: [512, 1024, 2048, 4096, 8192])
    canonical_refusal: str = CANONICAL_REFUSAL

    @classmethod
    def from_dict(cls, d: dict | None) -> "EqualizerConfig":
        d = dict(d or {})
        cfg = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        if cfg.bucket_ms < 1 or not cfg.size_buckets or sorted(cfg.size_buckets) != cfg.size_buckets:
            raise ValueError("invalid equalizer config")
        return cfg

    def to_dict(self) -> dict:
        return asdict(self)


class Equalizer:
    def __init__(self, cfg: EqualizerConfig):
        self.cfg = cfg

    def _target_size(self, size: int) -> int:
        for b in self.cfg.size_buckets:
            if b >= size:
                return b
        top = self.cfg.size_buckets[-1]
        return top * math.ceil(size / top)

    def shape(self, answered: bool, text: str | None, extra: dict | None = None) -> dict:
        """Build the complete red-visible response body. ``text`` is the answer
        if answered, or the raw refusal/block message otherwise (only shown
        when disabled). ``extra`` fields are included *before* padding: every
        byte red receives must count toward the bucket, or a field of variable
        width becomes a side channel."""
        if not self.cfg.enabled:
            return {**(extra or {}), "status": "ANSWERED" if answered else "REFUSED", "text": text or ""}
        view = {"status": "ANSWERED", "text": text or ""} if answered else {
            "status": "REFUSED", "text": self.cfg.canonical_refusal}
        view = {**(extra or {}), **view}
        base = len(canonical_json({**view, "pad": ""}))
        view["pad"] = " " * (self._target_size(base) - base)
        return view

    async def release(self, t0: float) -> dict:
        """Sleep until the next time bucket boundary after ``t0`` (monotonic)."""
        elapsed_ms = (time.monotonic() - t0) * 1000
        if not self.cfg.enabled:
            return {"release_ms": elapsed_ms, "buckets": 0, "spilled": False}
        k = max(1, math.ceil(elapsed_ms / self.cfg.bucket_ms))
        target = t0 + k * self.cfg.bucket_ms / 1000
        delay = target - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        return {"release_ms": (time.monotonic() - t0) * 1000, "buckets": k, "spilled": k > 1}
