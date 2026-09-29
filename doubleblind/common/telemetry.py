"""Metadata-only telemetry schema.

The observability plane must detect cross-boundary problems *without becoming
a leakage channel itself*. This schema is its hard contract: every field is a
closed enum, a bounded number or a hex digest. There is no free-text field,
and unknown fields are rejected (``extra="forbid"``), so plaintext payloads,
verdicts or defense logic cannot be smuggled into the monitoring stream.
"""

from __future__ import annotations

import time
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Zone = Literal["red", "blue", "authority", "enclave", "model", "observability"]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
TrialId = Annotated[str, Field(pattern=r"^t-[0-9a-f]{12}$")]
Code = Annotated[str, Field(pattern=r"^[A-Za-z0-9_:.-]{1,48}$")]


class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["boundary", "case_timing", "policy_denial", "token_denial", "state"]
    trial_id: TrialId
    ts: float = Field(default_factory=time.time)
    zone_from: Zone | None = None
    zone_to: Zone | None = None
    size_bytes: Annotated[int, Field(ge=0, le=10_000_000)] | None = None
    duration_ms: Annotated[float, Field(ge=0, le=3_600_000)] | None = None
    canary_fps: Annotated[list[Hex64], Field(max_length=16)] = Field(default_factory=list)
    code: Code | None = None


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    ts: float
    severity: Literal["info", "warn", "critical"]
    trial_id: TrialId
    kind: Literal["canary_breach", "canary_contained", "policy_probing", "token_abuse", "rate_spike",
                  "latency_drift", "drill"]
    zone: Zone | None = None
    message: str
