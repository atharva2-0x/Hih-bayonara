"""Observability zone: Canary Watcher + Anomaly Detector.

Receives only ``TelemetryEvent`` metadata. It can *invalidate* a trial (by
raising a critical alert to the Arbiter) but it can never *read* plaintext.
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from typing import Awaitable, Callable

from ..common.crypto import random_hex
from ..common.telemetry import Alert, TelemetryEvent
from .canary import fingerprint, new_canary

TENANTS = ("red", "blue")
AlertSink = Callable[[Alert], Awaitable[None]]


class AnomalyDetector:
    def __init__(self, max_rps: float = 60.0, denial_threshold: int = 5, drift_z: float = 4.0):
        self.max_rps = max_rps
        self.denial_threshold = denial_threshold
        self.drift_z = drift_z
        self._arrivals: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=512))
        self._denials: dict[tuple[str, str, str], deque] = defaultdict(lambda: deque(maxlen=64))
        self._durations: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._flagged: set[tuple] = set()

    def observe(self, ev: TelemetryEvent) -> list[tuple[str, str, str | None, str]]:
        """Returns [(severity, kind, zone, message)]."""
        out: list[tuple[str, str, str | None, str]] = []
        now = ev.ts
        if ev.kind in ("policy_denial", "token_denial") and ev.zone_from:
            key = (ev.trial_id, ev.zone_from, ev.kind)
            dq = self._denials[key]
            dq.append(now)
            recent = [t for t in dq if now - t <= 60]
            if len(recent) >= self.denial_threshold and key not in self._flagged:
                self._flagged.add(key)
                kind = "policy_probing" if ev.kind == "policy_denial" else "token_abuse"
                out.append(("warn", kind, ev.zone_from,
                            f"{len(recent)} {ev.kind.replace('_', ' ')}s from {ev.zone_from} within 60s"))
        if ev.kind == "boundary" and ev.zone_from in TENANTS:
            key2 = (ev.trial_id, ev.zone_from)
            dq = self._arrivals[key2]
            dq.append(now)
            window = [t for t in dq if now - t <= 1.0]
            if len(window) > self.max_rps and (key2, "rate") not in self._flagged:
                self._flagged.add((key2, "rate"))
                out.append(("warn", "rate_spike", ev.zone_from, f"{len(window)} requests/s from {ev.zone_from}"))
        if ev.kind == "case_timing" and ev.duration_ms is not None:
            dq = self._durations[ev.trial_id]
            if len(dq) >= 30:
                mu = statistics.fmean(dq)
                sd = statistics.pstdev(dq) or 1e-9
                z = (ev.duration_ms - mu) / sd
                key3 = (ev.trial_id, "drift")
                if z > self.drift_z and key3 not in self._flagged:
                    self._flagged.add(key3)
                    out.append(("info", "latency_drift", "model",
                                f"case latency z-score {z:.1f}: possible resource interference"))
            dq.append(ev.duration_ms)
        return out


class ObservabilityService:
    def __init__(self, alert_sink: AlertSink | None = None, detector: AnomalyDetector | None = None):
        self.alert_sink = alert_sink
        self.detector = detector or AnomalyDetector()
        self.registry: dict[str, dict] = {}  # fingerprint -> {trial_id, owner, drill}
        self.alerts: deque[Alert] = deque(maxlen=500)
        self.counters: dict[str, int] = defaultdict(int)

    # -- canary registry ------------------------------------------------------

    def register(self, trial_id: str, owner: str, fp: str, drill: bool = False) -> None:
        if owner not in TENANTS:
            raise ValueError("canary owner must be a tenant")
        self.registry[fp] = {"trial_id": trial_id, "owner": owner, "drill": drill}

    def create_drill_canary(self, trial_id: str, owner: str) -> str:
        """Synthetic canary for the canary drill. Registered like a real one, so
        the drill exercises the complete detection path."""
        token = new_canary()
        self.register(trial_id, owner, fingerprint(token), drill=True)
        return token

    # -- ingestion ------------------------------------------------------------

    async def _raise(self, severity: str, kind: str, trial_id: str, zone: str | None, message: str) -> Alert:
        alert = Alert(id="al-" + random_hex(6), ts=time.time(), severity=severity, trial_id=trial_id,
                      kind=kind, zone=zone, message=message)
        self.alerts.append(alert)
        self.counters[f"alerts_{severity}"] += 1
        if self.alert_sink:
            await self.alert_sink(alert)
        return alert

    async def ingest(self, ev: TelemetryEvent) -> dict:
        self.counters[f"events_{ev.kind}"] += 1
        result = {"verdict": "clean", "owners": []}
        if ev.kind == "boundary" and ev.canary_fps:
            result = await self._check_canaries(ev)
        for severity, kind, zone, msg in self.detector.observe(ev):
            await self._raise(severity, kind, ev.trial_id, zone, msg)
        return result

    async def _check_canaries(self, ev: TelemetryEvent) -> dict:
        breach, contained, owners = False, False, []
        for fp in ev.canary_fps:
            entry = self.registry.get(fp)
            if not entry:
                continue
            owner = entry["owner"]
            owners.append(owner)
            if ev.zone_from in TENANTS and owner != ev.zone_from:
                # A tenant *sent* another tenant's secret: it must already have seen it.
                breach = True
            elif ev.zone_to in TENANTS and owner != ev.zone_to:
                # About to *deliver* another tenant's secret: stop it at the boundary.
                contained = True
        if breach:
            self.counters["canary_breach"] += 1
            await self._raise("critical", "canary_breach", ev.trial_id, ev.zone_from,
                              f"foreign canary received from {ev.zone_from}: isolation breached")
            return {"verdict": "breach", "owners": owners}
        if contained:
            self.counters["canary_contained"] += 1
            await self._raise("warn", "canary_contained", ev.trial_id, ev.zone_to,
                              f"foreign canary in a message bound for {ev.zone_to}: withheld at the boundary")
            return {"verdict": "contained", "owners": owners}
        return {"verdict": "clean", "owners": owners}

    def snapshot(self) -> dict:
        return {
            "registered_canaries": {
                t: sum(1 for e in self.registry.values() if e["owner"] == t and not e["drill"]) for t in TENANTS
            },
            "counters": dict(self.counters),
            "alerts": [a.model_dump() for a in list(self.alerts)[-50:]],
        }
