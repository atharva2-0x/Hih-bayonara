"""HTTP surface of the observability zone (called only by the Arbiter)."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..common.telemetry import Hex64, TelemetryEvent, TrialId
from .service import ObservabilityService


class CanaryRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId
    owner: str = Field(pattern=r"^(red|blue)$")
    fingerprint: Hex64


class DrillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId
    owner: str = Field(pattern=r"^(red|blue)$")


def build_obs_app(svc: ObservabilityService) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND observability", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "zone": "observability"}

    @app.post("/v1/telemetry")
    async def telemetry(ev: TelemetryEvent):
        return await svc.ingest(ev)

    @app.post("/v1/canaries")
    async def register(req: CanaryRegistration):
        try:
            svc.register(req.trial_id, req.owner, req.fingerprint)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"registered": True}

    @app.post("/v1/drill/canary")
    async def drill(req: DrillRequest):
        return {"token": svc.create_drill_canary(req.trial_id, req.owner)}

    @app.get("/v1/snapshot")
    async def snapshot():
        return svc.snapshot()

    return app
