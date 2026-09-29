"""HTTP surface of the Trial Authority.

One FastAPI app **per caller role**, each served on its own listener:

    red listener       (net-red,  pinned red mTLS)      -> build_red_app
    blue listener      (net-blue, pinned blue mTLS)     -> build_blue_app
    alerts listener    (net-obs,  pinned obs mTLS)      -> build_alert_app
    operator listener  (net-ui, published on localhost) -> build_operator_app (+ War Room)

A caller's role is therefore fixed by *which door it came in through*. It is
never a claim in the request. Red's app does not even have a route for
uploading bundles, and blue's app has no route for submitting cases.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Literal

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from ..common.crypto import TokenError
from ..common.telemetry import Alert
from .policy import PolicyDenied
from .service import Authority, AuthorityError
from .trial import IllegalTransition

Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
WARROOM_DIR = Path(__file__).resolve().parents[1] / "warroom"


class CommitmentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    commitment: Hex64
    canary_fp: Hex64
    mode: Literal["static", "adaptive"] = "static"
    declared_cases: int | None = Field(default=None, ge=0, le=100_000)


class BundleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundle_b64: str = Field(max_length=100_000)


class CaseBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]
    text: str = Field(min_length=1, max_length=16_000)
    expect: Literal["refuse", "comply"]
    session: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,32}$")] = "default"


class RevealBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artifact_b64: str = Field(max_length=8_000_000)
    nonce: Hex64


class TrialCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(default="trial", max_length=80)
    config: dict = Field(default_factory=dict)


class InvalidateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="operator invalidated", max_length=200)


def _install_errors(app: FastAPI) -> None:
    @app.exception_handler(PolicyDenied)
    async def _denied(_: Request, exc: PolicyDenied):
        return JSONResponse({"detail": str(exc), "rule": exc.rule}, status_code=403)

    @app.exception_handler(AuthorityError)
    async def _auth(_: Request, exc: AuthorityError):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.exception_handler(IllegalTransition)
    async def _illegal(_: Request, exc: IllegalTransition):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(TokenError)
    async def _tok(_: Request, exc: TokenError):
        return JSONResponse({"detail": str(exc)}, status_code=401)

    @app.exception_handler(httpx.HTTPError)
    async def _zone(_: Request, exc: httpx.HTTPError):
        return JSONResponse({"detail": f"zone unavailable: {type(exc).__name__}"}, status_code=503)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise TokenError("missing bearer token")
    return authorization[7:]


def _tenant_common(app: FastAPI, auth: Authority, role: str) -> None:
    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "listener": role}

    @app.get("/v1/trials/{trial_id}")
    async def status(trial_id: str):
        return await auth.status(role, trial_id)

    @app.post("/v1/trials/{trial_id}/commitment")
    async def commit(trial_id: str, body: CommitmentBody):
        return await auth.submit_commitment(role, trial_id, body.model_dump())

    @app.post("/v1/trials/{trial_id}/reveal")
    async def reveal(trial_id: str, body: RevealBody):
        return await auth.reveal(role, trial_id, body.artifact_b64, body.nonce)

    @app.get("/v1/trials/{trial_id}/report")
    async def report(trial_id: str):
        return await auth.report(role, trial_id)


def build_red_app(auth: Authority) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND Arbiter: red listener", docs_url=None, redoc_url=None)
    _install_errors(app)
    _tenant_common(app, auth, "red")

    @app.post("/v1/trials/{trial_id}/session")
    async def session(trial_id: str):
        return await auth.obtain_session("red", trial_id)

    @app.post("/v1/trials/{trial_id}/cases")
    async def case(trial_id: str, body: CaseBody, authorization: str | None = Header(default=None)):
        return await auth.submit_case("red", trial_id, _bearer(authorization), body.model_dump())

    return app


def build_blue_app(auth: Authority) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND Arbiter: blue listener", docs_url=None, redoc_url=None)
    _install_errors(app)
    _tenant_common(app, auth, "blue")

    @app.post("/v1/trials/{trial_id}/bundle")
    async def bundle(trial_id: str, body: BundleBody):
        return await auth.upload_bundle("blue", trial_id, body.bundle_b64)

    return app


def build_alert_app(auth: Authority) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND Arbiter: alerts listener", docs_url=None, redoc_url=None)
    _install_errors(app)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "listener": "alerts"}

    @app.post("/v1/alerts")
    async def alert(a: Alert):
        return await auth.handle_alert(a)

    return app


def build_operator_app(auth: Authority, *, obs: httpx.AsyncClient | None = None, demo=None,
                       metrics_dir: str | Path | None = None) -> FastAPI:
    """Operator/auditor listener: trial lifecycle, ledger, events, War Room.
    ``demo`` is an optional object with async ``run(opts)`` and ``tamper()``."""
    app = FastAPI(title="DOUBLE-BLIND Arbiter: operator listener", docs_url=None, redoc_url=None)
    _install_errors(app)
    role = "operator"

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "listener": "operator"}

    @app.post("/v1/trials")
    async def create(body: TrialCreateBody):
        return await auth.create_trial(role, body.name, body.config)

    @app.get("/v1/trials")
    async def list_trials():
        return auth.overview()

    @app.get("/v1/trials/{trial_id}")
    async def status(trial_id: str):
        return await auth.status(role, trial_id)

    @app.post("/v1/trials/{trial_id}/arm")
    async def arm(trial_id: str):
        return await auth.arm(role, trial_id)

    @app.post("/v1/trials/{trial_id}/start")
    async def start(trial_id: str):
        return await auth.start(role, trial_id)

    @app.post("/v1/trials/{trial_id}/conclude")
    async def conclude(trial_id: str):
        return await auth.conclude(role, trial_id)

    @app.post("/v1/trials/{trial_id}/invalidate")
    async def invalidate(trial_id: str, body: InvalidateBody):
        return await auth.invalidate(role, trial_id, body.reason, source="operator")

    @app.post("/v1/trials/{trial_id}/drill/canary")
    async def canary(trial_id: str):
        return await auth.canary_drill(role, trial_id)

    @app.get("/v1/trials/{trial_id}/report")
    async def report(trial_id: str):
        return await auth.report(role, trial_id)

    @app.get("/v1/trials/{trial_id}/export")
    async def export(trial_id: str):
        return await auth.export(role, trial_id)

    @app.get("/v1/ledger")
    async def ledger(since: int = 0, limit: int = 200):
        evs = auth.d.ledger.events(since_seq=since, limit=min(limit, 1000))
        return {"events": [{k: v for k, v in e.items()} for e in evs],
                "checkpoints": auth.d.ledger.checkpoints()[-20:]}

    @app.get("/v1/ledger/verify")
    async def verify():
        from .ledger import verify_ledger_export
        rep = verify_ledger_export(auth.d.ledger.export(), pinned_public_key=auth.d.ledger.signer.public_key_hex)
        return rep.__dict__

    @app.get("/v1/policy")
    async def policy():
        return {"hash": auth.d.policy.hash, "invariants": auth.d.policy.check_invariants()}

    @app.get("/v1/observability")
    async def observability():
        if obs is None:
            return {}
        r = await obs.get("/v1/snapshot")
        return r.json()

    @app.get("/v1/metrics")
    async def metrics():
        out = {}
        if metrics_dir and Path(metrics_dir).is_dir():
            for p in sorted(Path(metrics_dir).glob("*.json")):
                try:
                    out[p.stem] = json.loads(p.read_text())
                except ValueError:
                    pass
        return out

    @app.get("/v1/events")
    async def events(request: Request):
        q = auth.bus.subscribe()
        history = list(auth.bus.history)[-200:]

        async def stream():
            try:
                for ev in history:
                    yield f"data: {json.dumps(ev)}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"data: {json.dumps(ev)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                auth.bus.unsubscribe(q)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    if demo is not None:
        @app.post("/v1/demo/run")
        async def demo_run(opts: dict | None = None):
            task = asyncio.create_task(demo.run(opts or {}))
            demo.tasks.add(task)
            task.add_done_callback(demo.tasks.discard)
            return {"started": True}

        @app.post("/v1/demo/tamper")
        async def demo_tamper():
            return await demo.tamper()

    if WARROOM_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=WARROOM_DIR), name="static")

        @app.get("/")
        async def site():
            return FileResponse(WARROOM_DIR / "site.html")

        @app.get("/warroom")
        async def warroom():
            return FileResponse(WARROOM_DIR / "index.html")

    return app
