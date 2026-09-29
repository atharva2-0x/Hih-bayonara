"""Model clean-room services.

Two separate apps, served on two listeners with different mTLS trust:

* **data** (``/v1/generate``): callable only by the enclave. Session scope is
  always namespaced by trial, so a tenant cannot address another trial's cache.
* **admin** (reset, fingerprint, describe): callable only by the Arbiter.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from .backends import ModelBackend
from .purity import fingerprint

TrialId = Annotated[str, Field(pattern=r"^t-[0-9a-f]{12}$")]


class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId
    session: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:/-]{1,96}$")]
    prompt: str = Field(max_length=32_000)
    system: str | None = Field(default=None, max_length=8_000)
    max_tokens: int = Field(default=160, ge=1, le=2048)
    seed: int = 7


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId | None = None


class FingerprintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId
    phase: Literal["pre", "post", "replay"]


def build_model_data_app(backend: ModelBackend) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND model (data)", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "zone": "model"}

    @app.post("/v1/generate")
    async def generate(req: GenerateRequest):
        r = await backend.generate(scope=f"{req.trial_id}/{req.session}", prompt=req.prompt,
                                   system=req.system, max_tokens=req.max_tokens, seed=req.seed)
        return {"text": r.text, "prompt_tokens": r.prompt_tokens, "cached_tokens": r.cached_tokens,
                "completion_tokens": r.completion_tokens}

    return app


def build_model_admin_app(backend: ModelBackend) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND model (admin)", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "zone": "model-admin"}

    @app.get("/v1/admin/describe")
    async def describe():
        return backend.describe()

    @app.post("/v1/admin/reset")
    async def reset(req: ResetRequest):
        return {"flushed": await backend.reset(req.trial_id)}

    @app.post("/v1/admin/fingerprint")
    async def fp(req: FingerprintRequest):
        return await fingerprint(backend, f"purity/{req.trial_id}/{req.phase}")

    return app
