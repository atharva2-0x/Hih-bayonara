"""Sealed Defense Enclave service.

Runs blue's bundle around the model: input guard -> model -> output guard.
Only the Arbiter can call it (network + pinned mTLS). It returns a
fixed-schema result to the Arbiter and **nothing to blue**. It never logs
request content.
"""

from __future__ import annotations

import base64
from typing import Annotated, Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .bundle import Bundle, BundleError

TrialId = Annotated[str, Field(pattern=r"^t-[0-9a-f]{12}$")]


class LoadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId
    bundle_b64: str = Field(max_length=100_000)


class UnloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId


class ProcessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: TrialId
    session: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:/-]{1,96}$")]
    text: str = Field(max_length=32_000)
    max_tokens: int = Field(default=160, ge=1, le=2048)
    seed: int = 7


class ProcessResult(BaseModel):
    """The enclave's entire output vocabulary."""
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["PASS", "BLOCKED_INPUT", "BLOCKED_OUTPUT"]
    reason_code: Annotated[str, Field(pattern=r"^R_[A-Z0-9_]{1,24}$")] | None = None
    output: str | None = Field(default=None, max_length=64_000)


def build_enclave_app(model_client: httpx.AsyncClient) -> FastAPI:
    app = FastAPI(title="DOUBLE-BLIND sealed enclave", docs_url=None, redoc_url=None)
    bundles: dict[str, Bundle] = {}

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "zone": "enclave", "loaded": len(bundles)}

    @app.post("/v1/load")
    async def load(req: LoadRequest):
        try:
            b = Bundle.parse(base64.b64decode(req.bundle_b64))
        except (BundleError, ValueError) as exc:
            raise HTTPException(422, f"bundle rejected: {exc}") from exc
        bundles[req.trial_id] = b
        return {"loaded": True, "bundle_sha256": b.sha256, "rules": len(b.input_rules) + len(b.output_rules)}

    @app.post("/v1/unload")
    async def unload(req: UnloadRequest):
        return {"unloaded": bundles.pop(req.trial_id, None) is not None}

    @app.post("/v1/process", response_model=ProcessResult)
    async def process(req: ProcessRequest):
        b = bundles.get(req.trial_id)
        if b is None:
            raise HTTPException(409, "no bundle loaded for this trial")
        ok, reason = b.input_guard(req.text)
        if not ok:
            return ProcessResult(verdict="BLOCKED_INPUT", reason_code=reason, output=b.block_message)
        r = await model_client.post("/v1/generate", json={
            "trial_id": req.trial_id, "session": req.session, "prompt": req.text,
            "system": b.system_prompt or None, "max_tokens": req.max_tokens, "seed": req.seed,
        })
        if r.status_code != 200:
            raise HTTPException(502, "model zone error")
        out = r.json()["text"]
        ok, reason = b.output_guard(out)
        if not ok:
            return ProcessResult(verdict="BLOCKED_OUTPUT", reason_code=reason, output=b.block_message)
        return ProcessResult(verdict="PASS", output=out)

    return app
