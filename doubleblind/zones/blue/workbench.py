"""Blue team workbench: package a defense bundle (planting blue's canary),
commit to it, upload it sealed, and reveal it after the trial."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx

from ...common.crypto import canonical_json, commitment, random_hex
from ...observability.canary import fingerprint, new_canary
from ..red.client import _check

SAMPLE_BUNDLE = Path(__file__).with_name("sample_bundle.json")


def package_bundle(template: str | Path = SAMPLE_BUNDLE) -> tuple[bytes, str]:
    """Returns (bundle_bytes, canary). The canary goes into the system prompt:
    if the model is ever coaxed into echoing its instructions to red, the
    Arbiter's boundary scan catches the canary and withholds the response."""
    d = json.loads(Path(template).read_text())
    canary = new_canary()
    d["system_prompt"] = f"[ref:{canary}] {d.get('system_prompt', '')}".strip()
    return canonical_json(d), canary


class BlueClient:
    def __init__(self, http: httpx.AsyncClient, state_dir: str | Path, template: str | Path = SAMPLE_BUNDLE,
                 fixed_bundle: tuple[bytes, str] | None = None):
        self.http = http
        self.state = Path(state_dir)
        self.state.mkdir(parents=True, exist_ok=True)
        self.template = Path(template)
        self.fixed_bundle = fixed_bundle  # (bundle_bytes, canary): reuse one package across trials (benchmarks)

    def _f(self, trial_id: str) -> Path:
        return self.state / f"{trial_id}.json"

    async def commit(self, trial_id: str) -> dict:
        bundle, canary = self.fixed_bundle or package_bundle(self.template)
        nonce = random_hex(32)
        self._f(trial_id).write_text(json.dumps({"nonce": nonce, "bundle_b64": base64.b64encode(bundle).decode()}))
        return _check(await self.http.post(f"/v1/trials/{trial_id}/commitment", json={
            "commitment": commitment(bundle, nonce), "canary_fp": fingerprint(canary)}))

    async def upload(self, trial_id: str) -> dict:
        st = json.loads(self._f(trial_id).read_text())
        return _check(await self.http.post(f"/v1/trials/{trial_id}/bundle", json={"bundle_b64": st["bundle_b64"]}))

    async def reveal(self, trial_id: str) -> dict:
        st = json.loads(self._f(trial_id).read_text())
        return _check(await self.http.post(f"/v1/trials/{trial_id}/reveal", json={
            "artifact_b64": st["bundle_b64"], "nonce": st["nonce"]}))

    async def report(self, trial_id: str) -> dict:
        return _check(await self.http.get(f"/v1/trials/{trial_id}/report"))
