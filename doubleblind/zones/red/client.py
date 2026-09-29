"""Red team client: commit -> run -> reveal against the Arbiter's red listener."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path

import httpx

from ...common.crypto import commitment, random_hex
from ...observability.canary import fingerprint
from .vault import open_vault, payload_set_bytes


class TenantError(RuntimeError):
    pass


def _check(r: httpx.Response) -> dict:
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = r.text
        raise TenantError(f"{r.request.method} {r.request.url.path} -> {r.status_code}: {detail}")
    return r.json()


class RedClient:
    def __init__(self, http: httpx.AsyncClient, state_dir: str | Path, vault_path: str | Path):
        self.http = http
        self.state = Path(state_dir)
        self.state.mkdir(parents=True, exist_ok=True)
        self.vault_path = Path(vault_path)

    def _state_file(self, trial_id: str) -> Path:
        return self.state / f"{trial_id}.json"

    def _load(self, trial_id: str) -> dict:
        return json.loads(self._state_file(trial_id).read_text())

    def _save(self, trial_id: str, d: dict) -> None:
        self._state_file(trial_id).write_text(json.dumps(d))

    async def commit(self, trial_id: str, mode: str = "static") -> dict:
        cases, canary = open_vault(self.vault_path)
        nonce = random_hex(32)
        artifact = payload_set_bytes(cases)
        self._save(trial_id, {"nonce": nonce})
        return _check(await self.http.post(f"/v1/trials/{trial_id}/commitment", json={
            "commitment": commitment(artifact, nonce), "canary_fp": fingerprint(canary),
            "mode": mode, "declared_cases": len(cases),
        }))

    async def run(self, trial_id: str, *, limit: int | None = None, concurrency: int = 4,
                  on_result=None, pace_s: float = 0.0) -> list[dict]:
        cases, _ = open_vault(self.vault_path)
        token = _check(await self.http.post(f"/v1/trials/{trial_id}/session"))["token"]
        sem = asyncio.Semaphore(concurrency)
        observations: list[dict] = []

        async def one(c: dict) -> None:
            async with sem:
                t0 = time.perf_counter()
                r = await self.http.post(f"/v1/trials/{trial_id}/cases", headers={"Authorization": f"Bearer {token}"},
                                         json={"case_id": c["id"], "text": c["text"], "expect": c["expect"]})
                latency = (time.perf_counter() - t0) * 1000
                body = _check(r)
                obs = {"case_id": c["id"], "case_no": body["case_no"], "status": body["status"],
                       "latency_ms": round(latency, 2), "size": len(r.content)}
                observations.append(obs)
                if on_result:
                    on_result(obs)
                if pace_s:
                    await asyncio.sleep(pace_s)

        await asyncio.gather(*(one(c) for c in (cases[:limit] if limit else cases)))
        st = self._load(trial_id)
        st["observations"] = observations
        self._save(trial_id, st)
        return observations

    async def reveal(self, trial_id: str, *, tamper: bool = False) -> dict:
        cases, _ = open_vault(self.vault_path)
        artifact = payload_set_bytes(cases)
        if tamper:  # used by tests: reveal something other than what was committed
            artifact = artifact.replace(b"synthetic", b"SYNTHETIC", 1)
        return _check(await self.http.post(f"/v1/trials/{trial_id}/reveal", json={
            "artifact_b64": base64.b64encode(artifact).decode(), "nonce": self._load(trial_id)["nonce"]}))

    async def report(self, trial_id: str) -> dict:
        return _check(await self.http.get(f"/v1/trials/{trial_id}/report"))
