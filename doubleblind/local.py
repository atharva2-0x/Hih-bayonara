"""Local simulation stack: every zone in one process, wired over in-process
ASGI transports, so the same HTTP code paths and schemas are exercised as in
the Docker deployment. Isolation between zones is **not** enforced here; the
breach drill reports that honestly (profile ``local-sim``)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from .authority.api import build_alert_app, build_blue_app, build_operator_app, build_red_app
from .authority.keybroker import KeyBroker
from .authority.ledger import Ledger
from .authority.policy import PolicyEngine
from .authority.service import Authority, AuthorityDeps
from .common.crypto import Signer
from .drill.drill import DrillProvider, LocalDrill
from .observability.app import build_obs_app
from .observability.service import ObservabilityService
from .zones.blue.workbench import BlueClient
from .zones.enclave.app import build_enclave_app
from .zones.model.app import build_model_admin_app, build_model_data_app
from .zones.model.backends import ModelBackend, StubBackend
from .zones.red.client import RedClient
from .zones.red.datasets import synthetic_suite
from .zones.red.vault import create_vault


def asgi_client(app, name: str, timeout: float = 120.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=f"http://{name}", timeout=timeout)


@dataclass
class LocalStack:
    workdir: Path
    authority: Authority
    obs_service: ObservabilityService
    backend: ModelBackend
    red_http: httpx.AsyncClient
    blue_http: httpx.AsyncClient
    operator_http: httpx.AsyncClient
    obs_http: httpx.AsyncClient
    red: RedClient
    blue: BlueClient
    apps: dict

    def new_red_vault(self, cases: list[dict], name: str = "vault.json") -> RedClient:
        path = self.workdir / "red" / name
        create_vault(path, cases)
        self.red = RedClient(self.red_http, self.workdir / "red" / "state", path)
        return self.red


def build_local_stack(workdir: str | Path, *, backend: ModelBackend | None = None, time_scale: float = 1.0,
                      drill: DrillProvider | None = None, cases: list[dict] | None = None,
                      metrics_dir: str | Path | None = None, demo=None) -> LocalStack:
    wd = Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    backend = backend or StubBackend(time_scale=time_scale)

    model_data = asgi_client(build_model_data_app(backend), "model")
    model_admin = asgi_client(build_model_admin_app(backend), "model-admin")
    enclave = asgi_client(build_enclave_app(model_data), "enclave")

    obs_svc = ObservabilityService()
    obs_http = asgi_client(build_obs_app(obs_svc), "obs")

    signer = Signer.load_or_create(wd / "authority" / "signing.pem")
    ledger = Ledger(wd / "authority" / "ledger.db", signer)
    authority = Authority(AuthorityDeps(
        ledger=ledger, policy=PolicyEngine.load(), keys=KeyBroker.from_dir(wd / "authority" / "keys"),
        enclave=enclave, model_admin=model_admin, obs=obs_http, drill=drill or LocalDrill(),
    ))
    alert_http = asgi_client(build_alert_app(authority), "arbiter-alerts")

    async def sink(alert):
        await alert_http.post("/v1/alerts", json=alert.model_dump())

    obs_svc.alert_sink = sink

    red_app, blue_app = build_red_app(authority), build_blue_app(authority)
    operator_app = build_operator_app(authority, obs=obs_http, demo=demo, metrics_dir=metrics_dir)
    red_http = asgi_client(red_app, "arbiter-red")
    blue_http = asgi_client(blue_app, "arbiter-blue")
    operator_http = asgi_client(operator_app, "arbiter-operator")

    vault = wd / "red" / "vault.json"
    create_vault(vault, cases if cases is not None else synthetic_suite())
    return LocalStack(
        workdir=wd, authority=authority, obs_service=obs_svc, backend=backend,
        red_http=red_http, blue_http=blue_http, operator_http=operator_http, obs_http=obs_http,
        red=RedClient(red_http, wd / "red" / "state", vault),
        blue=BlueClient(blue_http, wd / "blue" / "state"),
        apps={"red": red_app, "blue": blue_app, "operator": operator_app},
    )
