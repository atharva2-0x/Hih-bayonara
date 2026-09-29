"""Zone service processes for the Docker deployment.

Each container runs exactly one of these. Everything is configured through
environment variables (see docker-compose.yml). Every listener binds to one
specific IP on one specific network and pins the CA of the zone allowed to
call it.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from pathlib import Path

import httpx
import uvicorn

from ..authority.api import build_alert_app, build_blue_app, build_operator_app, build_red_app
from ..authority.keybroker import KeyBroker
from ..authority.ledger import Ledger
from ..authority.policy import PolicyEngine
from ..authority.service import Authority, AuthorityDeps
from ..common.crypto import Signer
from ..common.tls import mtls_client, server_ssl
from ..drill.drill import FileDrill
from ..observability.app import build_obs_app
from ..observability.service import ObservabilityService
from ..zones.enclave.app import build_enclave_app
from ..zones.model.app import build_model_admin_app, build_model_data_app
from ..zones.model.backends import LlamaCppBackend, StubBackend


def env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        raise SystemExit(f"missing required environment variable {name}")
    return v


def _bind(name: str, default: str) -> tuple[str, int]:
    host, port = env(name, default).rsplit(":", 1)
    return host, int(port)


def _tls() -> bool:
    return env("DB_TLS", "1") == "1"


def _certs() -> Path:
    return Path(env("DB_CERTS", "/certs"))


def _client(url_var: str, default_url: str, server_ca: str) -> httpx.AsyncClient:
    url = env(url_var, default_url)
    if not _tls():
        return httpx.AsyncClient(base_url=url.replace("https://", "http://"), timeout=120)
    c = _certs()
    return mtls_client(url, c / "client.crt", c / "client.key", c / server_ca)


def _server(app, bind_var: str, default: str, client_ca: str | None, *, cert: str = "server") -> uvicorn.Server:
    host, port = _bind(bind_var, default)
    kw = {}
    if _tls() and client_ca:
        c = _certs()
        kw = server_ssl(c / f"{cert}.crt", c / f"{cert}.key", c / client_ca)
    cfg = uvicorn.Config(app, host=host, port=port, log_level=env("DB_LOG_LEVEL", "warning"),
                         access_log=False, proxy_headers=False, server_header=False, **kw)
    return _QuietServer(cfg)


class _QuietServer(uvicorn.Server):
    """Signals are handled once for all listeners in the process (see serve_all)."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def serve_all(servers: list[uvicorn.Server]) -> None:
    loop = asyncio.get_running_loop()

    def stop() -> None:
        for s in servers:
            s.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    for s in servers:
        cfg = s.config
        print(f"listening on {cfg.host}:{cfg.port} ({'mTLS' if cfg.ssl_certfile else 'plain HTTP'})", flush=True)
    await asyncio.gather(*(s.serve() for s in servers))


# --------------------------------------------------------------------- zones


def run_arbiter() -> None:
    state = Path(env("DB_STATE", "/var/lib/doubleblind"))
    enclave = _client("DB_ENCLAVE_URL", "https://10.77.3.20:8300", "ca-enclave.crt")
    model_admin = _client("DB_MODEL_ADMIN_URL", "https://10.77.4.20:8211", "ca-model.crt")
    obs = _client("DB_OBS_URL", "https://10.77.5.20:8500", "ca-obs.crt")
    authority = Authority(AuthorityDeps(
        ledger=Ledger(state / "ledger.db", Signer.load_or_create(state / "signing.pem")),
        policy=PolicyEngine.load(), keys=KeyBroker.from_dir(state / "keys"),
        enclave=enclave, model_admin=model_admin, obs=obs,
        drill=FileDrill(env("DB_DRILL_DIR", "/drill-out")),
    ))
    print(f"ledger public key {authority.d.ledger.signer.public_key_hex}", flush=True)
    servers = [
        _server(build_red_app(authority), "DB_RED_BIND", "10.77.1.10:8443", "ca-red.crt"),
        _server(build_blue_app(authority), "DB_BLUE_BIND", "10.77.2.10:8443", "ca-blue.crt"),
        _server(build_alert_app(authority), "DB_ALERTS_BIND", "10.77.5.10:8444", "ca-obs.crt"),
        # Operator listener: plain HTTP on the UI network, published on the host's loopback only.
        _server(build_operator_app(authority, obs=obs, metrics_dir=env("DB_METRICS_DIR", "/metrics")),
                "DB_OPERATOR_BIND", "10.77.9.10:8100", None),
    ]
    asyncio.run(serve_all(servers))


def run_enclave() -> None:
    model = _client("DB_MODEL_URL", "https://10.77.4.20:8210", "ca-model.crt")
    asyncio.run(serve_all([_server(build_enclave_app(model), "DB_BIND", "10.77.3.20:8300", "ca-authority.crt")]))


def _backend():
    kind = env("DB_MODEL_BACKEND", "stub")
    if kind == "stub":
        return StubBackend(cache_scope=env("DB_CACHE_SCOPE", "session"))
    if kind == "llamacpp":
        return LlamaCppBackend(env("DB_LLAMA_URL", "http://llama:8080"),
                               model_path=os.environ.get("DB_MODEL_PATH") or None,
                               pinned_sha256=os.environ.get("DB_MODEL_SHA256") or None)
    raise SystemExit(f"unknown DB_MODEL_BACKEND {kind}")


def run_model() -> None:
    be = _backend()
    print(f"model backend {be.describe()}", flush=True)
    asyncio.run(serve_all([
        _server(build_model_data_app(be), "DB_DATA_BIND", "10.77.4.20:8210", "ca-enclave.crt"),
        _server(build_model_admin_app(be), "DB_ADMIN_BIND", "10.77.4.20:8211", "ca-authority.crt"),
    ]))


def run_obs() -> None:
    arbiter = _client("DB_ARBITER_ALERTS_URL", "https://10.77.5.10:8444", "ca-authority.crt")
    svc = ObservabilityService()

    async def sink(alert) -> None:
        try:
            await arbiter.post("/v1/alerts", json=alert.model_dump())
        except httpx.HTTPError as exc:
            print(f"alert delivery failed: {type(exc).__name__}", flush=True)

    svc.alert_sink = sink
    asyncio.run(serve_all([_server(build_obs_app(svc), "DB_BIND", "10.77.5.20:8500", "ca-authority.crt")]))


SERVICES = {"arbiter": run_arbiter, "enclave": run_enclave, "model": run_model, "obs": run_obs}
