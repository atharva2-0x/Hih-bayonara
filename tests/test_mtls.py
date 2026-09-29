"""Pinned per-zone mTLS, exercised over real TLS sockets on loopback."""

import asyncio
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

from doubleblind.common.tls import client_context, server_ssl
from doubleblind.deploy.certs import generate
from doubleblind.drill.drill import _tls_accepts


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return generate(tmp_path_factory.mktemp("pki"), extra_ips=["127.0.0.1"])


@pytest.fixture(scope="module")
def red_listener(pki):
    """A listener that, like the Arbiter's red door, trusts only the red CA."""
    app = FastAPI()

    @app.get("/healthz")
    async def h():
        return {"ok": True}

    port = _free_port()
    a = pki / "authority"
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error",
                         **server_ssl(a / "server.crt", a / "server.key", a / "ca-red.crt"))
    server = uvicorn.Server(cfg)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.05)
    yield port
    server.should_exit = True
    th.join(timeout=5)


def _get(pki, zone, port):
    ctx = client_context(pki / zone / "client.crt", pki / zone / "client.key", pki / zone / "ca-authority.crt")

    async def go():
        async with httpx.AsyncClient(base_url=f"https://127.0.0.1:{port}", verify=ctx) as c:
            return (await c.get("/healthz")).status_code

    return asyncio.run(go())


def test_red_cert_is_accepted_by_red_listener(pki, red_listener):
    assert _get(pki, "red", red_listener) == 200


def test_blue_cert_is_rejected_by_red_listener(pki, red_listener):
    with pytest.raises((httpx.HTTPError, ssl.SSLError)):
        _get(pki, "blue", red_listener)


def test_no_client_cert_is_rejected(pki, red_listener):
    ctx = ssl.create_default_context(cafile=str(pki / "red" / "ca-authority.crt"))

    async def go():
        async with httpx.AsyncClient(base_url=f"https://127.0.0.1:{red_listener}", verify=ctx) as c:
            return (await c.get("/healthz")).status_code

    with pytest.raises((httpx.HTTPError, ssl.SSLError)):
        asyncio.run(go())


def test_drill_tls_probe_matches(pki, red_listener):
    ok, _ = _tls_accepts("127.0.0.1", red_listener, 2.0, str(pki / "red/client.crt"), str(pki / "red/client.key"))
    bad, _ = _tls_accepts("127.0.0.1", red_listener, 2.0, str(pki / "blue/client.crt"), str(pki / "blue/client.key"))
    assert ok and not bad


def test_each_zone_dir_holds_only_what_it_needs(pki):
    names = {z: {p.name for p in (pki / z).iterdir()} for z in ("red", "blue", "enclave", "model", "obs", "authority")}
    assert names["red"] == {"client.crt", "client.key", "ca-authority.crt"}
    assert names["blue"] == {"client.crt", "client.key", "ca-authority.crt"}
    assert "server.key" not in names["red"] | names["blue"]
    assert names["model"] == {"server.crt", "server.key", "ca-enclave.crt", "ca-authority.crt"}
