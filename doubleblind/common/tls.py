"""Pinned mutual TLS between zones.

Every zone has its **own** certificate authority. A listener trusts only the
CA of the zone(s) allowed to call it. So the red listener accepts red's
certificate and nothing else, even though every certificate in the
deployment is "valid". A stolen blue certificate is useless against the red
listener, and the enclave's certificate cannot open the model's admin port.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import httpx


def server_ssl(certfile: str | Path, keyfile: str | Path, client_ca: str | Path) -> dict:
    """uvicorn.Config kwargs for a listener that requires a client cert from ``client_ca``."""
    return {
        "ssl_certfile": str(certfile),
        "ssl_keyfile": str(keyfile),
        "ssl_ca_certs": str(client_ca),
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
    }


def client_context(certfile: str | Path, keyfile: str | Path, server_ca: str | Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(server_ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(certfile), str(keyfile))
    return ctx


def mtls_client(base_url: str, certfile: str | Path, keyfile: str | Path, server_ca: str | Path,
                timeout: float = 120.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=base_url, verify=client_context(certfile, keyfile, server_ca), timeout=timeout)
