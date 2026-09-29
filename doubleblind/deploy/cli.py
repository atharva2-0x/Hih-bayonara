"""Docker-mode CLIs: zone services, tenant tooling, operator tooling, PKI.

    python -m doubleblind service {arbiter,enclave,model,obs}
    python -m doubleblind certs --out infra/certs/out [--extra-ip 127.0.0.1]

    # inside the red container (net-red only, red certs only)
    python -m doubleblind red init-vault [--import FILE --field goal --limit 100]
    python -m doubleblind red {commit,run,reveal,report} --trial ID

    # inside the blue container (net-blue only, blue certs only)
    python -m doubleblind blue {commit,upload,reveal,report} --trial ID [--bundle FILE]

    # on the host (operator listener is published on 127.0.0.1:8100)
    python -m doubleblind operator create [--name N] [--config JSON]
    python -m doubleblind operator {arm,start,conclude,canary,status,report} --trial ID
    python -m doubleblind operator export --trial ID --out FILE
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

from ..common.tls import mtls_client


def _tenant_http(zone: str) -> httpx.AsyncClient:
    url = os.environ.get("DB_ARBITER_URL", "https://10.77.1.10:8443" if zone == "red" else "https://10.77.2.10:8443")
    if os.environ.get("DB_TLS", "1") != "1":
        return httpx.AsyncClient(base_url=url.replace("https://", "http://"), timeout=300)
    certs = Path(os.environ.get("DB_CERTS", "/certs"))
    return mtls_client(url, certs / "client.crt", certs / "client.key", certs / "ca-authority.crt", timeout=300)


def _print(obj) -> None:
    print(json.dumps(obj, indent=1))


def _red(a) -> int:
    from ..zones.red.client import RedClient
    from ..zones.red.datasets import load_cases_file, synthetic_suite
    from ..zones.red.vault import create_vault

    vault = Path(a.vault or os.environ.get("DB_VAULT", "/vault/red/vault.json"))
    state = Path(os.environ.get("DB_STATE", "/state/red"))
    if a.action == "init-vault":
        cases = (load_cases_file(a.import_file, a.field, a.expect, a.limit) if a.import_file
                 else synthetic_suite(n_adv=a.n_adv, n_ctrl=a.n_ctrl))
        fp = create_vault(vault, cases)
        print(f"red vault: {len(cases)} cases sealed at {vault} (canary fingerprint {fp[:16]}…)")
        return 0

    async def go():
        async with _tenant_http("red") as http:
            rc = RedClient(http, state, vault)
            if a.action == "commit":
                return await rc.commit(a.trial, mode=a.mode)
            if a.action == "run":
                obs = await rc.run(a.trial, limit=a.limit, concurrency=a.concurrency)
                refused = sum(o["status"] == "REFUSED" for o in obs)
                return {"cases": len(obs), "answered": len(obs) - refused, "refused": refused,
                        "sizes_seen": sorted({o["size"] for o in obs})}
            if a.action == "reveal":
                return await rc.reveal(a.trial)
            return await rc.report(a.trial)

    _print(asyncio.run(go()))
    return 0


def _blue(a) -> int:
    from ..zones.blue.workbench import SAMPLE_BUNDLE, BlueClient

    state = Path(os.environ.get("DB_STATE", "/state/blue"))

    async def go():
        async with _tenant_http("blue") as http:
            bc = BlueClient(http, state, a.bundle or SAMPLE_BUNDLE)
            return await {"commit": bc.commit, "upload": bc.upload, "reveal": bc.reveal,
                          "report": bc.report}[a.action](a.trial)

    _print(asyncio.run(go()))
    return 0


def _operator(a) -> int:
    url = os.environ.get("DB_OPERATOR_URL", "http://127.0.0.1:8100")
    with httpx.Client(base_url=url, timeout=600) as http:
        if a.action == "create":
            r = http.post("/v1/trials", json={"name": a.name, "config": json.loads(a.config or "{}")})
        elif a.action == "list":
            r = http.get("/v1/trials")
        elif a.action == "status":
            r = http.get(f"/v1/trials/{a.trial}")
        elif a.action == "report":
            r = http.get(f"/v1/trials/{a.trial}/report")
        elif a.action == "export":
            r = http.get(f"/v1/trials/{a.trial}/export")
            if r.status_code == 200 and a.out:
                Path(a.out).parent.mkdir(parents=True, exist_ok=True)
                Path(a.out).write_text(r.text)
                print(f"export written to {a.out}")
                return 0
        else:
            path = {"arm": "arm", "start": "start", "conclude": "conclude", "canary": "drill/canary"}[a.action]
            r = http.post(f"/v1/trials/{a.trial}/{path}")
    try:
        body = r.json()
    except ValueError:
        body = r.text
    if a.action == "create" and r.status_code == 200 and a.quiet:
        print(body["id"])
    else:
        _print(body)
    return 0 if r.status_code < 400 else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="doubleblind", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("service")
    p.add_argument("name", choices=["arbiter", "enclave", "model", "obs"])

    p = sub.add_parser("certs")
    p.add_argument("--out", default="infra/certs/out")
    p.add_argument("--extra-ip", action="append", default=[])
    p.add_argument("--days", type=int, default=30)

    p = sub.add_parser("red")
    p.add_argument("action", choices=["init-vault", "commit", "run", "reveal", "report"])
    p.add_argument("--trial")
    p.add_argument("--vault")
    p.add_argument("--mode", default="static", choices=["static", "adaptive"])
    p.add_argument("--limit", type=int)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--import", dest="import_file")
    p.add_argument("--field")
    p.add_argument("--expect", default="refuse", choices=["refuse", "comply"])
    p.add_argument("--n-adv", type=int, default=24)
    p.add_argument("--n-ctrl", type=int, default=8)

    p = sub.add_parser("blue")
    p.add_argument("action", choices=["commit", "upload", "reveal", "report"])
    p.add_argument("--trial", required=True)
    p.add_argument("--bundle")

    p = sub.add_parser("operator")
    p.add_argument("action", choices=["create", "list", "status", "arm", "start", "conclude", "canary", "report", "export"])
    p.add_argument("--trial")
    p.add_argument("--name", default="docker-trial")
    p.add_argument("--config")
    p.add_argument("--out")
    p.add_argument("--quiet", action="store_true", help="create: print only the trial id")

    a = ap.parse_args(argv)
    if a.cmd == "service":
        from .services import SERVICES
        SERVICES[a.name]()
        return 0
    if a.cmd == "certs":
        from .certs import generate
        out = generate(a.out, extra_ips=a.extra_ip, days=a.days)
        print(f"per-zone PKI written to {out}/ (one CA per zone, {a.days}-day leaf certificates)")
        return 0
    if a.cmd in ("red", "blue") and a.action != "init-vault" and not a.trial:
        ap.error("--trial is required")
    return {"red": _red, "blue": _blue, "operator": _operator}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
