"""Breach Drill -> Isolation Certificate.

Before a trial is ARMED, the platform tries every forbidden path and records
the result. Three families of checks:

* **logical** (always enforceable, run in-process by the Arbiter): exhaustive
  policy invariants, telemetry schema refuses plaintext, the canary pipeline
  flags a foreign canary.
* **process** (run *inside* each zone container by a drill agent): no
  capabilities, no-new-privileges, seccomp filtering, non-root, read-only
  root filesystem, no container-runtime socket, no foreign mounts.
* **network** (run inside each zone container by a drill agent): every
  forbidden cell of the flow matrix must fail to connect or resolve, and every
  allowed cell must succeed. The allowed cells are *positive controls*: they
  prove the drill isn't passing only because the network is down.

In local simulation mode, process and network checks are reported as
``skip``, never as ``pass``. The certificate records its profile, so a
simulated trial can never be passed off as an isolated one.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import time
from pathlib import Path
from typing import Protocol

from ..common.crypto import canonical_json, sha256_hex

MATRIX_PATH = Path(__file__).with_name("flow_matrix.json")
CERT_FORMAT = "doubleblind-isolation-cert/v1"


def result(zone: str, cid: str, category: str, status: str, detail: str, positive: bool = False) -> dict:
    return {"zone": zone, "id": cid, "category": category, "status": status, "detail": detail[:200],
            "positive_control": positive}


# --------------------------------------------------------------------- logical


def logical_checks() -> list[dict]:
    from pydantic import ValidationError

    from ..authority.policy import PolicyEngine
    from ..common.telemetry import TelemetryEvent
    from ..observability.canary import fingerprint, new_canary
    from ..observability.service import ObservabilityService

    out = []
    inv = PolicyEngine.load().check_invariants()
    bad = [i["id"] for i in inv if not i["ok"]]
    out.append(result("authority", "logical.policy_invariants", "logical", "fail" if bad else "pass",
                      f"{sum(i['checked'] for i in inv)} decisions checked; violated: {bad or 'none'}"))
    try:
        TelemetryEvent(kind="boundary", trial_id="t-000000000000", text="plaintext")  # type: ignore[call-arg]
        out.append(result("observability", "logical.telemetry_no_plaintext", "logical", "fail", "free text accepted"))
    except ValidationError:
        out.append(result("observability", "logical.telemetry_no_plaintext", "logical", "pass",
                          "schema rejects unknown/free-text fields"))

    async def canary_selftest() -> str:
        svc = ObservabilityService()
        tok = new_canary()
        svc.register("t-000000000000", "blue", fingerprint(tok))
        r = await svc.ingest(TelemetryEvent(kind="boundary", trial_id="t-000000000000", zone_from="red",
                                            zone_to="authority", canary_fps=[fingerprint(tok)]))
        return r["verdict"]

    try:
        verdict = asyncio.run(canary_selftest())
    except RuntimeError:  # already inside an event loop
        loop = asyncio.new_event_loop()
        try:
            verdict = loop.run_until_complete(canary_selftest())
        finally:
            loop.close()
    out.append(result("observability", "logical.canary_pipeline", "logical",
                      "pass" if verdict == "breach" else "fail", f"foreign canary verdict: {verdict}"))
    return out


# --------------------------------------------------------------------- process


def _status_field(name: str) -> str | None:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(name + ":"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _in_gvisor() -> bool:
    """gVisor's emulated kernel log starts with 'Starting gVisor...'."""
    import subprocess

    try:
        out = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=3).stdout
        return "gVisor" in out
    except (OSError, subprocess.SubprocessError):
        return False


def process_checks(zone: str, forbidden_paths: list[str]) -> list[dict]:
    out = []
    cap = _status_field("CapEff")
    out.append(result(zone, "process.no_capabilities", "process",
                      "pass" if cap is not None and int(cap, 16) == 0 else "fail", f"CapEff={cap}"))
    nnp = _status_field("NoNewPrivs")
    out.append(result(zone, "process.no_new_privileges", "process", "pass" if nnp == "1" else "fail",
                      f"NoNewPrivs={nnp}"))
    sec = _status_field("Seccomp")
    gv = _in_gvisor()
    out.append(result(zone, "process.seccomp", "process", "pass" if sec == "2" or gv else "fail",
                      f"Seccomp={sec}{' (gVisor sandbox)' if gv else ''}"))
    out.append(result(zone, "process.non_root", "process", "pass" if os.getuid() != 0 else "fail",
                      f"uid={os.getuid()}"))
    probe = Path("/drill-write-probe")
    try:
        probe.write_text("x")
        probe.unlink()
        out.append(result(zone, "process.readonly_rootfs", "process", "fail", "root filesystem is writable"))
    except OSError as exc:
        out.append(result(zone, "process.readonly_rootfs", "process", "pass", f"write refused ({exc.errno})"))
    socks = [p for p in ("/var/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock")
             if Path(p).exists()]
    out.append(result(zone, "process.no_runtime_socket", "process", "fail" if socks else "pass",
                      f"present: {socks}" if socks else "no container runtime socket mounted"))
    present = [p for p in forbidden_paths if Path(p).exists()]
    out.append(result(zone, "process.no_foreign_mounts", "process", "fail" if present else "pass",
                      f"visible: {present}" if present else f"{len(forbidden_paths)} foreign paths absent"))
    return out


# --------------------------------------------------------------------- network


def _tcp(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except OSError as exc:
        return False, type(exc).__name__


def _tls_accepts(host: str, port: int, timeout: float, cert: str | None, key: str | None) -> tuple[bool, str]:
    """Does the listener complete a mutual-TLS exchange with *our* client cert?"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only test whether *they* accept *us*
    if cert and key and Path(cert).exists():
        ctx.load_cert_chain(cert, key)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                data = tls.recv(64)
                return (data.startswith(b"HTTP/1.1 200"), "handshake+request ok" if data else "closed")
    except (OSError, ssl.SSLError) as exc:
        return False, type(exc).__name__


def _dns(name: str) -> tuple[bool, str]:
    try:
        return True, socket.gethostbyname(name)
    except OSError as exc:
        return False, type(exc).__name__


def network_checks(zone: str, matrix: dict, timeout: float = 1.5) -> list[dict]:
    spec = matrix["zones"][zone]
    targets = matrix["targets"]
    cert, key = os.environ.get("DB_TLS_CERT"), os.environ.get("DB_TLS_KEY")
    out = []
    for tname in spec.get("allow", []):
        t = targets[tname]
        ok, why = _tcp(t["host"], t["port"], timeout)
        out.append(result(zone, f"net.allow.{tname}", "network", "pass" if ok else "fail",
                          f"{t['host']}:{t['port']} -> {why}", positive=True))
    for tname in spec.get("deny", []):
        t = targets[tname]
        ok, why = _tcp(t["host"], t["port"], timeout)
        out.append(result(zone, f"net.deny.{tname}", "network", "fail" if ok else "pass",
                          f"{t['host']}:{t['port']} -> {why}"))
    for tname in spec.get("tls_deny", []):
        t = targets[tname]
        ok, why = _tls_accepts(t["host"], t["port"], timeout, cert, key)
        out.append(result(zone, f"mtls.deny.{tname}", "network", "fail" if ok else "pass",
                          f"{t['host']}:{t['port']} with {zone} identity -> {why}"))
    for tname in spec.get("tls_allow", []):
        t = targets[tname]
        ok, why = _tls_accepts(t["host"], t["port"], timeout, cert, key)
        out.append(result(zone, f"mtls.allow.{tname}", "network", "pass" if ok else "fail",
                          f"{t['host']}:{t['port']} with {zone} identity -> {why}", positive=True))
    for name in spec.get("dns_deny", []):
        ok, why = _dns(name)
        out.append(result(zone, f"dns.deny.{name}", "network", "fail" if ok else "pass", f"{name} -> {why}"))
    return out


def run_agent(zone: str, out_dir: str, matrix_path: str | Path = MATRIX_PATH) -> dict:
    matrix = json.loads(Path(matrix_path).read_text())
    results = process_checks(zone, matrix["zones"][zone].get("forbidden_paths", [])) + network_checks(zone, matrix)
    report = {"zone": zone, "generated_at": time.time(), "matrix_sha256": sha256_hex(canonical_json(matrix)),
              "results": results}
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / f"{zone}.json").write_text(json.dumps(report, indent=1))
    return report


# --------------------------------------------------------------------- certificates


def summarize(results: list[dict]) -> dict:
    pos = [r for r in results if r["positive_control"]]
    return {
        "total": len(results),
        "pass": sum(r["status"] == "pass" for r in results),
        "fail": sum(r["status"] == "fail" for r in results),
        "skip": sum(r["status"] == "skip" for r in results),
        "positive_controls": {"total": len(pos), "pass": sum(r["status"] == "pass" for r in pos)},
        "failed_ids": sorted({r["id"] for r in results if r["status"] == "fail"}),
    }


def make_certificate(profile: str, results: list[dict], matrix_sha256: str | None = None) -> dict:
    return {"format": CERT_FORMAT, "profile": profile, "generated_at": time.time(),
            "matrix_sha256": matrix_sha256, "results": results, "summary": summarize(results)}


def cert_hash(cert: dict) -> str:
    return sha256_hex(canonical_json(cert))


class DrillProvider(Protocol):
    async def certificate(self) -> dict: ...


class LocalDrill:
    """In-process simulation: logical checks run for real; process and network
    isolation cannot be enforced in one process, so they are reported as skip."""

    async def certificate(self) -> dict:
        results = await asyncio.to_thread(logical_checks)
        matrix = json.loads(MATRIX_PATH.read_text())
        for zone in matrix["zones"]:
            results.append(result(zone, "process.*", "process", "skip", "not enforced in local simulation"))
            results.append(result(zone, "net.*", "network", "skip", "not enforced in local simulation"))
        return make_certificate("local-sim", results, sha256_hex(canonical_json(matrix)))


class FileDrill:
    """Docker profile: aggregates the per-zone reports written by drill agents
    (fresh reports only) and adds the logical checks."""

    def __init__(self, results_dir: str | Path, max_age_s: float = 1800, zones: list[str] | None = None):
        self.dir = Path(results_dir)
        self.max_age_s = max_age_s
        self.zones = zones

    async def certificate(self) -> dict:
        results = await asyncio.to_thread(logical_checks)
        matrix = json.loads(MATRIX_PATH.read_text())
        mhash = sha256_hex(canonical_json(matrix))
        for zone in self.zones or list(matrix["zones"]):
            p = self.dir / f"{zone}.json"
            if not p.exists():
                results.append(result(zone, "drill.report_present", "meta", "fail", "no drill report for zone"))
                continue
            rep = json.loads(p.read_text())
            age = time.time() - rep.get("generated_at", 0)
            if age > self.max_age_s:
                results.append(result(zone, "drill.report_fresh", "meta", "fail", f"report is {age:.0f}s old"))
                continue
            if rep.get("matrix_sha256") != mhash:
                results.append(result(zone, "drill.matrix_match", "meta", "fail", "report used a different flow matrix"))
                continue
            results.extend(rep["results"])
        return make_certificate("docker", results, mhash)
