"""Detect what this Docker host supports and write .env for docker compose.

Never silently downgrades: every fallback is printed, and the matching drill
check id is added to DB_ACCEPTED_RISKS so that a trial on this host can only
arm with that risk explicitly accepted and recorded in the ledger.
"""

import json
import os
import subprocess
from pathlib import Path


def docker_info() -> dict:
    try:
        out = subprocess.run(["docker", "info", "--format", "{{json .}}"], capture_output=True, text=True, timeout=20)
        return json.loads(out.stdout or "{}")
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def cpusets(n: int) -> dict:
    if n >= 8:
        return {"DB_CPUS_AUTHORITY": "0-1", "DB_CPUS_RED": "2-3", "DB_CPUS_BLUE": "4-5", "DB_CPUS_MODEL": "6-7"}
    if n >= 4:
        return {"DB_CPUS_AUTHORITY": "0", "DB_CPUS_RED": "1", "DB_CPUS_BLUE": "2", "DB_CPUS_MODEL": "3"}
    allc = f"0-{n - 1}" if n > 1 else "0"
    return {k: allc for k in ("DB_CPUS_AUTHORITY", "DB_CPUS_RED", "DB_CPUS_BLUE", "DB_CPUS_MODEL")}


def main() -> None:
    info = docker_info()
    env: dict[str, str] = {}
    risks: list[str] = []
    notes: list[str] = []

    runtimes = set((info.get("Runtimes") or {}).keys())
    if "runsc" in runtimes:
        env["DB_RUNTIME"] = "runsc"
    else:
        env["DB_RUNTIME"] = "runc"
        risks.append("process.gvisor_sandbox")
        notes.append("gVisor (runsc) not installed: falling back to runc. Install gVisor for the full sandbox.")

    secopts = " ".join(info.get("SecurityOptions") or [])
    if "seccomp" in secopts or env["DB_RUNTIME"] == "runsc":
        env["DB_SECCOMP"] = "./infra/seccomp/doubleblind.json"
    else:
        env["DB_SECCOMP"] = "unconfined"
        if env["DB_RUNTIME"] != "runsc":
            risks.append("process.seccomp")
        notes.append("this Docker daemon has no seccomp support: profile cannot be applied.")

    n = os.cpu_count() or 1
    env.update(cpusets(n))
    if n < 4:
        notes.append(f"only {n} CPUs: zones share cores (no cpuset separation).")

    env["DB_BASE_IMAGE"] = os.environ.get("DB_BASE_IMAGE", "python:3.11-slim")
    env["DB_ACCEPTED_RISKS"] = ",".join(risks)

    Path(".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    print("wrote .env:")
    for k, v in env.items():
        print(f"  {k}={v}")
    for note in notes:
        print(f"  ! {note}")
    if risks:
        print(f"  ! trials on this host must accept (and the ledger will record): {', '.join(risks)}")


if __name__ == "__main__":
    main()
