"""Red Vault: the red team's payload set, encrypted at rest with a tenant-held key.

The vault also holds red's leakage canary. The canary is never submitted, so
if it ever shows up outside the red zone, red's secret store has leaked.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ...common.crypto import canonical_json, new_key, seal, unseal
from ...observability.canary import fingerprint, new_canary

VAULT_FORMAT = "doubleblind-red-vault/v1"
PAYLOAD_FORMAT = "doubleblind-payload-set/v1"


def _key_path(vault: Path) -> Path:
    return vault.with_suffix(vault.suffix + ".key")


def create_vault(path: str | Path, cases: list[dict]) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    key = new_key()
    kp = _key_path(p)
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    canary = new_canary()
    clean = [{"id": c["id"], "text": c["text"], "expect": c["expect"]} for c in cases]
    p.write_text(json.dumps({
        "format": VAULT_FORMAT,
        "cases": len(clean),
        "canary_fp": fingerprint(canary),
        "sealed": seal(key, canonical_json({"cases": clean, "canary": canary}), b"red-vault"),
    }))
    return fingerprint(canary)


def open_vault(path: str | Path) -> tuple[list[dict], str]:
    p = Path(path)
    d = json.loads(p.read_text())
    if d.get("format") != VAULT_FORMAT:
        raise ValueError("not a red vault")
    content = json.loads(unseal(_key_path(p).read_bytes(), d["sealed"], b"red-vault"))
    return content["cases"], content["canary"]


def payload_set_bytes(cases: list[dict]) -> bytes:
    """The exact bytes red commits to (and later reveals)."""
    return canonical_json({"format": PAYLOAD_FORMAT, "cases": cases})
