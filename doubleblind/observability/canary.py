"""Leakage canaries (honeytokens).

Tenant tooling plants a unique random token in each tenant's secret material:
the red vault and the blue defense bundle (inside its system prompt). Only the
token's SHA-256 fingerprint is registered with the platform, so the
observability zone can recognise a canary without ever holding one.

The Arbiter scans every message that crosses a tenant boundary, fingerprints
anything that looks like a canary, and sends only those fingerprints to the
Canary Watcher. If a canary shows up somewhere its owner's data should never
reach, isolation has failed, and we can prove it.
"""

from __future__ import annotations

import base64
import os
import re

from ..common.crypto import sha256_hex

CANARY_RE = re.compile(r"cnry_[a-z2-7]{24}")


def new_canary() -> str:
    return "cnry_" + base64.b32encode(os.urandom(15)).decode("ascii").lower()


def fingerprint(token: str) -> str:
    return sha256_hex(token.encode("utf-8"))


def scan(text: str | None) -> list[str]:
    """Fingerprints of every canary-shaped token in ``text`` (deduplicated, bounded)."""
    if not text:
        return []
    seen: list[str] = []
    for m in CANARY_RE.finditer(text):
        fp = fingerprint(m.group(0))
        if fp not in seen:
            seen.append(fp)
        if len(seen) >= 16:
            break
    return seen
