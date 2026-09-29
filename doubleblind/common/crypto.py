"""Cryptographic primitives shared by every zone.

Everything that ends up in the ledger is hashed with *domain-separated,
length-prefixed* SHA-256 (``tagged_hash``) so that a hash computed for one
purpose can never be replayed as a hash for another purpose.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for everything that gets hashed or signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_bytes(part: bytes | str) -> bytes:
    return part.encode("utf-8") if isinstance(part, str) else part


def tagged_hash(tag: str, *parts: bytes | str) -> str:
    """SHA-256 over a domain tag and length-prefixed parts (no concatenation ambiguity)."""
    h = hashlib.sha256()
    t = tag.encode("utf-8")
    h.update(len(t).to_bytes(4, "big"))
    h.update(t)
    for part in parts:
        b = _as_bytes(part)
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)
    return h.hexdigest()


def random_hex(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)


# ---------------------------------------------------------------------------
# Commit-reveal and salted hashes
# ---------------------------------------------------------------------------

COMMIT_TAG = "doubleblind/commit/v1"
SALTED_TAG = "doubleblind/salted/v1"


def commitment(artifact: bytes, nonce_hex: str) -> str:
    """C = H(tag, H(artifact), nonce). Hiding (random nonce) and binding (SHA-256)."""
    return tagged_hash(COMMIT_TAG, hashlib.sha256(artifact).digest(), bytes.fromhex(nonce_hex))


def verify_commitment(commit_hex: str, artifact: bytes, nonce_hex: str) -> bool:
    try:
        return hmac.compare_digest(commitment(artifact, nonce_hex), commit_hex)
    except ValueError:
        return False


def salted_hash(salt_hex: str, data: bytes | str) -> str:
    """Per-trial salted hash. Stops dictionary attacks on the ledger: without the
    salt (sealed until REVEAL) nobody can test whether a public benchmark prompt
    was part of a trial."""
    return tagged_hash(SALTED_TAG, bytes.fromhex(salt_hex), _as_bytes(data))


# ---------------------------------------------------------------------------
# Ed25519 signatures (ledger checkpoints, isolation certificates)
# ---------------------------------------------------------------------------


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self.public_key_hex = (
            private_key.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Signer":
        p = Path(path)
        if p.exists():
            sk = serialization.load_pem_private_key(p.read_bytes(), password=None)
            assert isinstance(sk, Ed25519PrivateKey)
            return cls(sk)
        signer = cls.generate()
        p.parent.mkdir(parents=True, exist_ok=True)
        pem = signer._sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return signer

    @property
    def fingerprint(self) -> str:
        return sha256_hex(bytes.fromhex(self.public_key_hex))[:16]

    def sign(self, data: bytes) -> str:
        return self._sk.sign(data).hex()


def verify_signature(public_key_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), data
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# AES-256-GCM envelopes (sealed records, vaults, wrapped keys)
# ---------------------------------------------------------------------------


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def unseal(key: bytes, token: str, aad: bytes = b"") -> bytes:
    raw = base64.b64decode(token)
    try:
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad)
    except InvalidTag as exc:  # pragma: no cover - exercised via tests
        raise ValueError("sealed envelope failed authentication") from exc


# ---------------------------------------------------------------------------
# Trial-scoped bearer tokens (HMAC-SHA256, expiring, revocable)
# ---------------------------------------------------------------------------


class TokenError(Exception):
    pass


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class TokenIssuer:
    secret: bytes
    revoked_jti: set[str]
    revoked_trials: set[str]

    @classmethod
    def create(cls, secret: bytes | None = None) -> "TokenIssuer":
        return cls(secret or os.urandom(32), set(), set())

    def issue(self, *, sub: str, trial_id: str, scope: Iterable[str], ttl_s: int) -> str:
        claims = {
            "sub": sub,
            "trial_id": trial_id,
            "scope": sorted(scope),
            "exp": int(time.time()) + int(ttl_s),
            "jti": random_hex(8),
        }
        body = _b64u(canonical_json(claims))
        mac = _b64u(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{mac}"

    def verify(self, token: str, *, sub: str, trial_id: str, scope: str) -> dict:
        try:
            body, mac = token.split(".", 1)
        except ValueError as exc:
            raise TokenError("malformed token") from exc
        expected = _b64u(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, mac):
            raise TokenError("bad token signature")
        claims = json.loads(_b64u_dec(body))
        if claims["exp"] < time.time():
            raise TokenError("token expired")
        if claims["jti"] in self.revoked_jti or claims["trial_id"] in self.revoked_trials:
            raise TokenError("token revoked")
        if claims["sub"] != sub or claims["trial_id"] != trial_id or scope not in claims["scope"]:
            raise TokenError("token not valid for this subject/trial/scope")
        return claims

    def revoke_trial(self, trial_id: str) -> None:
        self.revoked_trials.add(trial_id)
