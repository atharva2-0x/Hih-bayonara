"""Key Broker: per-trial data keys, key wrapping, trial-scoped tokens.

* Every trial gets its own data-encryption key (DEK). Sealed records (case
  text, model output, verdicts) are encrypted with it the moment they are
  produced, so nothing sensitive sits in Authority memory or disk in plaintext.
* DEKs are wrapped with the Authority key-encryption key (KEK). In production
  the KEK would live in a KMS/HSM; here it is a file readable only inside the
  Authority zone.
* Tenants receive short-lived bearer tokens scoped to one trial, one role and
  a set of actions. Tokens are revoked the moment a trial concludes.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..common.crypto import TokenIssuer, new_key, seal, unseal


class KeyBroker:
    def __init__(self, kek: bytes, token_secret: bytes):
        self._kek = kek
        self.tokens = TokenIssuer.create(token_secret)

    @classmethod
    def ephemeral(cls) -> "KeyBroker":
        return cls(new_key(), os.urandom(32))

    @classmethod
    def from_dir(cls, key_dir: str | Path) -> "KeyBroker":
        d = Path(key_dir)
        d.mkdir(parents=True, exist_ok=True)

        def _load(name: str, n: int) -> bytes:
            p = d / name
            if not p.exists():
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(os.urandom(n))
            return p.read_bytes()

        return cls(_load("kek.bin", 32), _load("token.bin", 32))

    def new_dek(self) -> tuple[bytes, str]:
        dek = new_key()
        return dek, seal(self._kek, dek, b"dek")

    def unwrap(self, wrapped: str) -> bytes:
        return unseal(self._kek, wrapped, b"dek")

    def issue(self, trial_id: str, role: str, scope: list[str], ttl_s: int) -> str:
        return self.tokens.issue(sub=role, trial_id=trial_id, scope=scope, ttl_s=ttl_s)

    def check(self, token: str, trial_id: str, role: str, scope: str) -> dict:
        return self.tokens.verify(token, sub=role, trial_id=trial_id, scope=scope)

    def revoke_trial(self, trial_id: str) -> None:
        self.tokens.revoke_trial(trial_id)
