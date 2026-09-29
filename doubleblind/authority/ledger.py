"""Tamper-evident Trial Ledger.

* Append-only SQLite table of events. Each event commits to its predecessor
  (``prev_hash``), forming a hash chain.
* Periodic Merkle checkpoints over all event hashes so far, signed with the
  Authority's Ed25519 key. Checkpoints make truncation or rewriting detectable
  even by someone who only holds an old signed root.
* Event bodies hold **only commitments, salted hashes and metadata**, never
  adversarial payloads or defense logic, so the ledger can be shared (or
  anchored publicly) during a trial without leaking anything.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..common.crypto import Signer, canonical_json, tagged_hash, verify_signature
from ..common.merkle import merkle_root

GENESIS_HASH = "0" * 64
EVENT_TAG = "doubleblind/event/v1"
CHECKPOINT_TAG = "doubleblind/checkpoint/v1"
EXPORT_FORMAT = "doubleblind-ledger/v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def event_hash(seq: int, ts: str, trial_id: str, etype: str, body_json: str, prev_hash: str) -> str:
    return tagged_hash(EVENT_TAG, str(seq), ts, trial_id, etype, body_json, prev_hash)


def checkpoint_message(upto_seq: int, root: str, ts: str) -> bytes:
    return canonical_json({"tag": CHECKPOINT_TAG, "upto_seq": upto_seq, "merkle_root": root, "ts": ts})


class Ledger:
    def __init__(self, path: str | Path, signer: Signer, on_append: Callable[[dict], None] | None = None):
        self.path = str(path)
        self.signer = signer
        self.on_append = on_append
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL" if self.path != ":memory:" else "PRAGMA journal_mode=MEMORY")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                trial_id TEXT NOT NULL,
                type TEXT NOT NULL,
                body TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upto_seq INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                ts TEXT NOT NULL,
                signature TEXT NOT NULL,
                public_key TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            """
        )

    # -- writes -------------------------------------------------------------

    def append(self, trial_id: str, etype: str, body: dict[str, Any]) -> dict:
        with self._lock:
            seq, prev = self._head_locked()
            seq += 1
            ts = utc_now()
            body_json = canonical_json(body).decode("utf-8")
            h = event_hash(seq, ts, trial_id, etype, body_json, prev)
            self._db.execute(
                "INSERT INTO events(seq, ts, trial_id, type, body, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (seq, ts, trial_id, etype, body_json, prev, h),
            )
            ev = {"seq": seq, "ts": ts, "trial_id": trial_id, "type": etype, "body": body,
                  "prev_hash": prev, "hash": h}
        if self.on_append:
            self.on_append(ev)
        return ev

    def checkpoint(self, reason: str = "periodic") -> dict:
        with self._lock:
            rows = self._db.execute("SELECT hash FROM events ORDER BY seq").fetchall()
            upto = len(rows)
            root = merkle_root([r[0] for r in rows])
            ts = utc_now()
            sig = self.signer.sign(checkpoint_message(upto, root, ts))
            self._db.execute(
                "INSERT INTO checkpoints(upto_seq, merkle_root, ts, signature, public_key, reason) VALUES (?,?,?,?,?,?)",
                (upto, root, ts, sig, self.signer.public_key_hex, reason),
            )
        return {"upto_seq": upto, "merkle_root": root, "ts": ts, "signature": sig,
                "public_key": self.signer.public_key_hex, "reason": reason}

    # -- reads --------------------------------------------------------------

    def _head_locked(self) -> tuple[int, str]:
        row = self._db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS_HASH)

    def head(self) -> tuple[int, str]:
        with self._lock:
            return self._head_locked()

    def events(self, since_seq: int = 0, trial_id: str | None = None, limit: int | None = None) -> list[dict]:
        q = "SELECT seq, ts, trial_id, type, body, prev_hash, hash FROM events WHERE seq > ?"
        args: list[Any] = [since_seq]
        if trial_id:
            q += " AND trial_id = ?"
            args.append(trial_id)
        q += " ORDER BY seq"
        if limit:
            q += " LIMIT ?"
            args.append(limit)
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [
            {"seq": r[0], "ts": r[1], "trial_id": r[2], "type": r[3], "body_json": r[4],
             "prev_hash": r[5], "hash": r[6]}
            for r in rows
        ]

    def checkpoints(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT upto_seq, merkle_root, ts, signature, public_key, reason FROM checkpoints ORDER BY id"
            ).fetchall()
        return [
            {"upto_seq": r[0], "merkle_root": r[1], "ts": r[2], "signature": r[3], "public_key": r[4], "reason": r[5]}
            for r in rows
        ]

    def export(self) -> dict:
        """Raw export: bodies are kept as the exact stored JSON text so the
        verifier re-hashes precisely what was written (tampering included)."""
        return {
            "format": EXPORT_FORMAT,
            "public_key": self.signer.public_key_hex,
            "events": self.events(),
            "checkpoints": self.checkpoints(),
        }


# ---------------------------------------------------------------------------
# Offline verification (also used by the verifier CLI)
# ---------------------------------------------------------------------------


@dataclass
class LedgerReport:
    ok: bool = True
    events: int = 0
    checkpoints: int = 0
    first_bad_seq: int | None = None
    problems: list[str] = field(default_factory=list)

    def fail(self, msg: str, seq: int | None = None) -> None:
        self.ok = False
        self.problems.append(msg)
        if seq is not None and (self.first_bad_seq is None or seq < self.first_bad_seq):
            self.first_bad_seq = seq


def verify_ledger_export(export: dict, pinned_public_key: str | None = None) -> LedgerReport:
    rep = LedgerReport()
    if export.get("format") != EXPORT_FORMAT:
        rep.fail(f"unknown export format {export.get('format')!r}")
        return rep
    pub = export.get("public_key", "")
    if pinned_public_key and pub != pinned_public_key:
        rep.fail("ledger public key does not match the pinned Authority key")

    events = export.get("events", [])
    rep.events = len(events)
    prev = GENESIS_HASH
    hashes: list[str] = []
    for i, ev in enumerate(events, start=1):
        seq = ev.get("seq")
        if seq != i:
            rep.fail(f"sequence gap: expected seq {i}, found {seq}", i)
        if ev.get("prev_hash") != prev:
            rep.fail(f"seq {seq}: prev_hash does not link to previous event", seq)
        recomputed = event_hash(seq, ev["ts"], ev["trial_id"], ev["type"], ev["body_json"], ev["prev_hash"])
        if recomputed != ev.get("hash"):
            rep.fail(f"seq {seq}: content hash mismatch (event was modified after it was written)", seq)
        prev = ev.get("hash", "")
        hashes.append(recomputed)

    cps = export.get("checkpoints", [])
    rep.checkpoints = len(cps)
    for cp in cps:
        upto = cp["upto_seq"]
        if upto > len(hashes):
            rep.fail(f"checkpoint covers seq {upto} but only {len(hashes)} events exist (truncation?)", len(hashes) + 1)
            continue
        root = merkle_root(hashes[:upto])
        if root != cp["merkle_root"]:
            rep.fail(f"checkpoint @ seq {upto}: Merkle root mismatch", None)
        if cp.get("public_key") != pub:
            rep.fail(f"checkpoint @ seq {upto}: signed by an unexpected key")
        if not verify_signature(cp["public_key"], checkpoint_message(upto, cp["merkle_root"], cp["ts"]), cp["signature"]):
            rep.fail(f"checkpoint @ seq {upto}: invalid Ed25519 signature")
    return rep
