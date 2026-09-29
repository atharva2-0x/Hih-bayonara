"""Tamper tool for the demo: flip one character in one ledger event.

Works on an export copy (non-destructive, used by the War Room) or directly
on a ledger database (``--db``) to show that even an attacker with write
access to storage cannot rewrite history undetected.
"""

from __future__ import annotations

import copy
import json
import sqlite3


def _flip(s: str) -> str:
    """Change one hex digit inside the body (keeps valid JSON, so only the hash catches it)."""
    for i in range(len(s) - 1, -1, -1):
        if s[i] in "0123456789abcdef" and s[i - 1] not in ':"' and i > 10:
            return s[:i] + ("0" if s[i] != "0" else "1") + s[i + 1:]
    return s + " "


def pick_seq(events: list[dict]) -> int:
    cases = [e for e in events if e["type"] == "CASE"]
    target = cases[len(cases) // 2] if cases else events[len(events) // 2]
    return target["seq"]


def tamper_export(export: dict, seq: int | None = None) -> tuple[dict, int]:
    out = copy.deepcopy(export)
    events = out["ledger"]["events"] if "ledger" in out else out["events"]
    seq = seq or pick_seq(events)
    ev = next(e for e in events if e["seq"] == seq)
    ev["body_json"] = _flip(ev["body_json"])
    return out, seq


def tamper_db(db_path: str, seq: int) -> None:
    db = sqlite3.connect(db_path)
    (body,) = db.execute("SELECT body FROM events WHERE seq = ?", (seq,)).fetchone()
    db.execute("UPDATE events SET body = ? WHERE seq = ?", (_flip(body), seq))
    db.commit()
    db.close()


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="doubleblind tamper")
    ap.add_argument("target", help="export JSON file, or ledger .db with --db")
    ap.add_argument("--seq", type=int)
    ap.add_argument("--db", action="store_true")
    ap.add_argument("--out", help="output path for a tampered export copy")
    a = ap.parse_args(argv)
    if a.db:
        if not a.seq:
            ap.error("--seq is required with --db")
        tamper_db(a.target, a.seq)
        print(f"flipped one character in event seq {a.seq} of {a.target}")
        return 0
    export = json.load(open(a.target))
    tampered, seq = tamper_export(export, a.seq)
    out = a.out or a.target.replace(".json", ".tampered.json")
    with open(out, "w") as fh:
        json.dump(tampered, fh)
    print(f"flipped one character in event seq {seq}; wrote {out}")
    return 0
