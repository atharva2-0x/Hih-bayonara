"""dbverify: offline verifier CLI.

    dbverify export.json [--pubkey HEX] [--replay stub|http://llama:8080] [--json]

Exit code 0 = verified, 1 = verification failed.
"""

from __future__ import annotations

import argparse
import json
import sys

from .core import Verification, verify_export

ICONS = {"pass": "✅", "fail": "❌", "warn": "⚠️ ", "skip": "⏭️ "}


def render(v: Verification) -> str:
    lines = [f"DOUBLE-BLIND verifier · trial {v.trial_id} \"{v.trial_name}\" · state {v.state}", ""]
    w = max(len(c.name) for c in v.checks) if v.checks else 10
    for c in v.checks:
        lines.append(f"  {ICONS.get(c.status, '?')} {c.name:<{w}}  {c.detail}")
    lines.append("")
    if v.ok:
        verdict = "VERIFIED" + (f" (with {v.warnings} warning{'s' * (v.warnings != 1)})" if v.warnings else "")
    else:
        verdict = "VERIFICATION FAILED" + (f": first tampered event is seq {v.first_bad_seq}" if v.first_bad_seq else "")
    lines.append(f"  RESULT: {verdict}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dbverify", description="Verify a DOUBLE-BLIND trial export offline.")
    ap.add_argument("export")
    ap.add_argument("--pubkey", help="pin the Authority's Ed25519 public key (hex)")
    ap.add_argument("--replay", help="'stub' or a llama.cpp base URL to re-run every case deterministically")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with open(a.export) as fh:
        export = json.load(fh)
    v = verify_export(export, a.pubkey, a.replay)
    print(json.dumps(v.to_dict(), indent=1) if a.json else render(v))
    return 0 if v.ok else 1


if __name__ == "__main__":
    sys.exit(main())
