"""DOUBLE-BLIND command line.

Local simulation (no Docker needed)
    python -m doubleblind demo [--scenario all|standard|canary|contamination]
    python -m doubleblind serve            # site on http://127.0.0.1:8100, War Room at /warroom
    python -m doubleblind bench [leakage|overhead|kvcache|all]
    python -m doubleblind policy           # exhaustive policy invariant check
    python -m doubleblind verify EXPORT [--replay stub]
    python -m doubleblind tamper EXPORT [--seq N]

Docker deployment (see docker-compose.yml)
    python -m doubleblind service {arbiter,enclave,model,obs}
    python -m doubleblind drill --zone ZONE --out DIR
    python -m doubleblind red|blue|operator ...
    python -m doubleblind certs --out DIR
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from pathlib import Path


def _cmd_demo(a) -> int:
    from .demo import run_scenario
    from .local import build_local_stack
    from .verifier.cli import render
    from .verifier.core import verify_export
    from .tools.tamper import tamper_export

    wd = Path(a.workdir)
    if wd.exists() and a.fresh:
        shutil.rmtree(wd)
    stack = build_local_stack(wd)
    scenarios = ["standard", "canary", "contamination"] if a.scenario == "all" else [a.scenario]

    async def go():
        results = []
        for sc in scenarios:
            print(f"\n══ scenario: {sc} " + "═" * (60 - len(sc)))
            results.append(await run_scenario(stack, sc, bucket_ms=a.bucket_ms, exports_dir=a.exports))
        return results

    results = asyncio.run(go())
    for r in results:
        if r.get("export"):
            export = json.loads(Path(r["export"]).read_text())
            print("\n══ offline verification " + "═" * 44)
            print(render(verify_export(export, replay="stub" if a.replay else None)))
            print("\n══ tamper test: flip one character in one ledger event " + "═" * 12)
            tampered, seq = tamper_export(export)
            print(render(verify_export(tampered)))
    print("\nsummary: " + ", ".join(f"{r['trial_id']} → {r['state']}" for r in results))
    return 0


def _cmd_serve(a) -> int:
    import uvicorn

    from .demo import Demo
    from .local import build_local_stack

    demo = Demo(exports_dir=a.exports)
    stack = build_local_stack(a.workdir, demo=demo, metrics_dir=a.metrics)
    demo.stack = stack
    servers = [
        uvicorn.Server(uvicorn.Config(stack.apps["operator"], host=a.host, port=a.port, log_level="warning")),
        uvicorn.Server(uvicorn.Config(stack.apps["red"], host=a.host, port=a.port + 1, log_level="warning")),
        uvicorn.Server(uvicorn.Config(stack.apps["blue"], host=a.host, port=a.port + 2, log_level="warning")),
    ]
    print(f"Site          http://{a.host}:{a.port}/")
    print(f"War Room      http://{a.host}:{a.port}/warroom")
    print(f"red listener  http://{a.host}:{a.port + 1}   blue listener http://{a.host}:{a.port + 2}")
    print("(local simulation: zones share one process; see docker-compose.yml for the isolated deployment)")

    async def go():
        await asyncio.gather(*(s.serve() for s in servers))

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_bench(a) -> int:
    from .bench import kvcache, leakage, overhead

    out = Path(a.out)
    which = ["leakage", "overhead", "kvcache"] if a.which == "all" else [a.which]
    for w in which:
        mod = {"leakage": leakage, "overhead": overhead, "kvcache": kvcache}[w]
        asyncio.run(mod.run(out=out / f"{w}.json"))
    return 0


def _cmd_policy(a) -> int:
    from .authority.policy import PolicyEngine

    pe = PolicyEngine.load(a.file) if a.file else PolicyEngine.load()
    res = pe.check_invariants()
    print(f"policy {pe.policy['version']}  sha256 {pe.hash[:16]}…\n")
    for r in res:
        print(f"  {'✅' if r['ok'] else '❌'} {r['id']}  {r['text']}  ({r['checked']} decisions)")
        for v in r["violations"][:5]:
            print(f"        violation: {v}")
    total = sum(r["checked"] for r in res)
    bad = [r for r in res if not r["ok"]]
    print(f"\n  {total} decisions checked exhaustively: " + ("ALL INVARIANTS HOLD" if not bad else f"{len(bad)} VIOLATED"))
    return 1 if bad else 0


def _cmd_drill(a) -> int:
    from .drill.drill import run_agent

    rep = run_agent(a.zone, a.out)
    bad = [r for r in rep["results"] if r["status"] == "fail"]
    for r in rep["results"]:
        print(f"  {'✅' if r['status'] == 'pass' else '❌' if r['status'] == 'fail' else '⏭️ '} {r['id']:<34} {r['detail']}")
    print(f"\n  zone {a.zone}: {len(rep['results']) - len(bad)}/{len(rep['results'])} checks passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="doubleblind", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("demo", help="run scripted scenarios in the local simulation")
    p.add_argument("--scenario", default="all", choices=["all", "standard", "canary", "contamination"])
    p.add_argument("--workdir", default="var/demo")
    p.add_argument("--exports", default="exports")
    p.add_argument("--bucket-ms", type=int, default=150)
    p.add_argument("--replay", action="store_true", help="also replay every case deterministically when verifying")
    p.add_argument("--fresh", action="store_true", help="wipe the workdir first")
    p.set_defaults(fn=_cmd_demo)

    p = sub.add_parser("serve", help="local simulation + site + War Room")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8100)
    p.add_argument("--workdir", default="var/serve")
    p.add_argument("--exports", default="exports")
    p.add_argument("--metrics", default="docs/results")
    p.set_defaults(fn=_cmd_serve)

    p = sub.add_parser("bench", help="leakage / overhead / kvcache benchmarks")
    p.add_argument("which", nargs="?", default="all", choices=["all", "leakage", "overhead", "kvcache"])
    p.add_argument("--out", default="docs/results")
    p.set_defaults(fn=_cmd_bench)

    p = sub.add_parser("policy", help="exhaustively check policy invariants")
    p.add_argument("--file")
    p.set_defaults(fn=_cmd_policy)

    p = sub.add_parser("drill", help="run the breach-drill agent for one zone (inside its container)")
    p.add_argument("--zone", required=True)
    p.add_argument("--out", default="/drill-out")
    p.set_defaults(fn=_cmd_drill)

    sub.add_parser("verify", help="offline verifier (same as dbverify)", add_help=False)
    sub.add_parser("tamper", help="flip one character in a ledger event", add_help=False)

    for name in ("service", "red", "blue", "operator", "certs"):
        sub.add_parser(name, add_help=False)

    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "verify":
        from .verifier.cli import main as vmain
        return vmain(argv[1:])
    if argv and argv[0] == "tamper":
        from .tools.tamper import main as tmain
        return tmain(argv[1:])
    if argv and argv[0] in ("service", "red", "blue", "operator", "certs"):
        from .deploy import cli as dcli
        return dcli.main(argv)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
