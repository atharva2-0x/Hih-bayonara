import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from doubleblind.bench import kvcache
from doubleblind.bench.stats import knn_cv_accuracy, stump_cv_accuracy, wilson_ci
from doubleblind.demo import run_scenario
from doubleblind.drill.drill import LocalDrill, network_checks, process_checks
from doubleblind.local import build_local_stack
from doubleblind.tools.tamper import tamper_export
from doubleblind.verifier.cli import main as dbverify
from doubleblind.verifier.core import verify_export


def _standard_export(tmp_path):
    s = build_local_stack(tmp_path / "w", time_scale=0.02)
    r = asyncio.run(run_scenario(s, "standard", bucket_ms=25, exports_dir=tmp_path / "exports", log=lambda m: None))
    return s, json.loads(open(r["export"]).read())


def test_verifier_passes_clean_export_with_replay(tmp_path):
    _, export = _standard_export(tmp_path)
    v = verify_export(export, replay="stub")
    statuses = {c.name: c.status for c in v.checks}
    assert v.ok, [c for c in v.checks if c.status == "fail"]
    assert statuses["deterministic replay"] == "pass"
    assert statuses["isolation certificate"] == "warn"  # local-sim is never reported as a pass
    assert statuses["sealed records"] == "pass" and statuses["cases ⊆ committed set"] == "pass"


def test_verifier_catches_tampering_everywhere(tmp_path):
    _, export = _standard_export(tmp_path)

    tampered, seq = tamper_export(export)
    v = verify_export(tampered)
    assert not v.ok and v.first_bad_seq == seq

    swapped = json.loads(json.dumps(export))
    rec = swapped["trial"]["records"][0]
    rec["output"] = (rec["output"] or "") + " (edited)"
    assert {c.name for c in verify_export(swapped).checks if c.status == "fail"} == {"sealed records"}

    forged = json.loads(json.dumps(export))
    forged["trial"]["reveals"]["blue"]["nonce"] = "0" * 64
    assert "commitment opens (blue)" in {c.name for c in verify_export(forged).checks if c.status == "fail"}

    cert = json.loads(json.dumps(export))
    cert["trial"]["cert"]["summary"]["skip"] = 0
    assert "isolation certificate" in {c.name for c in verify_export(cert).checks if c.status == "fail"}


def test_verifier_pinned_key_and_cli(tmp_path, capsys):
    s, export = _standard_export(tmp_path)
    p = tmp_path / "e.json"
    p.write_text(json.dumps(export))
    assert dbverify([str(p), "--pubkey", s.authority.d.ledger.signer.public_key_hex]) == 0
    assert dbverify([str(p), "--pubkey", "ab" * 32]) == 1
    assert "RESULT" in capsys.readouterr().out


def test_invalidated_trial_export_verifies_as_invalidated(tmp_path):
    s = build_local_stack(tmp_path / "w", time_scale=0.02)
    r = asyncio.run(run_scenario(s, "canary", bucket_ms=25, log=lambda m: None))
    export = asyncio.run(s.operator_http.get(f"/v1/trials/{r['trial_id']}/export")).json()
    v = verify_export(export)
    assert v.ok and v.state == "INVALIDATED"
    assert any(c.name == "invalidation recorded" and "canary" in c.detail for c in v.checks)


def test_local_drill_certificate_is_honest():
    cert = asyncio.run(LocalDrill().certificate())
    assert cert["profile"] == "local-sim"
    assert cert["summary"]["fail"] == 0 and cert["summary"]["skip"] > 0
    assert {r["id"] for r in cert["results"] if r["category"] == "logical"} == {
        "logical.policy_invariants", "logical.telemetry_no_plaintext", "logical.canary_pipeline"}


def test_process_checks_run_and_report():
    res = process_checks("red", ["/definitely/not/here"])
    ids = {r["id"] for r in res}
    assert {"process.no_capabilities", "process.readonly_rootfs", "process.no_foreign_mounts"} <= ids
    assert next(r for r in res if r["id"] == "process.no_foreign_mounts")["status"] == "pass"


def test_network_checks_positive_and_negative_controls():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    closed_port = free.getsockname()[1]
    free.close()
    matrix = {"targets": {"up": {"host": "127.0.0.1", "port": srv.server_address[1]},
                          "down": {"host": "127.0.0.1", "port": closed_port}},
              "zones": {"red": {"allow": ["up"], "deny": ["down"], "dns_deny": ["no-such-host.invalid"]}}}
    res = {r["id"]: r for r in network_checks("red", matrix, timeout=0.5)}
    srv.shutdown()
    assert res["net.allow.up"]["status"] == "pass" and res["net.allow.up"]["positive_control"]
    assert res["net.deny.down"]["status"] == "pass"
    assert res["dns.deny.no-such-host.invalid"]["status"] == "pass"


def test_classifiers_and_ci():
    X = [[i, 0] for i in range(40)] + [[i + 100, 0] for i in range(40)]
    y = [0] * 40 + [1] * 40
    assert knn_cv_accuracy(X, y) == 1.0 and stump_cv_accuracy(X, y) == 1.0
    lo, hi = wilson_ci(0.5, 200)
    assert lo < 0.5 < hi


def test_kvcache_bench_smoke():
    res = asyncio.run(kvcache.run(pairs=20, log=lambda m: None))
    assert res["global_cache"]["observer_accuracy"] > 0.9
    assert res["session_cache"]["observer_accuracy"] < 0.75
