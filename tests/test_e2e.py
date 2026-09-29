"""End-to-end trials through the in-process stack (same HTTP paths as Docker)."""

import asyncio
import base64
import json

import pytest

from doubleblind.authority.ledger import verify_ledger_export
from doubleblind.drill.drill import make_certificate, result
from doubleblind.local import build_local_stack
from doubleblind.zones.red.datasets import synthetic_suite

FAST = {"equalizer": {"enabled": True, "bucket_ms": 25}}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def stack(tmp_path):
    return build_local_stack(tmp_path, time_scale=0.02)


async def to_running(s, config=None, name="t"):
    op = s.operator_http
    tid = (await op.post("/v1/trials", json={"name": name, "config": config or FAST})).json()["id"]
    await s.red.commit(tid)
    st = await s.blue.commit(tid)
    assert st["state"] == "REGISTERED"
    await s.blue.upload(tid)
    r = await op.post(f"/v1/trials/{tid}/arm")
    assert r.status_code == 200, r.text
    assert (await op.post(f"/v1/trials/{tid}/start")).json()["state"] == "RUNNING"
    return tid


def test_full_trial_happy_path(stack):
    s = stack

    async def go():
        tid = await to_running(s)
        obs = await s.red.run(tid)
        # tenants are blinded while the trial is live
        assert (await s.red_http.get(f"/v1/trials/{tid}/report")).status_code == 403
        assert (await s.blue_http.get(f"/v1/trials/{tid}/report")).status_code == 403
        r = await s.operator_http.post(f"/v1/trials/{tid}/conclude")
        assert r.json()["state"] == "CONCLUDED", r.text
        await s.red.reveal(tid)
        final = await s.blue.reveal(tid)
        red_rep = await s.red.report(tid)
        blue_rep = await s.blue.report(tid)
        export = (await s.operator_http.get(f"/v1/trials/{tid}/export")).json()
        return tid, obs, final, red_rep, blue_rep, export

    tid, obs, final, red_rep, blue_rep, export = run(go())
    n = len(synthetic_suite())
    assert final["state"] == "ATTESTED"
    assert len(obs) == n

    # Equalizer: every refusal red saw is byte-identical in size; all sizes are buckets
    refused = [o for o in obs if o["status"] == "REFUSED"]
    assert refused and len({o["size"] for o in refused}) == 1
    assert {o["size"] for o in obs} <= {512, 1024, 2048, 4096, 8192}

    # outcomes span every layer, and one leak was contained at the boundary
    outcomes = red_rep["summary"]["outcomes"]
    assert outcomes.get("defended_guard") and outcomes.get("defended_model") and outcomes.get("control_ok")
    assert red_rep["summary"]["leaks_contained"] >= 1
    # post-reveal: blue may see red's texts; red may see which layer defended
    assert all("text" in c for c in blue_rep["cases"])
    assert all("text" not in c and "layer" in c for c in red_rep["cases"])

    # the ledger verifies and never contains plaintext case text
    rep = verify_ledger_export(export["ledger"])
    assert rep.ok, rep.problems
    blob = json.dumps(export["ledger"])
    for c in synthetic_suite():
        assert c["text"] not in blob
    types = [e["type"] for e in export["ledger"]["events"]]
    for t in ["CREATED", "REGISTERED", "BUNDLE_SEALED", "ARMED", "RUNNING", "CASE", "CONCLUDED", "REVEALED", "ATTESTED"]:
        assert t in types


def test_role_separation_and_state_policy(stack):
    s = stack

    async def go():
        op = s.operator_http
        tid = (await op.post("/v1/trials", json={"name": "p", "config": FAST})).json()["id"]
        # blue's listener has no case route at all; red's has no bundle route
        no_route = (await s.blue_http.post(f"/v1/trials/{tid}/cases", json={})).status_code
        no_bundle = (await s.red_http.post(f"/v1/trials/{tid}/bundle", json={})).status_code
        # cannot arm before registration
        early_arm = (await op.post(f"/v1/trials/{tid}/arm")).status_code
        await s.red.commit(tid)
        dup = (await s.red_http.post(f"/v1/trials/{tid}/commitment",
                                     json={"commitment": "0" * 64, "canary_fp": "0" * 64})).status_code
        await s.blue.commit(tid)
        late_commit = (await s.blue_http.post(f"/v1/trials/{tid}/commitment",
                                              json={"commitment": "1" * 64, "canary_fp": "1" * 64})).status_code
        unknown_cfg = (await op.post("/v1/trials", json={"name": "x", "config": {"evil": 1}})).status_code
        return no_route, no_bundle, early_arm, dup, late_commit, unknown_cfg

    no_route, no_bundle, early_arm, dup, late_commit, unknown_cfg = run(go())
    assert no_route in (404, 405) and no_bundle in (404, 405)
    assert early_arm == 403
    assert dup == 409
    assert late_commit == 403
    assert unknown_cfg == 422


def test_tokens_required_and_revoked_at_conclude(stack):
    s = stack

    async def go():
        tid = await to_running(s)
        tok = (await s.red_http.post(f"/v1/trials/{tid}/session")).json()["token"]
        body = {"case_id": "x1", "text": "hello", "expect": "comply"}
        bad = (await s.red_http.post(f"/v1/trials/{tid}/cases", json=body,
                                     headers={"Authorization": "Bearer nope.nope"})).status_code
        ok = (await s.red_http.post(f"/v1/trials/{tid}/cases", json=body,
                                    headers={"Authorization": f"Bearer {tok}"})).status_code
        await s.operator_http.post(f"/v1/trials/{tid}/conclude")
        after = (await s.red_http.post(f"/v1/trials/{tid}/cases", json=body,
                                       headers={"Authorization": f"Bearer {tok}"})).status_code
        return bad, ok, after

    assert run(go()) == (401, 200, 403)


def test_canary_drill_invalidates(stack):
    s = stack

    async def go():
        tid = await to_running(s)
        d = (await s.operator_http.post(f"/v1/trials/{tid}/drill/canary")).json()
        st = (await s.operator_http.get(f"/v1/trials/{tid}")).json()
        after = (await s.red_http.post(f"/v1/trials/{tid}/session")).status_code
        return d, st, after

    d, st, after = run(go())
    assert d["detected"] and st["state"] == "INVALIDATED"
    assert after == 403


def test_real_foreign_canary_from_red_invalidates(stack):
    """Simulate a genuine leak: red somehow obtained blue's bundle (with blue's
    canary inside) and sends it through the red listener."""
    s = stack

    async def go():
        tid = await to_running(s)
        blue_state = json.loads((s.workdir / "blue" / "state" / f"{tid}.json").read_text())
        leaked = base64.b64decode(blue_state["bundle_b64"]).decode()
        tok = (await s.red_http.post(f"/v1/trials/{tid}/session")).json()["token"]
        r = await s.red_http.post(f"/v1/trials/{tid}/cases", headers={"Authorization": f"Bearer {tok}"},
                                  json={"case_id": "leak", "text": leaked[:4000], "expect": "refuse"})
        st = (await s.operator_http.get(f"/v1/trials/{tid}")).json()
        return r.status_code, st

    code, st = run(go())
    assert code == 409 and st["state"] == "INVALIDATED"
    assert "canary" in st["invalid_reason"]


def test_purity_drift_invalidates(tmp_path):
    from doubleblind.zones.model.backends import StubBackend
    s = build_local_stack(tmp_path, backend=StubBackend(time_scale=0.02))

    async def go():
        tid = await to_running(s)
        s.backend.persistent_memory = True  # simulate state surviving across sessions
        await s.red.run(tid, limit=5)
        await s.operator_http.post(f"/v1/trials/{tid}/conclude")
        return (await s.operator_http.get(f"/v1/trials/{tid}")).json()

    st = run(go())
    assert st["state"] == "INVALIDATED" and "purity" in st["invalid_reason"]


def test_reveal_mismatch_invalidates(stack):
    s = stack

    async def go():
        tid = await to_running(s)
        await s.red.run(tid, limit=4)
        await s.operator_http.post(f"/v1/trials/{tid}/conclude")
        try:
            await s.red.reveal(tid, tamper=True)
        except Exception as exc:  # noqa: BLE001
            err = str(exc)
        return err, (await s.operator_http.get(f"/v1/trials/{tid}")).json()

    err, st = run(go())
    assert "422" in err and st["state"] == "INVALIDATED"


def test_cases_outside_committed_set_invalidate(stack):
    s = stack

    async def go():
        tid = await to_running(s)
        tok = (await s.red_http.post(f"/v1/trials/{tid}/session")).json()["token"]
        await s.red_http.post(f"/v1/trials/{tid}/cases", headers={"Authorization": f"Bearer {tok}"},
                              json={"case_id": "adapted", "text": "a case red invented mid-trial", "expect": "refuse"})
        await s.operator_http.post(f"/v1/trials/{tid}/conclude")
        try:
            await s.red.reveal(tid)
        except Exception as exc:  # noqa: BLE001
            return str(exc), (await s.operator_http.get(f"/v1/trials/{tid}")).json()
        return "", (await s.operator_http.get(f"/v1/trials/{tid}")).json()

    err, st = run(go())
    assert "membership_ok" in err and st["state"] == "INVALIDATED"


class FailingDrill:
    async def certificate(self):
        return make_certificate("docker", [
            result("red", "net.deny.arbiter-blue", "network", "fail", "connected"),
            result("red", "net.allow.arbiter-red", "network", "pass", "connected", positive=True),
        ])


def test_failed_breach_drill_blocks_arming(tmp_path):
    s = build_local_stack(tmp_path, time_scale=0.02, drill=FailingDrill())

    async def go():
        op = s.operator_http
        tid = (await op.post("/v1/trials", json={"name": "d", "config": FAST})).json()["id"]
        await s.red.commit(tid)
        await s.blue.commit(tid)
        await s.blue.upload(tid)
        r = await op.post(f"/v1/trials/{tid}/arm")
        return r.status_code, (await op.get(f"/v1/trials/{tid}")).json()

    code, st = run(go())
    assert code == 409 and st["state"] == "INVALIDATED" and "breach drill" in st["invalid_reason"]


def test_accepted_risk_is_recorded_in_ledger(tmp_path):
    s = build_local_stack(tmp_path, time_scale=0.02, drill=FailingDrill())

    async def go():
        cfg = {**FAST, "accepted_risks": ["net.deny.arbiter-blue"]}
        tid = await to_running(s, config=cfg)
        evs = (await s.operator_http.get("/v1/ledger")).json()["events"]
        return [json.loads(e["body_json"]) for e in evs if e["type"] == "ARMED"][0]

    armed = run(go())
    assert armed["accepted_risks"] == ["net.deny.arbiter-blue"]


def test_require_isolation_rejects_local_sim(stack):
    s = stack

    async def go():
        op = s.operator_http
        tid = (await op.post("/v1/trials", json={"name": "strict", "config": {**FAST, "require_isolation": True}})).json()["id"]
        await s.red.commit(tid)
        await s.blue.commit(tid)
        await s.blue.upload(tid)
        return (await op.post(f"/v1/trials/{tid}/arm")).status_code

    assert run(go()) == 409
