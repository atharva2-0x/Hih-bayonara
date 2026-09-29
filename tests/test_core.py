import time

import pytest

from doubleblind.authority.keybroker import KeyBroker
from doubleblind.authority.ledger import Ledger, verify_ledger_export
from doubleblind.authority.policy import PolicyDenied, PolicyEngine
from doubleblind.authority.trial import IllegalTransition, State, Trial, is_legal_path
from doubleblind.common.crypto import (
    Signer,
    TokenError,
    commitment,
    new_key,
    random_hex,
    salted_hash,
    seal,
    tagged_hash,
    unseal,
    verify_commitment,
    verify_signature,
)
from doubleblind.common.merkle import inclusion_proof, merkle_root, verify_inclusion

# ---------------------------------------------------------------- crypto


def test_tagged_hash_is_domain_separated_and_unambiguous():
    assert tagged_hash("a", b"bc") != tagged_hash("ab", b"c")
    assert tagged_hash("t", b"ab", b"c") != tagged_hash("t", b"a", b"bc")


def test_commitment_binds_artifact_and_nonce():
    nonce = random_hex(32)
    c = commitment(b"payload-set", nonce)
    assert verify_commitment(c, b"payload-set", nonce)
    assert not verify_commitment(c, b"payload-set!", nonce)
    assert not verify_commitment(c, b"payload-set", random_hex(32))
    assert not verify_commitment(c, b"payload-set", "not-hex")


def test_salted_hash_depends_on_salt():
    s1, s2 = random_hex(32), random_hex(32)
    assert salted_hash(s1, "x") != salted_hash(s2, "x")


def test_envelope_roundtrip_and_tamper():
    k = new_key()
    tok = seal(k, b"secret", b"aad")
    assert unseal(k, tok, b"aad") == b"secret"
    with pytest.raises(ValueError):
        unseal(k, tok, b"other-aad")


def test_signatures():
    s = Signer.generate()
    sig = s.sign(b"msg")
    assert verify_signature(s.public_key_hex, b"msg", sig)
    assert not verify_signature(s.public_key_hex, b"msg2", sig)


def test_tokens_scope_expiry_revocation():
    kb = KeyBroker.ephemeral()
    t = kb.issue("t-1", "red", ["case:submit"], ttl_s=60)
    assert kb.check(t, "t-1", "red", "case:submit")["sub"] == "red"
    with pytest.raises(TokenError):
        kb.check(t, "t-1", "blue", "case:submit")
    with pytest.raises(TokenError):
        kb.check(t, "t-2", "red", "case:submit")
    with pytest.raises(TokenError):
        kb.check(t, "t-1", "red", "report:read")
    body, mac = t.split(".")
    with pytest.raises(TokenError):
        kb.check(body + "." + mac[:-2] + "AA", "t-1", "red", "case:submit")
    expired = kb.issue("t-1", "red", ["case:submit"], ttl_s=-1)
    with pytest.raises(TokenError):
        kb.check(expired, "t-1", "red", "case:submit")
    kb.revoke_trial("t-1")
    with pytest.raises(TokenError):
        kb.check(t, "t-1", "red", "case:submit")


def test_dek_wrapping():
    kb = KeyBroker.ephemeral()
    dek, wrapped = kb.new_dek()
    assert kb.unwrap(wrapped) == dek


# ---------------------------------------------------------------- merkle


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13])
def test_merkle_inclusion_proofs(n):
    leaves = [tagged_hash("leaf", str(i)) for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        assert verify_inclusion(leaves[i], inclusion_proof(leaves, i), root)
    assert not verify_inclusion(tagged_hash("leaf", "x"), inclusion_proof(leaves, 0), root)


# ---------------------------------------------------------------- ledger


def _ledger(tmp_path):
    return Ledger(tmp_path / "ledger.db", Signer.generate())


def test_ledger_chain_and_checkpoint_verify(tmp_path):
    led = _ledger(tmp_path)
    for i in range(7):
        led.append("t-1", "CASE", {"i": i})
    led.checkpoint("test")
    led.append("t-1", "CONCLUDED", {})
    rep = verify_ledger_export(led.export(), pinned_public_key=led.signer.public_key_hex)
    assert rep.ok, rep.problems
    assert rep.events == 8 and rep.checkpoints == 1


def test_ledger_detects_modified_event(tmp_path):
    led = _ledger(tmp_path)
    for i in range(5):
        led.append("t-1", "CASE", {"i": i})
    led.checkpoint()
    exp = led.export()
    exp["events"][2]["body_json"] = exp["events"][2]["body_json"].replace('"i":2', '"i":9')
    rep = verify_ledger_export(exp)
    assert not rep.ok and rep.first_bad_seq == 3


def test_ledger_detects_truncation_against_checkpoint(tmp_path):
    led = _ledger(tmp_path)
    for i in range(5):
        led.append("t-1", "CASE", {"i": i})
    led.checkpoint()
    exp = led.export()
    exp["events"] = exp["events"][:3]
    assert not verify_ledger_export(exp).ok


def test_ledger_detects_forged_checkpoint_signature(tmp_path):
    led = _ledger(tmp_path)
    led.append("t-1", "X", {})
    led.checkpoint()
    exp = led.export()
    other = Signer.generate()
    exp["checkpoints"][0]["signature"] = other.sign(b"whatever")
    assert not verify_ledger_export(exp).ok


def test_ledger_rejects_wrong_pinned_key(tmp_path):
    led = _ledger(tmp_path)
    led.append("t-1", "X", {})
    assert not verify_ledger_export(led.export(), pinned_public_key=Signer.generate().public_key_hex).ok


# ---------------------------------------------------------------- trial FSM


def test_trial_happy_path_and_illegal_transitions():
    t = Trial(name="x", config={})
    for s in [State.REGISTERED, State.ARMED, State.RUNNING, State.CONCLUDED, State.REVEALED, State.ATTESTED]:
        t.transition(s)
    with pytest.raises(IllegalTransition):
        t.transition(State.INVALIDATED)
    t2 = Trial(name="y", config={})
    with pytest.raises(IllegalTransition):
        t2.transition(State.RUNNING)
    assert is_legal_path(["REGISTERED", "ARMED", "INVALIDATED"])
    assert not is_legal_path(["ARMED"])


# ---------------------------------------------------------------- policy


def test_policy_invariants_hold_exhaustively():
    pe = PolicyEngine.load()
    results = pe.check_invariants()
    assert results and all(r["ok"] for r in results), [r for r in results if not r["ok"]]
    assert sum(r["checked"] for r in results) > 100


def test_policy_blinding_examples():
    pe = PolicyEngine.load()
    assert not pe.decide("blue", "red_cases:read", "RUNNING").allowed
    assert pe.decide("blue", "red_cases:read", "REVEALED").allowed
    assert pe.decide("red", "case:submit", "RUNNING").allowed
    assert not pe.decide("red", "case:submit", "CONCLUDED").allowed
    with pytest.raises(PolicyDenied) as ei:
        pe.require("red", "blue_bundle:read", "RUNNING")
    assert ei.value.rule == "D02"


def test_policy_edit_that_breaks_blinding_is_caught():
    pe = PolicyEngine.load()
    bad = dict(pe.policy)
    bad["rules"] = [r for r in pe.policy["rules"] if r["id"] != "D01"] + [
        {"id": "BAD", "effect": "allow", "roles": ["blue"], "actions": ["red_cases:read"], "states": ["RUNNING"]}
    ]
    results = PolicyEngine(bad).check_invariants()
    broken = [r for r in results if not r["ok"]]
    assert broken and broken[0]["id"] == "I1"


def test_policy_hash_changes_with_policy():
    pe = PolicyEngine.load()
    bad = dict(pe.policy, version="tampered")
    assert PolicyEngine(bad).hash != pe.hash
