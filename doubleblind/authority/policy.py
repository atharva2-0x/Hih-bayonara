"""Attribute-based access control: role x action x trial-state.

The decision space is finite (roles x actions x states), so instead of
spot-testing a few cases we *exhaustively* check every invariant declared in
the policy file. ``python -m doubleblind policy`` prints the result; the check
also runs in the test suite, so a policy edit that breaks blinding fails CI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common.crypto import canonical_json, sha256_hex
from .trial import State

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.json")
ALL_STATES = [s.value for s in State]
NO_TRIAL = "NONE"  # pseudo-state for actions not bound to an existing trial


class PolicyDenied(Exception):
    def __init__(self, role: str, action: str, state: str, rule: str | None):
        self.role, self.action, self.state, self.rule = role, action, state, rule
        super().__init__(f"{role} may not {action} while {state} (rule {rule or 'default-deny'})")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str | None


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]):
        self.policy = policy
        self.hash = sha256_hex(canonical_json(policy))
        self._validate()

    @classmethod
    def load(cls, path: str | Path = DEFAULT_POLICY_PATH) -> "PolicyEngine":
        return cls(json.loads(Path(path).read_text()))

    def _states(self, spec: Any) -> list[str]:
        return ALL_STATES + [NO_TRIAL] if spec == "*" else list(spec)

    def _validate(self) -> None:
        roles, actions = set(self.policy["roles"]), set(self.policy["actions"])
        for r in self.policy["rules"] + self.policy.get("invariants", []):
            unknown = (set(r["roles"]) - roles) | (set(r["actions"]) - actions)
            unknown |= set(self._states(r["states"])) - set(ALL_STATES + [NO_TRIAL])
            if unknown:
                raise ValueError(f"policy entry {r['id']} references unknown names: {sorted(unknown)}")

    def decide(self, role: str, action: str, state: str) -> Decision:
        allow_rule = None
        for rule in self.policy["rules"]:
            if role in rule["roles"] and action in rule["actions"] and state in self._states(rule["states"]):
                if rule["effect"] == "deny":
                    return Decision(False, rule["id"])  # deny overrides
                allow_rule = allow_rule or rule["id"]
        if allow_rule:
            return Decision(True, allow_rule)
        return Decision(False, None)

    def require(self, role: str, action: str, state: str) -> str:
        d = self.decide(role, action, state)
        if not d.allowed:
            raise PolicyDenied(role, action, state, d.rule)
        return d.rule or ""

    def check_invariants(self) -> list[dict[str, Any]]:
        """Exhaustively evaluate every invariant over its whole (role, action, state) space."""
        results = []
        for inv in self.policy.get("invariants", []):
            violations = []
            checked = 0
            for role in inv["roles"]:
                for action in inv["actions"]:
                    for state in self._states(inv["states"]):
                        checked += 1
                        got = "allow" if self.decide(role, action, state).allowed else "deny"
                        if got != inv["must_be"]:
                            violations.append({"role": role, "action": action, "state": state, "got": got})
            results.append({"id": inv["id"], "text": inv["text"], "checked": checked,
                            "violations": violations, "ok": not violations})
        return results

    def matrix(self, role: str) -> dict[str, dict[str, bool]]:
        return {a: {s: self.decide(role, a, s).allowed for s in ALL_STATES} for a in self.policy["actions"]}
