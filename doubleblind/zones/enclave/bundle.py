"""Blue defense bundles: declarative, validated, sealed.

A bundle is *data, not code*: a defense system prompt plus input/output rules
of a few fixed types. That keeps the enclave sealed by construction. A bundle
cannot open sockets, write files or print debug output, so it has no way to
send what it sees back to blue. Reason codes must come from a list declared
in the (committed) bundle and match a strict pattern, so they cannot be used
as a covert channel either.

Bundle format ``doubleblind-bundle/v1``::

    {
      "format": "doubleblind-bundle/v1",
      "name": "baseline-guard", "version": "1.0.0",
      "system_prompt": "...",            # may contain blue's canary
      "block_message": "...",            # what a naive platform would show
      "reason_codes": ["R_TOPIC", ...],
      "input_rules":  [{"id": ..., "type": "contains_any|regex|max_chars", ..., "reason": "R_..."}],
      "output_rules": [ ...same... ]
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ...common.crypto import sha256_hex

FORMAT = "doubleblind-bundle/v1"
MAX_BUNDLE_BYTES = 64 * 1024
MAX_RULES = 64
MAX_TERMS = 200
MAX_PATTERN = 200
REASON_RE = re.compile(r"^R_[A-Z0-9_]{1,24}$")
# Crude guard against catastrophic backtracking: a quantified group that is itself quantified.
NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*{]")


class BundleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    type: str
    reason: str
    terms: tuple[str, ...] = ()
    pattern: re.Pattern | None = None
    value: int = 0

    def matches(self, text: str) -> bool:
        if self.type == "contains_any":
            low = text.lower()
            return any(t in low for t in self.terms)
        if self.type == "regex":
            assert self.pattern is not None
            return self.pattern.search(text) is not None
        if self.type == "max_chars":
            return len(text) > self.value
        return False


def _compile_rule(raw: dict, declared: set[str]) -> Rule:
    rid, rtype, reason = str(raw.get("id", ""))[:32], raw.get("type"), raw.get("reason", "")
    if not REASON_RE.match(reason) or reason not in declared:
        raise BundleError(f"rule {rid}: reason code {reason!r} is not declared or malformed")
    if rtype == "contains_any":
        terms = raw.get("terms", [])
        if not terms or len(terms) > MAX_TERMS or any(not isinstance(t, str) or not t or len(t) > 200 for t in terms):
            raise BundleError(f"rule {rid}: invalid terms")
        return Rule(rid, rtype, reason, terms=tuple(t.lower() for t in terms))
    if rtype == "regex":
        pat = raw.get("pattern", "")
        if not isinstance(pat, str) or not pat or len(pat) > MAX_PATTERN:
            raise BundleError(f"rule {rid}: pattern missing or too long")
        if NESTED_QUANTIFIER_RE.search(pat):
            raise BundleError(f"rule {rid}: nested quantifiers are not allowed (ReDoS guard)")
        try:
            return Rule(rid, rtype, reason, pattern=re.compile(pat))
        except re.error as exc:
            raise BundleError(f"rule {rid}: {exc}") from exc
    if rtype == "max_chars":
        v = raw.get("value")
        if not isinstance(v, int) or not 1 <= v <= 1_000_000:
            raise BundleError(f"rule {rid}: invalid value")
        return Rule(rid, rtype, reason, value=v)
    raise BundleError(f"rule {rid}: unknown rule type {rtype!r}")


@dataclass(frozen=True)
class Bundle:
    name: str
    version: str
    system_prompt: str
    block_message: str
    reason_codes: tuple[str, ...]
    input_rules: tuple[Rule, ...]
    output_rules: tuple[Rule, ...]
    sha256: str

    @classmethod
    def parse(cls, raw: bytes) -> "Bundle":
        if len(raw) > MAX_BUNDLE_BYTES:
            raise BundleError("bundle too large")
        try:
            d = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BundleError("bundle is not valid JSON") from exc
        if d.get("format") != FORMAT:
            raise BundleError(f"unsupported bundle format {d.get('format')!r}")
        codes = d.get("reason_codes", [])
        if not isinstance(codes, list) or len(codes) > 32 or any(not REASON_RE.match(str(c)) for c in codes):
            raise BundleError("reason_codes must be a list of R_[A-Z0-9_] codes")
        declared = set(codes)
        rules_in = d.get("input_rules", [])
        rules_out = d.get("output_rules", [])
        if len(rules_in) + len(rules_out) > MAX_RULES:
            raise BundleError("too many rules")
        sp = d.get("system_prompt", "")
        bm = d.get("block_message", "Request blocked.")
        if not isinstance(sp, str) or len(sp) > 4000 or not isinstance(bm, str) or len(bm) > 500:
            raise BundleError("system_prompt/block_message invalid")
        return cls(
            name=str(d.get("name", "unnamed"))[:64],
            version=str(d.get("version", "0"))[:32],
            system_prompt=sp,
            block_message=bm,
            reason_codes=tuple(codes),
            input_rules=tuple(_compile_rule(r, declared) for r in rules_in),
            output_rules=tuple(_compile_rule(r, declared) for r in rules_out),
            sha256=sha256_hex(raw),
        )

    @staticmethod
    def _run(rules: tuple[Rule, ...], text: str) -> tuple[bool, str | None]:
        for rule in rules:
            if rule.matches(text):
                return False, rule.reason
        return True, None

    def input_guard(self, text: str) -> tuple[bool, str | None]:
        return self._run(self.input_rules, text)

    def output_guard(self, text: str) -> tuple[bool, str | None]:
        return self._run(self.output_rules, text)
