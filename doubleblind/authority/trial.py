"""Trial state machine (see ARCHITECTURE.md §3)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..common.crypto import random_hex


class State(str, Enum):
    DRAFT = "DRAFT"
    REGISTERED = "REGISTERED"
    ARMED = "ARMED"
    RUNNING = "RUNNING"
    CONCLUDED = "CONCLUDED"
    REVEALED = "REVEALED"
    ATTESTED = "ATTESTED"
    INVALIDATED = "INVALIDATED"


TRANSITIONS: dict[State, set[State]] = {
    State.DRAFT: {State.REGISTERED, State.INVALIDATED},
    State.REGISTERED: {State.ARMED, State.INVALIDATED},
    State.ARMED: {State.RUNNING, State.INVALIDATED},
    State.RUNNING: {State.CONCLUDED, State.INVALIDATED},
    State.CONCLUDED: {State.REVEALED, State.INVALIDATED},
    State.REVEALED: {State.ATTESTED, State.INVALIDATED},
    State.ATTESTED: set(),
    State.INVALIDATED: set(),
}

PRE_REVEAL = [State.DRAFT, State.REGISTERED, State.ARMED, State.RUNNING, State.CONCLUDED]
TERMINAL = {State.ATTESTED, State.INVALIDATED}


class IllegalTransition(Exception):
    pass


def is_legal_path(states: list[str]) -> bool:
    """True if a sequence of state names is a legal walk from DRAFT."""
    cur = State.DRAFT
    for s in states:
        nxt = State(s)
        if nxt not in TRANSITIONS[cur]:
            return False
        cur = nxt
    return True


@dataclass
class Trial:
    name: str
    config: dict[str, Any]
    id: str = field(default_factory=lambda: "t-" + random_hex(6))
    state: State = State.DRAFT
    created_at: float = field(default_factory=time.time)
    history: list[dict[str, Any]] = field(default_factory=list)

    # pre-registration
    commitments: dict[str, dict[str, Any]] = field(default_factory=dict)
    # sealed per-trial secrets (never leave the Authority before REVEAL)
    salt_hex: str = field(default_factory=lambda: random_hex(32))
    dek_wrapped: str = ""
    # arming artefacts
    model_digest: str | None = None
    policy_hash: str | None = None
    bundle_sealed: str | None = None
    bundle_sha256: str | None = None
    cert: dict[str, Any] | None = None
    cert_hash: str | None = None
    f_pre: str | None = None
    f_post: str | None = None
    # run
    case_count: int = 0
    case_commits: list[str] = field(default_factory=list)
    sealed_records: list[str] = field(default_factory=list)
    leaks_contained: int = 0
    # reveal
    reveals: dict[str, dict[str, Any]] = field(default_factory=dict)
    invalid_reason: str | None = None
    checkpoint: dict[str, Any] | None = None

    def transition(self, to: State, reason: str = "") -> None:
        if to not in TRANSITIONS[self.state]:
            raise IllegalTransition(f"{self.id}: {self.state.value} -> {to.value} is not allowed")
        self.history.append({"from": self.state.value, "to": to.value, "ts": time.time(), "reason": reason})
        self.state = to

    def public_view(self) -> dict[str, Any]:
        """What any role may see about a trial at any time (no secrets)."""
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state.value,
            "created_at": self.created_at,
            "committed": sorted(self.commitments),
            "case_count": self.case_count,
            "invalid_reason": self.invalid_reason,
        }
