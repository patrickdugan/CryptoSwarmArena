"""Deterministic, hash-chained event log — the single source of truth.

State is a fold over events; every artifact is reproducible from the log plus the
scenario.  Canonicalization sorts keys so the chain is stable across processes and
hash seeds (the repository's audit recorded a replay failure from sorting before
normalizing, so determinism here is a tested property, not an aspiration).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def canon(obj: Any) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def seed_int(*parts: object) -> int:
    raw = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).digest()
    return int.from_bytes(raw[:8], "big")


@dataclass(frozen=True)
class Event:
    """One recorded step.  Carries no payload, message, or free-text content."""

    seq: int
    tick: int
    actor: str
    kind: str
    data: dict[str, Any]
    gateway: str  # "allow" | "deny" | "n/a"
    verdict: str  # oracle verdict, or "n/a"

    def canon(self) -> str:
        return canon(
            {
                "seq": self.seq,
                "tick": self.tick,
                "actor": self.actor,
                "kind": self.kind,
                "data": self.data,
                "gateway": self.gateway,
                "verdict": self.verdict,
            }
        )


class EventLog:
    """An append-only log whose head is a hash chain over every event."""

    GENESIS = "genesis"

    def __init__(self) -> None:
        self.events: list[Event] = []
        self.hashes: list[str] = []
        self._head = self.GENESIS

    def append(self, event: Event) -> str:
        h = digest(self._head, event.canon())
        self.events.append(event)
        self.hashes.append(h)
        self._head = h
        return h

    @property
    def head(self) -> str:
        return self._head

    def verdicts(self) -> list[str]:
        return [event.verdict for event in self.events]

    def by_kind(self, kind: str) -> list[Event]:
        return [event for event in self.events if event.kind == kind]

    def __len__(self) -> int:
        return len(self.events)
