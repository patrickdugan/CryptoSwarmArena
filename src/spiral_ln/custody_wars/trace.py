"""Hash-chained session trace with visibility-scoped reads.

Every engine and session event is appended with ``hash = sha256(prev || canon(event))``.
The full chain (including the sealed ``referee`` channel and private diaries) is
the referee's record; seats only ever read the subset whose ``visible_to``
names them or ``ALL``.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Iterable

GENESIS = "0" * 64
TRACE_CHANNELS = ("session", "public_speech", "private_speech", "private_diary", "formal_pact", "order",
                  "engine_resolution", "pact_enforcement", "alert", "referee")
SEALED_CHANNELS = frozenset({"referee"})


def canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


class Trace:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.head = GENESIS
        self._lock = threading.Lock()   # webhook/codex seats log from worker threads

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if event.get("channel") not in TRACE_CHANNELS:
            raise ValueError(f"unknown trace channel {event.get('channel')}")
        with self._lock:
            body = {"seq": len(self.entries), "prev": self.head, "event": event}
            body["hash"] = hashlib.sha256((self.head + canon(event)).encode()).hexdigest()
            self.entries.append(body)
            self.head = body["hash"]
        return body

    def extend(self, events: Iterable[dict[str, Any]]) -> None:
        for e in events:
            self.append(e)

    def verify(self, entries: list[dict[str, Any]] | None = None, expected_head: str | None = None) -> bool:
        head = GENESIS
        for i, body in enumerate(self.entries if entries is None else entries):
            if body.get("seq") != i or body.get("prev") != head:
                return False
            if body.get("hash") != hashlib.sha256((head + canon(body.get("event"))).encode()).hexdigest():
                return False
            head = body["hash"]
        return head == (self.head if expected_head is None else expected_head)

    @staticmethod
    def visible(event: dict[str, Any], seat: str) -> bool:
        if event["channel"] in SEALED_CHANNELS:
            return False
        vis = event.get("visible_to", "ALL")
        return vis == "ALL" or (isinstance(vis, list) and seat in vis)

    def for_seat(self, seat: str, since_turn: int = 0, limit: int = 60) -> list[dict[str, Any]]:
        out = [b["event"] for b in self.entries
               if b["event"].get("turn", 0) >= since_turn and self.visible(b["event"], seat)]
        return out[-limit:]

    def public(self) -> list[dict[str, Any]]:
        return [b["event"] for b in self.entries if self.visible(b["event"], "__public__") ]

    def write_jsonl(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for body in self.entries:
                fh.write(canon(body) + "\n")
