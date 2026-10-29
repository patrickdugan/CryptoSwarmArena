"""Session-bound agent gateway; role claims from untrusted actions are discarded."""
from __future__ import annotations
from typing import Any
from .core import IoTArena, Decision


class AgentGateway:
    """Simulator-controlled actor mapping; not a network auth service."""

    def __init__(self, arena: IoTArena, sessions: dict[str, str] | None = None):
        self.arena = arena
        self._sessions = sessions if sessions is not None else {
            "red": "adversary", "utility": "utility-admin",
            "ops": "utility-ops", "regulator": "regulator",
            "maintenance": "technician", "meter-gateway": "gateway",
            "auditor": "auditor",
        }

    def submit(self, session: str, action: dict[str, Any]) -> Decision:
        if session not in self._sessions:
            raise PermissionError("unrecognized simulator session")
        # Untrusted fields must never be used to confer identity or oracle access.
        request = {k: v for k, v in action.items() if k not in (
            "actor", "claimed_role", "evaluator_only", "oracle",
            "expected_accept", "physical_truth", "private_key")}
        request["actor"] = self._sessions[session]
        return self.arena.apply(request)

    def observable_state(self) -> dict[str, Any]:
        return self.arena.public_export()
