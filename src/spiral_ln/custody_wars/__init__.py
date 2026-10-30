"""Custody Wars: a sealed, synthetic multi-seat crypto-security game for AI agents.

Six seats (CUSTODIAN, HIVE, SENTINEL, REGULATOR, BROKER, BRIDGE) play a
five-phase turn (negotiation, allocation, action declaration, simultaneous
resolution, turn end) over a board of custody infrastructure and NPC staff.
Agents plug in as in-process heuristics, outbound webhooks, pull-mode HTTP
clients (e.g. Codex agents), or local ``codex exec`` calls. A sealed referee
labels every executed action with the RTG-0 mandate oracle.

Nothing here touches a real network asset, wallet, key, or person.
"""

from .content import SCHEMA_VERSION, SEATS
from .engine import Engine
from .session import AwaitingDecisions, Session
from .world import build_world, list_scenarios

__all__ = ["SCHEMA_VERSION", "SEATS", "Engine", "Session", "AwaitingDecisions", "build_world", "list_scenarios"]
