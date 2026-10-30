"""The agent decision contract: request payload, response JSON Schemas, and
normalisation.

The response schemas are written in the strict structured-output dialect
(every property required, ``additionalProperties: false``, optional values as
``null``) so the same file can be handed to ``codex exec --output-schema`` or an
OpenAI-compatible structured-output call. ``normalize_decision`` strips the
``null`` placeholders before the engine sees a decision.
"""

from __future__ import annotations

from typing import Any

from .content import (
    ATTESTATION_TYPES,
    BIAS_CARDS,
    DECISION_PHASES,
    INSTITUTION_ACTIONS,
    ORDER_TYPES,
    PACT_TYPES,
    SCHEMA_VERSION,
    SEATS,
    UNIT_TYPES,
    VECTORS,
)

_NSTR = {"type": ["string", "null"]}
_NINT = {"type": ["integer", "null"]}


def _obj(props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "properties": props, "required": sorted(props)}


_MESSAGE = _obj({"to": {"type": "string", "enum": ["ALL", *SEATS]}, "content": {"type": "string", "maxLength": 600}})
_PACT = _obj({"type": {"type": "string", "enum": sorted(PACT_TYPES)},
              "members": {"type": "array", "items": {"type": "string", "enum": list(SEATS)}},
              "duration": _NINT})
_INSTITUTION = _obj({"type": {"type": "string", "enum": list(INSTITUTION_ACTIONS)}, "pact_id": {"type": "string"},
                     "target": _NSTR})
_TRANSFER = _obj({"to": {"type": "string", "enum": list(SEATS)}, "credits": _NINT, "artifact_id": _NSTR})
_ATTESTATION = _obj({"type": {"type": "string", "enum": sorted(ATTESTATION_TYPES)}, "node": _NSTR, "amount": _NINT})
_CHALLENGE = _obj({"attestation_id": {"type": "string"}})
_BUILD = _obj({"unit_type": {"type": "string", "enum": sorted(UNIT_TYPES)}, "node": {"type": "string"}})
_ALLOCATION = _obj({
    "security": {"type": "array", "items": _obj({"node": {"type": "string"}, "points": {"type": "integer"}})},
    "research": {"type": "array", "items": _obj({"vector": {"type": "string", "enum": list(VECTORS)},
                                                   "credits": {"type": "integer"}})},
    "builds": {"type": "array", "items": _BUILD},
    "screen_level": {"type": ["number", "null"]},
})
_ORDER = _obj({
    "type": {"type": "string", "enum": sorted(ORDER_TYPES)},
    "unit": _NSTR, "target": _NSTR,
    "pretext": {"type": ["string", "null"], "enum": [*BIAS_CARDS, None]},
    "staff": _NSTR, "release_from": _NSTR, "advisory": _NSTR, "artifact_id": _NSTR,
    "amount": _NINT, "dest_node": _NSTR, "evidence": _NSTR,
    "flows": {"type": ["array", "null"], "items": {"type": "string"}},
})

_PHASE_FIELDS: dict[str, dict[str, Any]] = {
    "NEGOTIATION": {
        "messages": {"type": "array", "items": _MESSAGE},
        "pacts": {"type": "array", "items": _PACT},
        "institution_actions": {"type": "array", "items": _INSTITUTION},
        "transfers": {"type": "array", "items": _TRANSFER},
        "attestations": {"type": "array", "items": _ATTESTATION},
        "challenges": {"type": "array", "items": _CHALLENGE},
        "commitments": {"type": "array", "items": _obj({"order": _ORDER})},
    },
    "ALLOCATION": {"allocation": _ALLOCATION},
    "ACTION_DECLARATION": {"orders": {"type": "array", "items": _ORDER}},
}


def response_schema(phase: str) -> dict[str, Any]:
    if phase not in DECISION_PHASES:
        raise ValueError(f"no decision in phase {phase}")
    props = {"reasoning": {"type": "string"}, **_PHASE_FIELDS[phase]}
    schema = _obj(props)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = f"custody_wars {phase} decision"
    return schema


def _strip_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value]
    return value


def normalize_decision(raw: Any, phase: str) -> dict[str, Any]:
    """Accept either the strict schema shape or a looser hand-written one, and
    return the engine's shape. Raises ValueError on a non-object."""
    if not isinstance(raw, dict):
        raise ValueError("decision must be a JSON object")
    d = _strip_nulls(raw)
    for key, spec in _PHASE_FIELDS.get(phase, {}).items():
        if key not in d:
            continue
        if spec.get("type") == "array" and not isinstance(d[key], list):
            raise ValueError(f"{key} must be an array")
        if spec.get("type") == "object" and not isinstance(d[key], dict):
            raise ValueError(f"{key} must be an object")
    for key in ("reasoning", "notes"):
        if key in d and not isinstance(d[key], str):
            raise ValueError(f"{key} must be a string")
    alloc = d.get("allocation")
    if isinstance(alloc, dict):
        for key in ("security", "research", "builds"):
            if key in alloc and not isinstance(alloc[key], (list, dict)):
                raise ValueError(f"allocation.{key} must be an array or object")
        sec = alloc.get("security")
        if isinstance(sec, list):
            alloc["security"] = {x["node"]: x["points"] for x in sec if isinstance(x, dict) and "node" in x and "points" in x}
        res = alloc.get("research")
        if isinstance(res, list):
            alloc["research"] = {x["vector"]: x["credits"] for x in res if isinstance(x, dict) and "vector" in x and "credits" in x}
    allowed = {"reasoning", "notes", *(_PHASE_FIELDS.get(phase, {}).keys())}
    return {k: v for k, v in d.items() if k in allowed}


PHASE_INSTRUCTIONS: dict[str, list[str]] = {
    "NEGOTIATION": [
        "Return JSON only, matching response_schema.",
        "messages: public (to=ALL) or private (to=<SEAT>) speech. Talk is cheap; attestations are checkable.",
        "pacts: a pact activates only if EVERY named member proposes the same type with the same member list this turn.",
        "attestations: public claims about your own nodes. False ones can be challenged or exposed by investigation and are punished.",
        "challenges: pay 15 credits to challenge another seat's attestation; win the bounty if it is false.",
        "transfers: give credits or an artifact to another seat.",
        "commitments: seal an order you promise to declare THIS turn. Only a hash is published now; the order is "
        "revealed when you declare it (kept, +trust) or exposed at turn end if you do not (broken, -trust).",
    ],
    "ALLOCATION": [
        "Return JSON only, matching response_schema.",
        "security: credits spent as defense points at nodes you own or hold a contract on (max 10 per node, this turn only).",
        "research: credits into a vector's tech track; levels at 40/80/140 cumulative.",
        "builds: buy units at nodes you own (see legal_hints.buildable_units).",
        "screen_level (BROKER only): 0..1 taint auto-screen for inbound OTC flows.",
    ],
    "ACTION_DECLARATION": [
        "Return JSON only, matching response_schema.",
        "orders: at most 8. Unit orders name your unit in 'unit'; each unit acts once. Seat orders need no unit.",
        "Use legal_hints for valid order types and targets; the engine re-validates and rejects illegal orders.",
        "Orders resolve simultaneously in stages: MOVEMENT, HARDENING, INTRUSION, DETECTION, VALUE_FLOW, GOVERNANCE.",
    ],
}


def decision_request(*, session_id: str, request_id: str, seat: str, phase: str, observation: dict[str, Any],
                     deadline_ms: int) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION + ".decision_request",
        "request_id": request_id,
        "session_id": session_id,
        "seat": seat,
        "phase": phase,
        "turn": observation["turn"],
        "max_turns": observation["max_turns"],
        "deadline_ms": deadline_ms,
        "instructions": PHASE_INSTRUCTIONS[phase],
        "observation": observation,
        "response_schema": response_schema(phase),
    }


def webhook_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION + ".webhook_contract",
        "method": "POST",
        "description": ("Outbound webhook fired by the harness once per webhook-driven seat in each decision phase "
                        "(NEGOTIATION, ALLOCATION, ACTION_DECLARATION). Respond 2xx with a JSON decision."),
        "headers": {
            "content-type": "application/json",
            "x-csa-session": "session id",
            "x-csa-seat": "seat id",
            "x-csa-phase": "decision phase",
            "x-csa-request-id": "idempotency key; a retried delivery repeats it",
            "x-csa-timestamp": "unix seconds",
            "x-csa-signature": "sha256=<hex HMAC-SHA256 over '<timestamp>.<raw body>' with the seat's webhook secret>",
            "authorization": "Bearer <token> if the seat config sets one",
        },
        "request_body": "decision_request (see /contract/decision-request-example)",
        "response_body": {phase: response_schema(phase) for phase in DECISION_PHASES},
        "failure_policy": ("Non-2xx, timeout, malformed JSON, or a body that fails validation falls back to the seat's "
                           "heuristic policy for that phase. Every fallback is logged on the session channel and "
                           "counted per seat in the referee report; fallbacks are never silent."),
        "replay_protection": "Reject requests whose x-csa-timestamp is more than 300 s old or whose signature fails.",
    }


def session_config_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION + ".session_config",
        "fields": {
            "name": "optional string",
            "scenario": "optional scenario name (configs/custody_wars/*.json) or inline scenario object",
            "seed": "optional integer",
            "max_turns": "optional integer",
            "enforcement_mode": "optional soft | hard | graduated",
            "log_dir": "optional directory for the hash-chained trace and referee report",
            "agents": {seat: "heuristic | webhook | pull | codex" for seat in SEATS},
        },
        "agent_shapes": {
            "heuristic": {"type": "heuristic", "profile": "optional: default | greedy | passive"},
            "webhook": {"type": "webhook", "url": "http(s)://...", "secret": "optional HMAC secret",
                        "token": "optional bearer token", "timeout_ms": 60000, "retries": 1},
            "pull": {"type": "pull", "deadline_ms": 600000,
                     "note": "the seat polls GET /sessions/{id}/decision-request and POSTs /sessions/{id}/decisions "
                             "with its seat token; the session waits for it before advancing"},
            "codex": {"type": "codex", "model": "optional model id", "timeout_ms": 600000,
                      "note": "runs `codex exec --output-schema` locally for each decision (see codex_runner.py)"},
        },
    }
