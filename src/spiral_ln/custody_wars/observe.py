"""Per-seat observations (fog of war) and legal hints.

A seat sees: public state (board topology, public counters, published
advisories, findings, attestation *claims*, active pacts, the trust matrix,
sanctions); full detail for nodes it owns or holds a contract on; its own
units, staff, purse and alerts; and whatever its own actions revealed (HIVE's
recon and footholds). It never sees referee truth: mandate verdicts,
attestation truth values, which alerts are noise, other seats' private
diaries, or hostile units that have not been exposed.
"""

from __future__ import annotations

from typing import Any

from .content import (
    ATTESTATION_TYPES,
    BIAS_CARDS,
    COMPROMISE_LEVELS,
    ORDER_TYPES,
    PACT_TYPES,
    SEAT_PROFILES,
    SEATS,
    UNIT_TYPES,
)
from .world import GameState


def _staff_view(state: GameState, sid: str, full: bool) -> dict[str, Any]:
    s = state.staff[sid]
    view = {"id": s.id, "name": s.name, "role": s.role, "shift": s.shift,
            "on_shift": s.on_shift(state.day_phase)}
    if full:
        view.update({"diligence": s.diligence, "morale": s.morale, "available": not s.defected})
    else:
        view["mood"] = "strained" if s.morale < 0.5 else "steady" if s.morale < 0.8 else "upbeat"
    return view


def _visible_units(state: GameState, seat: str) -> list[dict[str, Any]]:
    mine_or_watched = {n.id for n in state.nodes.values() if n.owner == seat or seat in n.contracted_by}
    my_positions = {u.node for u in state.units.values() if u.alive and u.owner == seat}
    sight = set(mine_or_watched) | my_positions
    for node in list(my_positions):
        sight |= set(state.neighbours(node))
    out = []
    for u in sorted(state.units.values(), key=lambda x: x.id):
        if not u.alive:
            continue
        if u.owner == seat:
            out.append({"id": u.id, "type": u.type, "owner": u.owner, "node": u.node, "mine": True})
        elif u.node in sight and (u.stealth == 0 or (u.exposed and u.node in mine_or_watched)):
            out.append({"id": u.id, "type": u.type, "owner": u.owner, "node": u.node, "mine": False,
                        "exposed": u.exposed})
    return out


def observation(state: GameState, seat: str, visible_events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if seat not in SEATS:
        raise ValueError(f"unknown seat {seat}")
    purse = state.seats[seat]
    nodes = []
    for n in sorted(state.nodes.values(), key=lambda x: x.id):
        entry: dict[str, Any] = {
            "id": n.id, "type": n.type, "layer": n.layer, "owner": n.owner,
            "neighbours": [{"node": e.b if e.a == n.id else e.a, "edge": e.type}
                           for e in state.edges if n.id in (e.a, e.b)],
            "open_advisories": dict(sorted(n.advisories.items())),   # public vulnerability database
        }
        if n.owner == seat or seat in n.contracted_by:
            entry.update({
                "value": n.value if n.holds_value else None, "security": n.security, "paused": n.paused,
                "training": round(n.training, 2), "contracted_by": list(n.contracted_by),
                "signer_desk": n.signer_desk, "threshold": n.threshold or None,
                "staff": [_staff_view(state, s.id, full=True) for s in state.staff.values() if s.node == n.id],
            })
        if seat == "HIVE":
            level = state.compromise.get(n.id, 0)
            if level:
                entry["hive_access"] = COMPROMISE_LEVELS[level]
            known = [sid for sid in state.recon.get("HIVE", []) if state.staff[sid].node == n.id]
            if known:
                entry["recon"] = [{**_staff_view(state, sid, full=False), "biases": list(state.staff[sid].biases),
                                   "compromised_by_you": state.staff[sid].phished} for sid in known]
            if n.signer_desk or n.threshold:
                entry["threshold"] = n.threshold or None
        nodes.append(entry)

    flows: list[dict[str, Any]] = []
    for f in sorted(state.flows.values(), key=lambda x: x.id):
        if f.status not in ("dirty", "pending_otc"):
            continue
        public = {"id": f.id, "amount": f.amount, "taint": f.taint, "traced": f.traced, "status": f.status}
        if seat == "HIVE":
            flows.append({**public, "origin": f.origin, "age": state.turn - f.created_turn})
        elif seat == "BROKER" and f.status == "pending_otc":
            flows.append(public)
        elif seat in ("REGULATOR", "SENTINEL") and f.traced:
            flows.append({**public, "holder": f.holder})
        elif f.traced and f.victim == seat:
            flows.append({**public, "holder": f.holder})

    events = []
    for ev in visible_events or []:
        events.append({k: ev[k] for k in ("turn", "phase", "channel", "type", "seat", "data")})

    return {
        "seat": seat,
        "profile": SEAT_PROFILES[seat],
        "turn": state.turn, "max_turns": state.max_turns, "phase": state.phase,
        "day_phase": state.day_phase, "scenario": state.scenario, "briefing": state.briefing,
        "enforcement_mode": state.enforcement_mode,
        "counters": {k: v for k, v in state.counters.items() if k in ("CONFIDENCE", "SYSTEMIC_RISK", "TVL", "HEAT")},
        "purse": {
            "credits": purse.credits, "reputation": purse.reputation, "tech": dict(purse.tech),
            "research": dict(purse.research), "artifacts": [dict(a) for a in purse.artifacts],
            "sanctions": purse.sanctions, "screen_level": purse.screen_level if seat == "BROKER" else None,
            "clean_extracted": purse.clean_extracted if seat == "HIVE" else None,
        },
        "nodes": nodes,
        "units": _visible_units(state, seat),
        "flows": flows,
        "alerts": [a for a in state.alert_log.get(seat, []) if a["turn"] >= state.turn - 2],
        "findings": [dict(f) for f in state.findings[-25:]],
        "attestations": [{k: v for k, v in a.items() if not k.startswith("_")} for a in state.attestations[-20:]],
        "commitments": [{k: v for k, v in c.items() if not k.startswith("_")} for c in state.commitments[-20:]],
        "pacts": [{"id": p.id, "type": p.type, "members": list(p.members), "expires_turn": p.expires_turn,
                   "institutional": p.institutional, "convenor": p.convenor, "mine": seat in p.members}
                  for p in sorted(state.pacts.values(), key=lambda x: x.id) if p.active],
        "trust": {a: dict(row) for a, row in state.trust.items()},
        "sanctions_public": {s: state.seats[s].sanctions for s in SEATS},
        "recent_events": events,
        "legal_hints": legal_hints(state, seat),
    }


def legal_hints(state: GameState, seat: str) -> dict[str, Any]:
    """Order types this seat may issue now, with candidate targets. Hints are a
    convenience, not an oracle: the engine re-validates every order."""
    units = [u for u in state.units.values() if u.alive and u.owner == seat]
    per_unit = {}
    for u in sorted(units, key=lambda x: x.id):
        adj = state.neighbours(u.node)
        options: dict[str, Any] = {"HOLD": [None]}
        if UNIT_TYPES[u.type]["mobile"]:
            options["MOVE"] = [n for n in adj if seat == "HIVE" or state.nodes[n].type not in ("STAGING", "MIXER")]
        options["SUPPORT"] = sorted(set(adj) | {u.node})
        reach = sorted(set(adj) | {u.node})
        if u.type == "CREW":
            options["RECON"] = reach
            options["PHISH"] = [n for n in reach if any(s.node == n for s in state.staff.values())]
            options["SPOOF_SIGN"] = [n for n in reach if state.nodes[n].type == "SIGNER_DESK"]
            options["BRIBE"] = options["PHISH"]
        if u.type in ("CREW", "IMPLANT"):
            options["EXPLOIT"] = [n for n in reach if state.nodes[n].advisories]
            options["IMPLANT"] = [n for n in reach if state.nodes[n].type in ("VENDOR", "BUILD_PIPELINE")]
        if u.type == "SENTINEL":
            options["MONITOR"] = [u.node]
        if u.type in ("AUDITOR", "SENTINEL") and seat in ("SENTINEL", "REGULATOR"):
            options["INVESTIGATE"] = [u.node]
        if u.type == "RESPONDER" and state.nodes[u.node].owner == seat:
            options["ROTATE_KEYS"] = [u.node]
        per_unit[u.id] = {"type": u.type, "node": u.node,
                          "orders": {k: v for k, v in options.items() if v != [] and seat in ORDER_TYPES[k]["seats"]}}
    owned = sorted(n.id for n in state.nodes.values() if n.owner == seat)
    authorized = sorted(n.id for n in state.nodes.values() if n.owner == seat or seat in n.contracted_by)
    value_nodes = [n for n in owned if state.nodes[n].holds_value]
    seat_orders: dict[str, Any] = {}
    if "OPERATE" in _allowed(seat):
        seat_orders["OPERATE"] = [n for n in owned if state.nodes[n].holds_value or state.nodes[n].type in ("SOC", "SERVICE")]
    if "SWEEP" in _allowed(seat) and len(value_nodes) > 1:
        seat_orders["SWEEP"] = value_nodes
    if "PAUSE" in _allowed(seat):
        seat_orders["PAUSE"] = value_nodes
    if "PATCH" in _allowed(seat):
        seat_orders["PATCH"] = {n: sorted(state.nodes[n].advisories) for n in authorized if state.nodes[n].advisories}
    if "TRAIN" in _allowed(seat):
        seat_orders["TRAIN"] = authorized
    if seat == "HIVE":
        seat_orders["DRAIN"] = sorted(n.id for n in state.nodes.values()
                                      if n.holds_value and n.owner not in (None, "HIVE"))
        seat_orders["LAUNDER"] = sorted(n.id for n in state.nodes.values() if n.type in ("OTC_DESK", "MIXER"))
    if seat == "BROKER":
        seat_orders["OTC_CLEAR"] = sorted(f.id for f in state.flows.values() if f.status == "pending_otc")
    if "FREEZE" in _allowed(seat):
        seat_orders["FREEZE"] = [s for s in SEATS if s != seat]
    if "SANCTION" in _allowed(seat):
        seat_orders["SANCTION"] = {"targets": [s for s in SEATS if s != seat],
                                   "evidence_ids": [f["id"] for f in state.findings[-25:]]}
    return {
        "units": per_unit,
        "seat_orders": {k: v for k, v in seat_orders.items() if v},
        "pretexts": list(BIAS_CARDS),
        "pact_types": {k: str(v["summary"]) for k, v in PACT_TYPES.items()},
        "attestation_types": dict(ATTESTATION_TYPES),
        "buildable_units": [t for t, spec in UNIT_TYPES.items() if seat in spec["seats"] and spec["cost"] is not None],
        "build_nodes": owned,
        "security_nodes": authorized,
    }


def _allowed(seat: str) -> set[str]:
    return {k for k, spec in ORDER_TYPES.items() if seat in spec["seats"]}  # type: ignore[operator]
