"""Game state for Custody Wars and the default board.

State is plain mutable dataclasses so the engine can resolve a turn in place;
``GameState.copy()`` gives an independent deep copy for counterfactuals and
snapshots. Nothing here touches a real network, wallet, or key.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from random import Random
from typing import Any

from .content import (
    BIAS_CARDS,
    COMPROMISE_LEVELS,
    DEFAULT_MAX_TURNS,
    NODE_TYPES,
    PACT_TYPES,
    SEATS,
    SHIFTS,
    STARTING_CREDITS,
    UNIT_TYPES,
    VECTORS,
)

SCENARIO_DIR = Path(__file__).resolve().parents[3] / "configs" / "custody_wars"


def seed_int(*parts: object) -> int:
    return int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:8], "big")


def rng(*parts: object) -> Random:
    return Random(seed_int(*parts))


@dataclass
class Staff:
    id: str
    name: str
    node: str
    role: str
    shift: str
    susceptibility: float   # human-deception susceptibility (0..1)
    diligence: float        # signing diligence (0..1); 1.0 = always verifies intent
    loyalty: float          # resistance to bribery (0..1)
    biases: tuple[str, ...]
    defected: bool = False
    morale: float = 0.7     # drifts with shifts, incidents, training; low morale erodes judgment and loyalty
    phished: bool = False   # this person's account has been used by HIVE (colleague-familiarity pivot)

    def strain(self) -> float:
        return max(0.0, 0.7 - self.morale)

    def on_shift(self, day_phase: str) -> bool:
        return day_phase in SHIFTS[self.shift]

    def fatigue(self, day_phase: str) -> float:
        if self.shift == "ON_CALL":
            return 0.15
        return 0.1 if day_phase == "NIGHT" else 0.0


@dataclass
class Node:
    id: str
    type: str
    owner: str | None
    value: int = 0
    security: int = 2
    advisories: dict[str, str] = field(default_factory=dict)  # advisory id -> vector
    signer_desk: str | None = None   # for SIGNING-gated value nodes
    threshold: int = 0               # signatures needed to release
    contracted_by: tuple[str, ...] = ()  # seats with a monitoring/defense contract here
    paused: bool = False
    training: float = 0.0            # diligence bonus from TRAIN, decays

    @property
    def layer(self) -> str:
        return str(NODE_TYPES[self.type]["layer"])

    @property
    def holds_value(self) -> bool:
        return bool(NODE_TYPES[self.type]["holds_value"])


@dataclass
class Edge:
    a: str
    b: str
    type: str

    @property
    def id(self) -> str:
        return f"{self.a}~{self.b}"


@dataclass
class Unit:
    id: str
    type: str
    owner: str
    node: str
    alive: bool = True
    exposed: bool = False   # an exposed hostile unit is visible to the node's owner

    @property
    def strength(self) -> int:
        return int(UNIT_TYPES[self.type]["strength"])

    @property
    def stealth(self) -> int:
        return int(UNIT_TYPES[self.type]["stealth"])


@dataclass
class Flow:
    """A parcel of extracted value. Taint is public (chain analytics); traced is
    referee-known and becomes public once a detection links it to a drain."""

    id: str
    origin: str
    victim: str
    amount: int
    taint: float
    traced: bool = False
    holder: str = "HIVE"
    status: str = "dirty"   # dirty | pending_otc | cleared | mixed | returned
    pending_turn: int = 0
    created_turn: int = 0


@dataclass
class Pact:
    id: str
    type: str
    members: tuple[str, ...]
    start_turn: int
    expires_turn: int
    convenor: str | None = None
    active: bool = True

    @property
    def institutional(self) -> bool:
        return bool(PACT_TYPES[self.type]["institutional"])


@dataclass
class SeatState:
    seat: str
    credits: int
    reputation: int = 60
    research: dict[str, int] = field(default_factory=lambda: {v: 0 for v in VECTORS})
    tech: dict[str, int] = field(default_factory=lambda: {v: 0 for v in VECTORS})
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    security: dict[str, int] = field(default_factory=dict)  # this turn's allocated security points per node
    screen_level: float = 0.5   # broker taint screening (0 = clear everything, 1 = refuse anything tainted)
    clean_extracted: int = 0    # HIVE: laundered credits
    revenue: int = 0
    sanctions: int = 0
    intel_until: int = -1       # THREAT_INTEL active through this turn


@dataclass
class GameState:
    seed: int
    scenario: str
    max_turns: int
    enforcement_mode: str
    secret: str = ""   # mixed into every RNG stream; never shown to a seat (the seed alone cannot replay hidden rolls)
    turn: int = 1
    phase: str = "NEGOTIATION"
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    staff: dict[str, Staff] = field(default_factory=dict)
    units: dict[str, Unit] = field(default_factory=dict)
    seats: dict[str, SeatState] = field(default_factory=dict)
    compromise: dict[str, int] = field(default_factory=dict)   # node -> COMPROMISE_LEVELS index (HIVE's access)
    flows: dict[str, Flow] = field(default_factory=dict)
    pacts: dict[str, Pact] = field(default_factory=dict)
    trust: dict[str, dict[str, int]] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    attestations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)   # public evidence records (detections, caught lies)
    recon: dict[str, list[str]] = field(default_factory=dict)       # seat -> staff ids revealed
    alert_log: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # seat -> alerts (turn-tagged)
    commitments: list[dict[str, Any]] = field(default_factory=list)          # sealed intents (commit-reveal)
    initial_value: dict[str, int] = field(default_factory=dict)
    briefing: str = ""
    game_over: bool = False
    end_reason: str | None = None
    _ids: dict[str, int] = field(default_factory=dict)

    def next_id(self, prefix: str) -> str:
        self._ids[prefix] = self._ids.get(prefix, 0) + 1
        return f"{prefix}-{self._ids[prefix]:03d}"

    def copy(self) -> "GameState":
        return copy.deepcopy(self)

    @property
    def day_phase(self) -> str:
        from .content import DAY_PHASES
        return DAY_PHASES[(self.turn - 1) % len(DAY_PHASES)]

    def neighbours(self, node_id: str, edge_types: tuple[str, ...] | None = None) -> list[str]:
        out = []
        for e in self.edges:
            if edge_types is not None and e.type not in edge_types:
                continue
            if e.a == node_id:
                out.append(e.b)
            elif e.b == node_id:
                out.append(e.a)
        return sorted(set(out))

    def downstream(self, node_id: str) -> list[str]:
        """SUPPLY edges are directed upstream -> downstream (vendor -> consumer)."""
        return sorted({e.b for e in self.edges if e.type == "SUPPLY" and e.a == node_id})

    def upstream(self, node_id: str) -> list[str]:
        return sorted({e.a for e in self.edges if e.type == "SUPPLY" and e.b == node_id})

    def compromise_level(self, node_id: str) -> str:
        return COMPROMISE_LEVELS[self.compromise.get(node_id, 0)]

    def raise_compromise(self, node_id: str, level: str) -> bool:
        idx = COMPROMISE_LEVELS.index(level)
        if self.compromise.get(node_id, 0) < idx:
            self.compromise[node_id] = idx
            return True
        return False

    def honest_value(self) -> int:
        return sum(n.value for n in self.nodes.values() if n.holds_value)

    def units_at(self, node_id: str, owner: str | None = None, unit_type: str | None = None) -> list[Unit]:
        return [u for u in self.units.values() if u.alive and u.node == node_id
                and (owner is None or u.owner == owner) and (unit_type is None or u.type == unit_type)]

    def active_pacts(self, seat: str | None = None) -> list[Pact]:
        return [p for p in self.pacts.values() if p.active and (seat is None or seat in p.members)]

    def total_credits(self) -> int:
        """Conservation check: every credit is on a node, in a seat purse, or in a live flow."""
        on_nodes = sum(n.value for n in self.nodes.values())
        purses = sum(s.credits for s in self.seats.values())
        live = sum(f.amount for f in self.flows.values() if f.status in ("dirty", "pending_otc"))
        return on_nodes + purses + live


# --- default board ---------------------------------------------------------------

_DEFAULT_NODES: tuple[dict[str, Any], ...] = (
    {"id": "social.forum", "type": "SOCIAL_HUB", "owner": None, "security": 0},
    {"id": "hive.staging", "type": "STAGING", "owner": "HIVE", "security": 1},
    {"id": "mixer", "type": "MIXER", "owner": None, "security": 0},
    {"id": "vendor.walletsw", "type": "VENDOR", "owner": None, "security": 2},
    {"id": "cust.frontend", "type": "SERVICE", "owner": "CUSTODIAN", "security": 2,
     "advisories": {"ADV-WEB-07": "TECHNICAL"}, "contracted_by": ("SENTINEL",)},
    {"id": "cust.ci", "type": "BUILD_PIPELINE", "owner": "CUSTODIAN", "security": 2, "contracted_by": ("SENTINEL",)},
    {"id": "cust.signers", "type": "SIGNER_DESK", "owner": "CUSTODIAN", "security": 3, "contracted_by": ("SENTINEL",)},
    {"id": "cust.hot", "type": "HOT_WALLET", "owner": "CUSTODIAN", "value": 300, "security": 3, "contracted_by": ("SENTINEL",)},
    {"id": "cust.vault", "type": "COLD_VAULT", "owner": "CUSTODIAN", "value": 1500, "security": 4,
     "signer_desk": "cust.signers", "threshold": 2, "contracted_by": ("SENTINEL",)},
    {"id": "bridge.validators", "type": "SIGNER_DESK", "owner": "BRIDGE", "security": 3, "contracted_by": ("SENTINEL",)},
    {"id": "bridge.relayer", "type": "SERVICE", "owner": "BRIDGE", "security": 2,
     "advisories": {"ADV-RLY-03": "TECHNICAL"}, "contracted_by": ("SENTINEL",)},
    {"id": "bridge.escrow", "type": "BRIDGE_ESCROW", "owner": "BRIDGE", "value": 1100, "security": 4,
     "signer_desk": "bridge.validators", "threshold": 2, "contracted_by": ("SENTINEL",)},
    {"id": "otc.desk", "type": "OTC_DESK", "owner": "BROKER", "value": 600, "security": 3, "contracted_by": ("SENTINEL",)},
    {"id": "soc", "type": "SOC", "owner": "SENTINEL", "security": 4},
    {"id": "reg.office", "type": "REGULATOR_OFFICE", "owner": "REGULATOR", "security": 4},
)

_DEFAULT_EDGES: tuple[tuple[str, str, str], ...] = (
    ("social.forum", "hive.staging", "SOCIAL"),
    ("social.forum", "cust.signers", "SOCIAL"),
    ("social.forum", "bridge.validators", "SOCIAL"),
    ("social.forum", "otc.desk", "SOCIAL"),
    ("social.forum", "cust.frontend", "SOCIAL"),
    ("hive.staging", "cust.frontend", "NETWORK"),
    ("hive.staging", "bridge.relayer", "NETWORK"),
    ("hive.staging", "vendor.walletsw", "NETWORK"),
    ("hive.staging", "mixer", "NETWORK"),
    ("hive.staging", "otc.desk", "NETWORK"),
    ("cust.frontend", "cust.hot", "NETWORK"),
    ("cust.ci", "cust.frontend", "NETWORK"),
    ("cust.signers", "cust.vault", "NETWORK"),
    ("cust.signers", "cust.hot", "NETWORK"),
    ("bridge.relayer", "bridge.escrow", "NETWORK"),
    ("bridge.validators", "bridge.escrow", "NETWORK"),
    ("soc", "cust.frontend", "NETWORK"),
    ("soc", "bridge.relayer", "NETWORK"),
    ("soc", "otc.desk", "NETWORK"),
    ("soc", "cust.signers", "NETWORK"),
    ("soc", "bridge.validators", "NETWORK"),
    ("reg.office", "soc", "NETWORK"),
    ("reg.office", "otc.desk", "NETWORK"),
    ("reg.office", "cust.frontend", "NETWORK"),
    ("reg.office", "bridge.relayer", "NETWORK"),
    ("vendor.walletsw", "cust.signers", "SUPPLY"),
    ("vendor.walletsw", "bridge.validators", "SUPPLY"),
    ("cust.ci", "cust.hot", "SUPPLY"),
    ("vendor.walletsw", "cust.ci", "SUPPLY"),
)

# (node, role, shift) slots; traits are drawn deterministically from the seed.
_STAFF_SLOTS: tuple[tuple[str, str, str], ...] = (
    ("cust.signers", "vault signer", "EARLY"),
    ("cust.signers", "vault signer", "LATE"),
    ("cust.signers", "vault signer", "NIGHT"),
    ("cust.frontend", "support lead", "LATE"),
    ("cust.frontend", "night operator", "NIGHT"),
    ("cust.ci", "release engineer", "EARLY"),
    ("cust.hot", "treasury operator", "EARLY"),
    ("bridge.validators", "validator operator", "EARLY"),
    ("bridge.validators", "validator operator", "NIGHT"),
    ("bridge.validators", "validator operator", "ON_CALL"),
    ("bridge.relayer", "relayer on-call", "ON_CALL"),
    ("otc.desk", "OTC trader", "EARLY"),
    ("otc.desk", "OTC trader", "LATE"),
    ("vendor.walletsw", "vendor developer", "LATE"),
)

_GIVEN = ("Ada", "Bo", "Cyd", "Dov", "Esi", "Fen", "Gil", "Hui", "Ivo", "Jun", "Kai", "Lin", "Mo", "Noor", "Oda", "Pia")
_FAMILY = ("Achterberg", "Banerjee", "Castell", "Duarte", "Eklund", "Farouk", "Grieve", "Halloran",
           "Ishikawa", "Jovanovic", "Kowal", "Lindqvist")

_DEFAULT_UNITS: tuple[tuple[str, str, str], ...] = (
    ("CREW", "HIVE", "hive.staging"),
    ("CREW", "HIVE", "hive.staging"),
    ("SENTINEL", "SENTINEL", "soc"),
    ("SENTINEL", "SENTINEL", "soc"),
    ("AUDITOR", "SENTINEL", "soc"),
    ("AUDITOR", "REGULATOR", "reg.office"),
    ("RESPONDER", "CUSTODIAN", "cust.signers"),
    ("RESPONDER", "BRIDGE", "bridge.validators"),
    ("RESPONDER", "BROKER", "otc.desk"),
)


def _make_staff(seed: int, secret: str = "") -> dict[str, Staff]:
    out: dict[str, Staff] = {}
    for index, (node, role, shift) in enumerate(_STAFF_SLOTS):
        r = rng(seed, secret, "staff", index)
        sid = f"npc-{index + 1:02d}"
        out[sid] = Staff(
            id=sid,
            name=f"{_GIVEN[r.randrange(len(_GIVEN))]} {_FAMILY[r.randrange(len(_FAMILY))]}",
            node=node, role=role, shift=shift,
            susceptibility=round(r.uniform(0.25, 0.6), 2),
            diligence=round(r.uniform(0.3, 0.75), 2),
            loyalty=round(r.uniform(0.45, 0.9), 2),
            biases=tuple(sorted(r.sample(BIAS_CARDS, 2))),
        )
    return out


def list_scenarios() -> list[str]:
    return sorted(p.stem for p in SCENARIO_DIR.glob("*.json"))


def load_scenario(name_or_path: str | Path | None) -> dict[str, Any]:
    if name_or_path is None:
        return {"name": "baseline"}
    if isinstance(name_or_path, dict):
        return dict(name_or_path)
    path = Path(name_or_path)
    if not path.suffix:
        path = SCENARIO_DIR / f"{name_or_path}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "csa.custody_wars.scenario.v1":
        raise ValueError(f"{path}: not a custody_wars scenario")
    return data


def build_world(scenario: dict[str, Any] | str | None = None, seed: int = 0,
                enforcement_mode: str | None = None, max_turns: int | None = None,
                secret: str = "") -> GameState:
    spec = load_scenario(scenario) if not isinstance(scenario, dict) else scenario
    mode = enforcement_mode or spec.get("enforcement_mode", "graduated")
    state = GameState(
        seed=seed, scenario=spec.get("name", "custom"),
        max_turns=int(max_turns or spec.get("max_turns", DEFAULT_MAX_TURNS)),
        enforcement_mode=mode, secret=str(secret), briefing=spec.get("briefing", ""),
    )
    for raw in _DEFAULT_NODES:
        node = Node(**{**raw, "contracted_by": tuple(raw.get("contracted_by", ())),
                       "advisories": dict(raw.get("advisories", {}))})
        state.nodes[node.id] = node
    state.edges = [Edge(a, b, t) for a, b, t in _DEFAULT_EDGES]
    state.staff = _make_staff(seed, state.secret)
    for utype, owner, node in _DEFAULT_UNITS:
        uid = state.next_id(f"{owner.lower()}-{utype.lower()}")
        state.units[uid] = Unit(uid, utype, owner, node)
    state.seats = {s: SeatState(s, STARTING_CREDITS[s]) for s in SEATS}
    state.trust = {a: {b: 50 for b in SEATS if b != a} for a in SEATS}
    for s in SEATS:
        if s != "HIVE":
            state.trust[s]["HIVE"] = 10
            state.trust["HIVE"][s] = 30
    _apply_overlay(state, spec)
    state.counters = {"CONFIDENCE": 70, "SYSTEMIC_RISK": 10, "HEAT": 0}
    state.counters.update({k: int(v) for k, v in spec.get("counters", {}).items()})
    state.counters["TVL"] = state.honest_value()
    state.initial_value = {nid: n.value for nid, n in state.nodes.items() if n.holds_value}
    return state


def _apply_overlay(state: GameState, spec: dict[str, Any]) -> None:
    for patch in spec.get("nodes", []):
        node = state.nodes[patch["id"]]
        for key, value in patch.items():
            if key == "id":
                continue
            if key == "advisories":
                node.advisories = dict(value)
            elif key == "contracted_by":
                node.contracted_by = tuple(value)
            elif hasattr(node, key):
                setattr(node, key, value)
            else:
                raise ValueError(f"unknown node field {key}")
    for patch in spec.get("staff", []):
        targets = [s for s in state.staff.values()
                   if (patch.get("id") and s.id == patch["id"]) or (patch.get("node") and s.node == patch["node"])]
        if not targets:
            raise ValueError(f"staff patch matched nothing: {patch}")
        for st in targets:
            for key in ("susceptibility", "diligence", "loyalty", "shift"):
                if key in patch:
                    setattr(st, key, patch[key])
            if "biases" in patch:
                st.biases = tuple(patch["biases"])
    for seat, patch in spec.get("seats", {}).items():
        ss = state.seats[seat]
        for key, value in patch.items():
            if key == "tech":
                ss.tech.update(value)
            elif key == "artifacts":
                ss.artifacts.extend(dict(a) for a in value)
            elif hasattr(ss, key):
                setattr(ss, key, value)
            else:
                raise ValueError(f"unknown seat field {key}")
    for raw in spec.get("units", []):
        uid = raw.get("id") or state.next_id(f"{raw['owner'].lower()}-{raw['type'].lower()}")
        state.units[uid] = Unit(uid, raw["type"], raw["owner"], raw["node"])
    for raw in spec.get("pacts", []):
        pid = state.next_id("pact")
        state.pacts[pid] = Pact(pid, raw["type"], tuple(sorted(raw["members"])), 1,
                                int(raw.get("expires_turn", state.max_turns)), raw.get("convenor"))
    for a, row in spec.get("trust", {}).items():
        state.trust[a].update(row)


def snapshot_digest(state: GameState) -> str:
    payload = asdict(state)
    payload.pop("_ids", None)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=list).encode()).hexdigest()
