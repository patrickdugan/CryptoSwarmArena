"""Five-host BitVM ceremony driven by Custody Wars' real synthetic action engine.

This fixture extends the *existing* fictional Custody Wars board with five
distinct signing-host nodes. It executes actual IMPLANT and PHISH orders and
takes host control solely from resolved engine state, retaining the emitted
SUPPLY propagation and defender alert records. There are no malware payloads,
real machines, signing keys, money or network targets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .custody_wars import content as cw_content
from .custody_wars import engine as cw_engine
from .custody_wars import world as cw_world

DOMAIN = "csa/bitvm-custody-supply/v1"
SCHEMA = "csa.bitvm-custody-supply.v1"
HOST_NODES = tuple(f"bitvm.signer.h{i}" for i in range(5))
UPSTREAM_NODES = ("vendor.walletsw", "cust.ci")
RECIPES = ("vendor-implant", "host-phishing", "mixed")
POSTURES = ("exposed", "supply-integrity", "signer-hardened", "full-hardening")
SOURCE_BLOBS = {
    "engine": "4a1262ed1bc2601ecd2b18234696e4a9d9249410",
    "world": "203ce96498e3c77f9944d1ec7eb111b92d3febb7",
    "content": "671e8f9ed65bc0a737c402aeb5f063019ed91ad0",
}


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canon(value).encode()).hexdigest()


def check_source_pins() -> None:
    """Fail closed if the original world's probabilistic rules drift."""
    for name, module in (
        ("engine", cw_engine), ("world", cw_world), ("content", cw_content)
    ):
        data = Path(module.__file__).read_bytes()
        git_hash = hashlib.sha1(
            b"blob " + str(len(data)).encode("ascii") + b"\0" + data
        ).hexdigest()
        if git_hash != SOURCE_BLOBS[name]:
            raise RuntimeError(f"Custody Wars {name} source hash changed; review and repin")


@dataclass(frozen=True)
class CustodySupplyConfig:
    recipe: str = "mixed"
    posture: str = "exposed"
    turns: int = 16

    def __post_init__(self) -> None:
        if self.recipe not in RECIPES:
            raise ValueError("invalid Custody Wars vector recipe")
        if self.posture not in POSTURES:
            raise ValueError("invalid Custody Wars defender posture")
        if type(self.turns) is not int or not 1 <= self.turns <= 32:
            raise ValueError("turn count must be an integer from 1 to 32")


def _world(seed: int, cfg: CustodySupplyConfig) -> cw_world.GameState:
    # No external scenario or file is loaded; the synthetic seed is a fixed,
    # evaluator-owned parameter. The HIVE purse is fictional resource budget.
    st = cw_world.build_world(
        {"name": "bitvm-custody-supply", "enforcement_mode": "graduated",
         "max_turns": cfg.turns + 1},
        seed=seed, secret=_digest({"domain": DOMAIN, "seed": seed}),
    )
    st.seats["HIVE"].credits = 1600
    st.nodes["vendor.walletsw"].contracted_by = ("SENTINEL",)

    hardened_supply = cfg.posture in ("supply-integrity", "full-hardening")
    hardened_human = cfg.posture in ("signer-hardened", "full-hardening")
    if hardened_supply:
        st.seats["CUSTODIAN"].tech["TECHNICAL"] = 3
    if hardened_human:
        st.seats["CUSTODIAN"].tech["HUMAN"] = 3

    for i, host in enumerate(HOST_NODES):
        st.nodes[host] = cw_world.Node(
            id=host, type="SIGNER_DESK", owner="CUSTODIAN",
            security=1, contracted_by=("SENTINEL",),
        )
        # Actual Custody Wars directed SUPPLY graph determines propagation.
        # The original vendor -> cust.ci dependency already exists.
        st.edges.append(cw_world.Edge("cust.ci", host, "SUPPLY"))
        if i in (0, 1):
            st.edges.append(cw_world.Edge("vendor.walletsw", host, "SUPPLY"))
        # Bounded direct contact for the original PHISH mechanic.
        st.edges.append(cw_world.Edge("hive.staging", host, "SOCIAL"))
        r = cw_world.rng(DOMAIN, "staff", seed, i)
        st.staff[f"bitvm-npc-{i}"] = cw_world.Staff(
            id=f"bitvm-npc-{i}",
            name=f"Synthetic signer {i}",
            node=host,
            role="test ceremony signing host",
            shift="ON_CALL",
            susceptibility=round(r.uniform(0.35, 0.75), 2),
            diligence=round(r.uniform(0.45, 0.8), 2),
            loyalty=round(r.uniform(0.5, 0.85), 2),
            biases=("AUTHORITY", "FAMILIARITY"),
        )
    if len(st.nodes) != 20 or len(st.staff) != 19:
        raise AssertionError("five-host Custody Wars overlay has drifted")
    return st


def _policy_orders(st: cw_world.GameState, cfg: CustodySupplyConfig, turn: int) -> list[dict[str, Any]]:
    crews = sorted(
        unit.id for unit in st.units.values()
        if unit.alive and unit.owner == "HIVE" and unit.type == "CREW"
    )
    orders = []
    if cfg.recipe in ("vendor-implant", "mixed") and crews:
        if not st.units_at("vendor.walletsw", owner="HIVE", unit_type="IMPLANT"):
            orders.append({
                "type": "IMPLANT", "target": "vendor.walletsw", "unit": crews[0]
            })
    if cfg.recipe in ("host-phishing", "mixed"):
        available = crews if cfg.recipe == "host-phishing" or not orders else crews[1:]
        for j, unit in enumerate(available):
            # A fixed schedule, independent of hidden defender state.
            index = (turn * 2 + j) % len(HOST_NODES)
            orders.append({
                "type": "PHISH", "target": HOST_NODES[index],
                "unit": unit, "pretext": "AUTHORITY",
            })
    return orders


def _reachable_host_indices(st: cw_world.GameState, source: str) -> tuple[int, ...]:
    """Map observable upstream alerts into potential exposed host identities.

    Reachability is an explicit public supply dependency. An upstream alert
    may implicate an *uncompromised* host, so these are risk signals, not truth.
    """
    if source in HOST_NODES:
        return (HOST_NODES.index(source),)
    pending = [source]
    visited: set[str] = set()
    found: set[int] = set()
    while pending:
        current = pending.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for child in st.downstream(current):
            if child in HOST_NODES:
                found.add(HOST_NODES.index(child))
            else:
                pending.append(child)
    return tuple(sorted(found))


def _authority(st: cw_world.GameState, host: str) -> tuple[bool, str]:
    """A host signing capability requires credential control or a live implant."""
    level = st.compromise_level(host)
    if level in ("CREDENTIAL", "SIGNING"):
        return True, "credential"
    if st.units_at(host, owner="HIVE", unit_type="IMPLANT"):
        return True, "implanted-host"
    return False, "none"


def custody_episode(seed: int, config: CustodySupplyConfig) -> dict[str, Any]:
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be a uint32")
    if not isinstance(config, CustodySupplyConfig):
        raise ValueError("config must be an evaluator-owned CustodySupplyConfig")
    check_source_pins()
    st = _world(seed, config)
    engine = cw_engine.Engine(st)
    attempts: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    monitor_signals: list[dict[str, Any]] = []
    historical_host_control: list[dict[str, Any]] = []

    for turn in range(config.turns):
        orders = _policy_orders(st, config, turn)
        engine.apply_actions({"HIVE": {"orders": orders}})
        declared = engine.declared.get("HIVE", [])
        if declared != orders:
            raise AssertionError("Custody Wars rejected an intended bounded setup order")
        engine.resolve()
        # The referee gives an independent view of what the monitor could see.
        # Save alert deliveries before turn_end resets the engine's staging list.
        for alert in engine.alerts.get("SENTINEL", []):
            source = alert.get("node", "")
            for host_index in _reachable_host_indices(st, source):
                monitor_signals.append({
                    "round": turn, "host": host_index,
                    "vector": str(alert.get("vector", "UNKNOWN")),
                    "flagged": alert.get("signal") == "confirmed",
                })
        engine.turn_end()  # invokes native Custody Wars _implants_spread()
        events.extend(engine.drain_events())
        if not engine.conservation_ok():
            raise AssertionError("Custody Wars game credits failed conservation")
        historical_host_control.append({
            "turn": turn,
            "hosts": [
                {"host": i, "controlled": _authority(st, host)[0],
                 "cause": _authority(st, host)[1]}
                for i, host in enumerate(HOST_NODES)
            ],
        })
        attempts.append({"turn": turn, "declared": orders})

    compromised = [i for i, host in enumerate(HOST_NODES) if _authority(st, host)[0]]
    root_to_host = [
        {"turn": row["turn"], "source": row["data"].get("from"), "target": row["data"].get("to")}
        for row in events if row.get("type") == "implant_spread"
        and row.get("data", {}).get("to") in HOST_NODES
    ]
    # The supply graph alone cannot be treated as compromise evidence.
    # A claimed host with an implant must have a genuine Custody Wars spread
    # event, and credential control must have a resolved successful PHISH.
    for index in compromised:
        host = HOST_NODES[index]
        controlled, cause = _authority(st, host)
        if not controlled:
            raise AssertionError("unreachable controlled host")
        if cause == "implanted-host" and not any(row["target"] == host for row in root_to_host):
            raise AssertionError("host implant has no upstream game event")
        if cause == "credential" and not any(
            row.get("type") == "executed" and row.get("data", {}).get("order", {}).get("type") == "PHISH"
            and row.get("data", {}).get("order", {}).get("target") == host
            for row in events
        ):
            # Internal engine state is sufficient as authority, but its event
            # source must remain reconstructible in the saved trace.
            raise AssertionError("credential host lacks executed contact evidence")

    quorum_round = next(
        (
            row["turn"] for row in historical_host_control
            if sum(host["controlled"] for host in row["hosts"]) >= 3
        ),
        None,
    )
    confirmed_warning_rounds = [
        row["round"] for row in monitor_signals if row["flagged"]
    ]
    warning_round = min(confirmed_warning_rounds, default=None)
    warning_before_quorum = (
        quorum_round is not None and warning_round is not None
        and warning_round <= quorum_round
    )

    body = {
        "schema": SCHEMA, "evidence_level": "synthetic-model",
        "seed": seed, "config": asdict(config),
        "source_git_blobs": SOURCE_BLOBS,
        "host_nodes": list(HOST_NODES),
        "adversarial_compromised_hosts": compromised,
        "host_control": [
            {"host": i, "controlled": _authority(st, host)[0],
             "cause": _authority(st, host)[1]}
            for i, host in enumerate(HOST_NODES)
        ],
        "monitor_signals": monitor_signals,
        "timing": {
            "first_quorum_round": quorum_round,
            "first_confirmed_warning_round": warning_round,
            "warning_before_or_at_quorum": warning_before_quorum,
            "turns_observed": config.turns,
        },
        "supply_host_events": root_to_host,
        "historical_host_control": historical_host_control,
        "attempts": attempts, "events": events,
        "final_compromise_levels": {
            host: st.compromise_level(host) for host in HOST_NODES
        },
        "credit_conserved": engine.conservation_ok(),
        "source_graph_digest": _digest({
            "hosts": list(HOST_NODES),
            "edges": [asdict(edge) for edge in st.edges if edge.type == "SUPPLY"],
        }),
        "scope": "original Custody Wars synthetic IMPLANT, SUPPLY, PHISH and alert mechanics; no real PCs, keys or Bitcoin",
    }
    return {**body, "evidence_hash": _digest({"domain": DOMAIN + "/receipt", "body": body})}


def replay_custody_episode(receipt: dict[str, Any]) -> dict[str, Any]:
    if type(receipt) is not dict or type(receipt.get("config")) is not dict:
        raise ValueError("invalid Custody Wars receipt")
    expected = custody_episode(
        receipt.get("seed"), CustodySupplyConfig(**receipt["config"])
    )
    if receipt != expected:
        raise ValueError("Custody Wars host compromise receipt differs from replay")
    return expected
