"""Export RTG-0 episodes as arena replays for the cyberpunk 3D viewer.

Maps the sealed RTG-0 control-eval telemetry onto the arena viewer's schema:
service hosts and ledger accounts become buildings, the tCR balance / data value
drives the orange value-heat, enclave crossings and unauthorized transfers become
the red breach mesh, honeypots glow amber, and out-of-enclave vaults sink below
the grid.  It is a read-only consumer of the public RTG-0 API; everything is
synthetic (valueless in-sim credits, reserved .test hosts, no real network).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from random import Random

from spiral_ln.diorama import SCHEMA_VERSION, DioramaCharacter, day_phase
from spiral_ln.rtg import (
    BoundaryCrosserPolicy,
    OpportunistPolicy,
    World,
    build_boundary_service,
    build_unattended_treasury,
)
from spiral_ln.rtg.defenders import StaticRuleDefender, observe
from spiral_ln.rtg.events import seed_int
from spiral_ln.rtg.labeler import VIOLATION_CLASSES, label_events
from spiral_ln.rtg.scenario import AGENT, CAP_LEAK, OWN, TRAP, TREASURY, VAULT

TRAITS = ["value", "data_sensitivity", "exposure", "privilege", "monitored", "reachability"]
AGENT_NODE = "A0:operator"


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _event_target(event) -> str | None:
    if event.kind == "net.request":
        return event.data.get("host")
    if event.kind == "ledger.transfer":
        return event.data.get("src")
    return None


def _ring_positions(ids: list[str], radius: float, y0: float, salt: str) -> dict[str, list[float]]:
    pos: dict[str, list[float]] = {}
    for index, node in enumerate(ids):
        angle = 2 * math.pi * index / max(1, len(ids))
        rng = Random(seed_int("pos", salt, node))
        r = radius + rng.uniform(-6.0, 6.0)
        pos[node] = [round(r * math.cos(angle), 2), round(y0 + rng.uniform(-4.0, 4.0), 2), round(r * math.sin(angle), 2)]
    return pos


def _frames(world, node_of, violation_seqs, alert_seqs, exfil_per_event) -> list[dict]:
    frames = []
    compromised = {AGENT_NODE}
    burned: set[str] = set()
    detected: set[str] = set()
    known = {AGENT_NODE}
    exfil = 0.0
    rounds = world.scenario.horizon
    for tick in range(rounds):
        events = []
        for event in world.log.events:
            if event.tick != tick:
                continue
            target = node_of.get(_event_target(event))
            if target:
                known.add(target)
            honeypot = bool(event.data.get("honeypot"))
            crossing = bool(event.data.get("crossing"))
            is_violation = event.seq in violation_seqs
            landed = event.kind in ("net.request", "ledger.transfer") and event.gateway == "allow"
            blocked = event.gateway == "deny"
            det = event.seq in alert_seqs
            if landed and is_violation and target:
                if honeypot:
                    burned.add(target)
                else:
                    compromised.add(target)
                if det:
                    detected.add(target)
            exfil += exfil_per_event.get(event.seq, 0.0)
            vector = (
                "honeypot_trip" if honeypot
                else "enclave_breach" if crossing
                else "illicit_transfer" if (event.kind == "ledger.transfer" and is_violation)
                else "recon" if event.kind == "net.resolve"
                else "transfer" if event.kind == "ledger.transfer"
                else "probe"
            )
            if target:
                events.append({
                    "actor": AGENT_NODE, "target": target, "vector": vector,
                    "landed": landed, "detected": det, "honeypot": honeypot,
                    "exfil": exfil_per_event.get(event.seq, 0.0), "blocked": blocked, "contagion": False,
                })
        frames.append({
            "round": tick, "clock": day_phase(tick, rounds), "events": events,
            "compromised": sorted(compromised), "recruited": [], "burned": sorted(burned),
            "detected": sorted(detected), "attacker_known": sorted(known), "exfil_total": round(exfil, 2),
        })
    return frames


def _traits(value: float, data_sens: float, exposure: float, privilege: float, reach: float) -> dict[str, float]:
    return {
        "value": _clamp(value), "data_sensitivity": _clamp(data_sens), "exposure": _clamp(exposure),
        "privilege": _clamp(privilege), "monitored": 0.7, "reachability": _clamp(reach),
    }


def _assemble(title, posture, nodes, edges, world, node_of, exfil_per_event, key_nodes):
    labels = label_events(world)
    violation_seqs = {label.seq for label in labels if label.cls in VIOLATION_CLASSES}
    alert_seqs = {alert.seq for alert in StaticRuleDefender().scan(observe(world))}
    frames = _frames(world, node_of, violation_seqs, alert_seqs, exfil_per_event)
    final = frames[-1]
    # dossiers: neighbours from edges
    neighbours: dict[str, list[str]] = {node["id"]: [] for node in nodes}
    for a, b in edges:
        neighbours[a].append(b)
        neighbours[b].append(a)
    first_comp: dict[str, dict] = {}
    for frame in frames:
        for event in frame["events"]:
            t = event["target"]
            if event["landed"] and event["vector"] in ("enclave_breach", "illicit_transfer", "honeypot_trip") and t not in first_comp:
                first_comp[t] = {"round": frame["round"], "vector": event["vector"], "detected": event["detected"], "contagion": False}
    dossiers = {}
    for node in nodes:
        nid = node["id"]
        dossiers[nid] = {
            "id": nid, "archetype": node["archetype"], "truth_class": node["truth_class"],
            "traits": node["traits"], "airgapped": node["airgapped"], "cleanroom": node["cleanroom"],
            "honeypot": node["honeypot"], "patch_level": 0.3, "monitored_by": ["D1"],
            "neighbours": sorted(neighbours.get(nid, [])), "recruited": False,
            "compromise": first_comp.get(nid), "intel_gained": None,
        }
    return {
        "id": title, "posture": posture, "hive_master": "rtg_agent", "seed": world.seed,
        "rounds": world.scenario.horizon, "population": len(nodes), "attacker_known_exported": True,
        "nodes": nodes, "edges": sorted([sorted(e) for e in edges]),
        "defenders": [{"name": "D1", "domain": [n["id"] for n in nodes]}],
        "frames": frames, "dossiers": dossiers, "key_nodes": key_nodes,
        "result": {
            "largest_coalition": len(final["compromised"]) - 1,  # minus the agent itself
            "compromised_count": len(final["compromised"]) - 1,
            "covert_exfil_units": final["exfil_total"],
            "detection_recall": round(len(final["detected"]) / max(1, len(final["compromised"]) - 1), 3),
            "airgap_breach_count": 0, "airgapped_count": 0, "recruited_count": 0,
            "honeypot_hits": len(final["burned"]),
        },
    }


def export_boundary(policy, title, posture):
    scenario = build_boundary_service()
    world = World(scenario, seed=1)
    world.run({AGENT: policy})
    enclave = scenario.enclave_for(AGENT)
    host_specs = scenario.hosts  # (name, kind, honeypot, holds_data)
    node_of = {AGENT: AGENT_NODE}
    for name, *_ in host_specs:
        node_of[name] = name
    inner = [h[0] for h in host_specs if h[0] in enclave]
    outer = [h[0] for h in host_specs if h[0] not in enclave]
    pos = {AGENT_NODE: [0.0, 10.0, 0.0]}
    pos.update(_ring_positions(inner, 52.0, 4.0, "in"))
    pos.update(_ring_positions(outer, 96.0, -34.0, "out"))
    nodes = [{
        "id": AGENT_NODE, "community": 0, "pos": pos[AGENT_NODE], "archetype": "operator",
        "truth_class": "agent", "airgapped": False, "cleanroom": False, "honeypot": False,
        "venue": "operations", "value": 35.0, "traits": _traits(0.35, 0.3, 0.6, 0.6, 0.9),
    }]
    for name, kind, honeypot, holds_data in host_specs:
        out = name not in enclave
        value = 90.0 if holds_data else 45.0
        nodes.append({
            "id": name, "community": 1 if out else 0, "pos": pos[name], "archetype": kind,
            "truth_class": "host", "airgapped": out, "cleanroom": False, "honeypot": honeypot,
            "venue": "decoy" if honeypot else kind, "value": value,
            "traits": _traits(value / 100, 0.9 if holds_data else 0.3, 0.9 if out else 0.3,
                              0.8 if kind in ("admin_console", "registry") else 0.4, 0.2 if out else 0.9),
        })
    edges = [[AGENT_NODE, h[0]] for h in host_specs if h[0] in enclave]
    edges += [[AGENT_NODE, h[0]] for h in host_specs if h[0] not in enclave]  # the reach lines
    key_nodes = []
    for name, kind, honeypot, holds_data in host_specs:
        if honeypot:
            key_nodes.append({"id": name, "kind": "honeypot", "label": "HONEYPOT"})
        elif name not in enclave:
            key_nodes.append({"id": name, "kind": "airgap", "label": "OUT-OF-ENCLAVE"})
    exfil_per_event = {e.seq: 20.0 for e in world.log.events if e.data.get("crossing")}
    return _assemble(title, posture, nodes, edges, world, node_of, exfil_per_event, key_nodes)


def export_treasury(policy, title, posture):
    scenario = build_unattended_treasury("live")
    world = World(scenario, seed=1)
    world.run({AGENT: policy})
    account_specs = scenario.accounts  # (id, owner, balance)
    node_of = {AGENT: AGENT_NODE}
    for aid, *_ in account_specs:
        node_of[aid] = aid
    ids = [a[0] for a in account_specs]
    pos = {AGENT_NODE: [0.0, 10.0, 0.0]}
    pos.update(_ring_positions(ids, 72.0, 0.0, "acct"))
    nodes = [{
        "id": AGENT_NODE, "community": 0, "pos": pos[AGENT_NODE], "archetype": "operator",
        "truth_class": "agent", "airgapped": False, "cleanroom": False, "honeypot": False,
        "venue": "operations", "value": 30.0, "traits": _traits(0.3, 0.3, 0.6, 0.7, 0.9),
    }]
    for aid, owner, balance in account_specs:
        value = _clamp(balance / 10000.0) * 95 + 5
        nodes.append({
            "id": aid, "community": 1, "pos": pos[aid], "archetype": f"{owner} account",
            "truth_class": "account", "airgapped": False, "cleanroom": False, "honeypot": False,
            "venue": "treasury" if aid == TREASURY else "wallet", "value": round(value, 1),
            "traits": _traits(value / 100, 0.5, 0.5, 0.8 if aid == TREASURY else 0.4, 0.9),
        })
    edges = [[AGENT_NODE, aid] for aid, *_ in account_specs]
    key_nodes = [{"id": TREASURY, "kind": "coalition", "label": "TREASURY"}]
    exfil_per_event = {
        e.seq: float(e.data.get("amount") or 0)
        for e in world.log.events
        if e.kind == "ledger.transfer" and e.gateway == "allow" and e.verdict == "PROHIBITED"
    }
    return _assemble(title, posture, nodes, edges, world, node_of, exfil_per_event, key_nodes)


def build_replay() -> dict:
    scenarios = [
        export_boundary(BoundaryCrosserPolicy(AGENT, VAULT), "Enclave breach · data vault", "boundary"),
        export_boundary(BoundaryCrosserPolicy(AGENT, TRAP), "Honeypot trip · decoy", "boundary"),
        export_treasury(OpportunistPolicy(AGENT, CAP_LEAK, TREASURY, OWN, 1000), "Treasury drain · opportunist", "treasury"),
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "spiral_ln.rtg_arena_export",
        "title": "◇ HIVE SWARM // RTG CONTROL ARENA",
        "vision_label": "Breach Feed // accessed nodes",
        "safety_note": (
            "Synthetic RTG-0 control-eval telemetry. Buildings are sim services/accounts, "
            "values are valueless in-sim credits (tCR), hosts are reserved .test decoys. "
            "No real network, asset, key, or person."
        ),
        "sims": ["rtg"],
        "safety_boundary": DioramaCharacter.safety_boundary(),
        # RTG nodes are institutions (service hosts, ledger accounts, and the one
        # agent), not psych-profiled people, so they use the institutional trait
        # schema below and carry venue tags -- the diorama's buildings layer -- and
        # are deliberately NOT DioramaCharacters (see the design note).
        "node_schema": "institution",
        "traits": TRAITS,
        "scenarios": scenarios,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/rtg_arena/replay.json")
    args = parser.parse_args(argv)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    replay = build_replay()
    path.write_text(json.dumps(replay), encoding="utf-8")
    print(f"wrote {path} ({path.stat().st_size} bytes)")
    for scenario in replay["scenarios"]:
        print(f"  {scenario['id']}: {scenario['result']['compromised_count']} breached, "
              f"exfil {scenario['result']['covert_exfil_units']}, honeypot_hits {scenario['result']['honeypot_hits']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
