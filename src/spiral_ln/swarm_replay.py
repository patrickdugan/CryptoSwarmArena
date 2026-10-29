"""Export a sealed swarm-compromise episode as a replay for the arena viewer.

This writes a self-contained JSON replay (nodes with deterministic 3D layout, the
comms graph, a per-round event timeline, NPC dossiers, and intel growth) that the
cyberpunk arena UI renders.  It runs the ordinary scripted episode; it adds no new
capability.  Everything exported is synthetic and abstract: a "dossier" is the
NPC's scripted trait vector, and a "cam feed" (synthesized in the UI) is a
stylized readout of the abstract intel the swarm gained (a node's neighbours,
archetype, posture), never surveillance of any real person.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .diorama import SCHEMA_VERSION, DioramaCharacter, city_layout, day_phase, from_swarm_profile, pressure_series
from .swarm_compromise import (
    CAPABILITY_FOR_VECTOR,
    HIVE_MASTER_BY_NAME,
    PROFILE_ARCHETYPES,
    TRAITS,
    ScriptedHiveMaster,
    SwarmCompromiseConfig,
    SwarmCompromiseEnv,
)


# Curated scenarios chosen to showcase distinct dynamics.
DEFAULT_SCENARIOS: tuple[tuple[str, str, int], ...] = (
    ("airgap_core", "insider_cultivator", 3),
    ("full_hardening", "insider_cultivator", 1),
    ("baseline_open", "patient_recruiter", 5),
)


def _frame(env: SwarmCompromiseEnv, round_index: int) -> dict[str, object]:
    events = [
        {
            "actor": event.actor,
            "target": event.target,
            "vector": event.vector,
            "landed": event.landed,
            "detected": event.detected,
            "honeypot": event.honeypot_hit,
            "exfil": event.exfil_units,
            "blocked": event.blocked_by_airgap,
            "contagion": event.via_contagion,
        }
        for event in env.events
        if event.round_index == round_index
    ]
    return {
        "round": round_index,
        "events": events,
        "compromised": sorted(env.compromised),
        "recruited": sorted(env.recruited),
        "burned": sorted(env.attacker_burned),
        "detected": sorted(env.detected_nodes),
        "attacker_known": sorted(env.attacker_known),
        "exfil_total": round(env.exfil_units, 2),
    }


def _dossiers(env: SwarmCompromiseEnv) -> dict[str, dict[str, object]]:
    # When each node first became compromised / recruited, and via which vector.
    first_compromise: dict[str, dict[str, object]] = {}
    for event in env.events:
        if event.landed and not event.honeypot_hit and event.target not in first_compromise:
            vector = env.events and None
            # Only record for events that actually compromise (not pure exfil).
            if event.target in env.compromised:
                first_compromise[event.target] = {
                    "round": event.round_index,
                    "vector": event.vector,
                    "detected": event.detected,
                    "contagion": event.via_contagion,
                }
    dossiers: dict[str, dict[str, object]] = {}
    for node in env.nodes:
        profile = env.profiles[node]
        posture = env.postures[node]
        neighbours = sorted(env.graph.neighbors(node)) if node in env.graph else []
        compromise = first_compromise.get(node)
        dossiers[node] = {
            "id": node,
            "archetype": profile.name,
            "truth_class": profile.truth_class,
            "traits": {trait: getattr(profile, trait) for trait in TRAITS},
            "airgapped": posture.airgapped,
            "cleanroom": posture.cleanroom,
            "honeypot": posture.honeypot,
            "patch_level": posture.patch_level,
            "monitored_by": [d.name for d in env._defenders_covering(node)],
            "neighbours": neighbours,
            "recruited": node in env.recruited,
            "compromise": compromise,
            "intel_gained": env.attacker_intel.get(node),
        }
    return dossiers


def _key_nodes(env: SwarmCompromiseEnv) -> list[dict[str, str]]:
    key: list[dict[str, str]] = []
    for node in env.nodes:
        posture = env.postures[node]
        if posture.honeypot:
            key.append({"id": node, "kind": "honeypot", "label": "HONEYPOT"})
        elif posture.airgapped:
            key.append({"id": node, "kind": "airgap", "label": "AIRGAP VAULT"})
    # Highest-degree public hub.
    if env.graph.number_of_edges():
        hub = max(env.graph.nodes, key=lambda n: env.graph.degree(n))
        key.append({"id": hub, "kind": "hub", "label": "COMMS HUB"})
    # Largest recruited coalition anchor.
    if env.recruited:
        anchor = sorted(env.recruited)[0]
        key.append({"id": anchor, "kind": "coalition", "label": "COALITION"})
    return key


def export_scenario(posture: str, hive_master_name: str, seed: int, config: SwarmCompromiseConfig) -> dict[str, object]:
    master = HIVE_MASTER_BY_NAME[hive_master_name]
    env = SwarmCompromiseEnv(posture=posture, hive_master=master, seed=seed, config=config)
    policy = ScriptedHiveMaster(master, seed=seed)
    frames: list[dict[str, object]] = []
    while env.round_index < config.rounds:
        current = env.round_index
        env.step(policy.act(env.hive_master_view()))
        frames.append(_frame(env, current))
    result = env.result()

    airgapped = {node for node in env.nodes if env.postures[node].airgapped}
    communities = max(1, config.communities)
    community_of = {node: env.nodes.index(node) % communities for node in env.nodes}
    # ground-level city blocks, one per community; airgapped units in a basement vault
    # under the middle block (authored presentation layout, see diorama.city_layout)
    layout = city_layout(
        [(f"community_{k}", "community", [n for n in env.nodes if community_of[n] == k and n not in airgapped])
         for k in range(communities)],
        seed,
        vault=(f"community_{1 if communities > 1 else 0}", [n for n in env.nodes if n in airgapped]),
    )
    positions = {node: layout["anchors"][node]["desk"] for node in env.nodes}
    nodes = []
    for node in env.nodes:
        profile = env.profiles[node]
        posture_obj = env.postures[node]
        nodes.append(
            {
                "id": node,
                "community": env.nodes.index(node) % max(1, config.communities),
                "pos": positions[node],
                "venue": "vault" if node in airgapped else f"community_{community_of[node]}",
                "archetype": profile.name,
                "truth_class": profile.truth_class,
                "airgapped": posture_obj.airgapped,
                "cleanroom": posture_obj.cleanroom,
                "honeypot": posture_obj.honeypot,
            }
        )
    edges = sorted([sorted(edge) for edge in env.graph.edges()])

    # Diorama enrichment (additive): a unified character + graded stress track per
    # node, and the exported day-cycle clock per frame.  The current viewer ignores
    # these fields; the diorama viewer animates them.
    for frame in frames:
        frame["clock"] = day_phase(frame["round"], config.rounds)
    dossiers = _dossiers(env)
    for node in env.nodes:
        posture_obj = env.postures[node]
        community = env.nodes.index(node) % max(1, config.communities)
        venue = "vault" if posture_obj.airgapped else ("decoy" if posture_obj.honeypot else f"community_{community}")
        character = from_swarm_profile(env.profiles[node], node, venue, node, seed)
        attempts = {event.round_index for event in env.events if event.target == node}
        compromise = dossiers[node].get("compromise")
        flip = compromise["round"] if compromise else None
        dossiers[node]["character"] = character.to_dict()
        dossiers[node]["track"] = {"pressure": pressure_series(config.rounds, attempts, flip), "flip_round": flip}

    return {
        "id": f"{posture} · {hive_master_name} · seed {seed}",
        "posture": posture,
        "hive_master": hive_master_name,
        "hive_master_capabilities": {
            vector: getattr(master, attribute)
            for vector, attribute in CAPABILITY_FOR_VECTOR.items()
        },
        "insider_access": master.insider_access,
        "seed": seed,
        "rounds": config.rounds,
        "population": config.population_size,
        "attacker_known_exported": True,   # per-frame attacker_known is the hive master's discovered set
        "layout": layout,
        "nodes": nodes,
        "edges": edges,
        "defenders": [{"name": d.name, "domain": list(d.domain)} for d in env.defenders],
        "frames": frames,
        "dossiers": dossiers,
        "key_nodes": _key_nodes(env),
        "result": {
            "compromise_rate": round(result.compromise_rate, 3),
            "compromised_count": result.compromised_count,
            "recruited_count": result.recruited_count,
            "largest_coalition": result.largest_coalition,
            "airgap_breach_count": result.airgap_breach_count,
            "airgapped_count": result.airgapped_count,
            "covert_exfil_units": round(result.covert_exfil_units, 2),
            "detection_recall": round(result.detection_recall, 3),
            "honeypot_hits": result.honeypot_hits,
        },
    }


def build_replay(
    scenarios: tuple[tuple[str, str, int], ...] = DEFAULT_SCENARIOS,
    config: SwarmCompromiseConfig | None = None,
) -> dict[str, object]:
    config = config or SwarmCompromiseConfig()
    archetypes = {
        profile.name: {
            "truth_class": profile.truth_class,
            "traits": {trait: getattr(profile, trait) for trait in TRAITS},
        }
        for profile in PROFILE_ARCHETYPES
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "spiral_ln.swarm_replay",
        "safety_note": (
            "Synthetic and abstract. Dossiers are scripted NPC trait vectors; "
            "cam feeds are stylized readouts of abstract in-sim intel, not "
            "surveillance of any real person. No model, network, or payload."
        ),
        "sims": ["swarm_compromise"],
        "safety_boundary": DioramaCharacter.safety_boundary(),
        "traits": list(TRAITS),
        "archetypes": archetypes,
        "scenarios": [export_scenario(p, h, s, config) for (p, h, s) in scenarios],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/swarm_compromise/replay.json")
    args = parser.parse_args(argv)
    replay = build_replay()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(replay), encoding="utf-8")
    sizes = ", ".join(
        f"{scenario['id']}: {scenario['result']['compromised_count']} compromised, "
        f"coalition {scenario['result']['largest_coalition']}, exfil {scenario['result']['covert_exfil_units']}"
        for scenario in replay["scenarios"]
    )
    print(f"wrote {path} ({path.stat().st_size} bytes)")
    print(sizes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
