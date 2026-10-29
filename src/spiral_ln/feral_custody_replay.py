"""Export a sealed feral-custody episode as a diorama replay for the arena viewer.

This runs the ordinary scripted custody episode and writes a self-contained JSON
replay in the shared diorama schema (schema_version 2.0): nodes with a
deterministic 3D venue layout, a per-epoch event timeline, ``DioramaCharacter``
dossiers, each character's graded per-epoch stress trajectory, and the exported
day-cycle clock.  It adds no capability and keeps the swarm-replay field shape
(nodes/edges/frames/dossiers/key_nodes/result) so the existing viewer opens it.

Sealed and synthetic: characters are scripted parameter vectors, not real people;
there is no model call, network, real key material, or persuasion content, and the
hidden ``truth_class`` validation label is never placed in an attacker-visible
node field (it lives only in the researcher dossier).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import diorama
from .diorama import SAFETY_NOTE, SCHEMA_VERSION, city_layout, day_phase, from_custody_persona, pressure_series
from .feral_custody import (
    FeralCustodyEnv,
    build_custody_config,
    default_adversary,
    strategy_reassembles,
)
from .swarm_compromise import PROFILE_ARCHETYPES, TRAITS

# Curated scenarios chosen to showcase distinct custody dynamics.  Each is
# (strategy, objective, bribery_budget, seed, overrides).
DEFAULT_SCENARIOS: tuple[tuple[str, str, int, int, dict], ...] = (
    ("enclave", "key_extraction", 60_000, 1, {}),
    ("obfuscation", "key_extraction", 60_000, 1, {}),
    ("loyalist", "key_extraction", 60_000, 1, {}),
    ("threshold_signing", "coerced_signing", 40_000, 1, {"legal_pressure": 0.8}),
)

VENUE_BY_ROLE: dict[str, str] = {
    "host": "operations",
    "enclave_operator": "enclave_datacenter",
    "shard_holder": "shard_holders",
    "gig_worker": "gig_shopfront",
    "loyalist": "loyalist_hall",
}
_VENUE_ORDER = ("operations", "enclave_datacenter", "shard_holders", "gig_shopfront", "loyalist_hall")


def _edges(personas) -> list[list[str]]:
    host = next((p for p in personas if p.role in ("host",)), None)
    shards = [p for p in personas if p.role in ("shard_holder", "loyalist", "gig_worker")]
    edges: list[list[str]] = []
    if host is not None:  # star: each shard/worker links to the reassembly host
        for shard in shards:
            edges.append(sorted([host.id, shard.id]))
    hosts = [p for p in personas if p.role == "host"]
    for i in range(len(hosts)):  # threshold hosts form a ring among themselves
        for j in range(i + 1, len(hosts)):
            edges.append(sorted([hosts[i].id, hosts[j].id]))
    unique = {tuple(edge) for edge in edges}
    return sorted(list(edge) for edge in unique)


def _frame(env, epoch: int, horizon: int) -> dict[str, object]:
    events = [
        {"actor": e.actor, "kind": e.kind, "target": e.target, "amount": e.amount, "success": e.success}
        for e in env.events if e.epoch == epoch
    ]
    return {
        "round": epoch,
        "clock": day_phase(epoch, horizon),
        "events": events,
        "compromised": sorted(env.defected),
        "recruited": [],
        "burned": [],
        "detected": [],
        "attacker_known": [],
        "exfil_total": round(float(env.stolen_total), 2),
        "funds": env.funds,
        "extraction_events": env.extraction_events,
        "denial_events": env.denial_events,
        "coerced_signatures": env.coerced_signatures,
        "key_compromised": env.key_compromised,
    }


def _character_tracks(env, horizon: int) -> dict[str, dict[str, object]]:
    """Per-persona flip frame and the frames on which they were pressed."""
    flip: dict[str, int] = {}
    attempts: dict[str, set] = {p.id: set() for p in env.config.personas}
    for e in env.events:
        if e.kind == "defection" and e.actor in attempts and e.actor not in flip:
            flip[e.actor] = e.epoch
        if e.kind in ("bribe", "coerced_signature") and e.target in attempts:
            attempts[e.target].add(e.epoch)
        if e.kind == "defection" and e.actor in attempts:
            attempts[e.actor].add(e.epoch)
    tracks: dict[str, dict[str, object]] = {}
    for persona in env.config.personas:
        tracks[persona.id] = {
            "pressure": pressure_series(horizon, attempts[persona.id], flip.get(persona.id)),
            "flip_round": flip.get(persona.id),
        }
    return tracks


def export_scenario(strategy: str, objective: str, budget: int, seed: int, overrides: dict) -> dict[str, object]:
    config = build_custody_config(strategy, seed=seed, **overrides)
    adversary = default_adversary(objective, budget)
    env = FeralCustodyEnv(config, adversary, seed=seed)
    horizon = config.epochs
    frames: list[dict[str, object]] = []
    while env.epoch < horizon:
        current = env.epoch
        env.step()
        frames.append(_frame(env, current, horizon))
    result = env.result()

    personas = list(config.personas)
    # ground-level city blocks per venue; the enclave operator works in a sealed
    # basement under the datacenter block (authored presentation layout)
    venue_of = {p.id: VENUE_BY_ROLE.get(p.role, "operations") for p in personas}
    present = [v for v in _VENUE_ORDER if v in venue_of.values()]
    vault_ids = [p.id for p in personas if p.role == "enclave_operator"]
    layout = city_layout(
        [(v, v, [p.id for p in personas if venue_of[p.id] == v and p.id not in vault_ids]) for v in present],
        seed,
        vault=("enclave_datacenter", vault_ids),
    )
    positions = {p.id: layout["anchors"][p.id]["desk"] for p in personas}
    tracks = _character_tracks(env, horizon)
    nodes: list[dict[str, object]] = []
    dossiers: dict[str, dict[str, object]] = {}
    for index, persona in enumerate(personas):
        venue = VENUE_BY_ROLE.get(persona.role, "operations")
        character = from_custody_persona(persona, venue=venue, station=f"{persona.role}-{index}", seed=seed)
        nodes.append({
            "id": persona.id,
            "community": _VENUE_ORDER.index(venue),
            "pos": positions[persona.id],
            "archetype": character.archetype,
            "role": persona.role,
            "venue": venue,
            "airgapped": persona.role == "enclave_operator",
            "cleanroom": False,
            "honeypot": False,
        })
        dossier = character.to_dict()  # researcher dossier (carries truth_class)
        dossier["track"] = tracks[persona.id]
        dossiers[persona.id] = dossier

    key_nodes: list[dict[str, str]] = []
    for persona in personas:
        if persona.role == "enclave_operator":
            key_nodes.append({"id": persona.id, "kind": "enclave", "label": "TEE ENCLAVE"})
        elif persona.role == "host" and strategy_reassembles(strategy):
            key_nodes.append({"id": persona.id, "kind": "reassembly", "label": "REASSEMBLY HOST"})

    return {
        "id": f"{strategy} · {objective} · seed {seed}",
        "sim": "feral_custody",
        "strategy": strategy,
        "objective": objective,
        "bribery_budget": budget,
        "seed": seed,
        "rounds": horizon,
        "epochs": horizon,
        "population": len(personas),
        "attacker_known_exported": False,   # the custody sim has no discovery model; attacker_known is always empty
        "layout": layout,
        "reassembles": strategy_reassembles(strategy),
        "reassembly_windows": [{"epoch": w.epoch, "host": w.host} for w in env.reassembly_windows()],
        "nodes": nodes,
        "edges": _edges(personas),
        "defenders": [],
        "frames": frames,
        "dossiers": dossiers,
        "key_nodes": key_nodes,
        "result": result.to_dict(),
    }


def build_replay(scenarios: tuple = DEFAULT_SCENARIOS) -> dict[str, object]:
    archetypes = {
        profile.name: {"truth_class": profile.truth_class, "traits": {t: getattr(profile, t) for t in TRAITS}}
        for profile in PROFILE_ARCHETYPES
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "spiral_ln.feral_custody_replay",
        "safety_note": SAFETY_NOTE,
        "sims": ["feral_custody"],
        "traits": list(TRAITS),
        "archetypes": archetypes,
        "safety_boundary": diorama.DioramaCharacter.safety_boundary(),
        "scenarios": [export_scenario(s, o, b, seed, ov) for (s, o, b, seed, ov) in scenarios],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/feral_custody/replay.json")
    args = parser.parse_args(argv)
    replay = build_replay()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(replay), encoding="utf-8")
    print(f"wrote {path} ({path.stat().st_size} bytes)")
    for scenario in replay["scenarios"]:
        r = scenario["result"]
        print(f"  {scenario['id']}: funds_retained={r['funds_retained']} extraction={r['extraction_events']} coerced={r['coerced_signatures']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
