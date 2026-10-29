"""Combined diorama replay: all three sims' scenarios in one arena page.

Merges the swarm-compromise, feral-custody, and RTG replays into a single
schema-2.0 replay whose scenario list spans all three sims, so the viewer's
scenario selector hops between them.  Each sim keeps its own trait schema
(people vs institutions), carried per scenario as ``traits`` so the inspector
labels each dossier correctly.

Read-only and deterministic: it just concatenates the three ``build_replay``
outputs; it runs no new simulation and adds no capability.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import feral_custody_replay, rtg_arena_export, swarm_replay
from .diorama import SCHEMA_VERSION, DioramaCharacter


def build_combined() -> dict:
    swarm = swarm_replay.build_replay()
    feral = feral_custody_replay.build_replay()
    rtg = rtg_arena_export.build_replay()

    scenarios: list[dict] = []
    for replay, sim in ((swarm, "swarm_compromise"), (feral, "feral_custody"), (rtg, "rtg")):
        traits = replay.get("traits")
        for scenario in replay["scenarios"]:
            merged = dict(scenario)
            merged["sim"] = merged.get("sim") or sim
            merged["traits"] = traits
            scenarios.append(merged)

    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "spiral_ln.arena_replay",
        "title": "◇ HIVE SWARM // DIORAMA",
        "vision_label": "Diorama // social-engineering surface",
        "safety_note": swarm["safety_note"],
        "sims": ["swarm_compromise", "feral_custody", "rtg"],
        "safety_boundary": DioramaCharacter.safety_boundary(),
        "traits": swarm["traits"],          # default; per-scenario traits override it
        "archetypes": swarm["archetypes"],
        "scenarios": scenarios,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/arena/replay.json")
    args = parser.parse_args(argv)
    replay = build_combined()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(replay), encoding="utf-8")
    print(f"wrote {path} ({path.stat().st_size} bytes) — {len(replay['scenarios'])} scenarios across {len(replay['sims'])} sims")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
