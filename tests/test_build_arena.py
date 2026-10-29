"""Build smoke: the real build_arena.py inlines a replay into a self-contained
page whose embedded JSON parses and carries every sim's scenarios.

This exercises the Python build pipeline and the page's data contract. It does
not execute the three.js/WebGL render (that needs a browser and is verified
interactively); it guarantees the page is well-formed and the replay is intact.
"""

import importlib.util
import json
import re
from pathlib import Path

from spiral_ln import arena_replay

REPO = Path(__file__).resolve().parents[1]
ARENA = REPO / "ui" / "arena"


def _build_arena_module():
    spec = importlib.util.spec_from_file_location("build_arena", ARENA / "build_arena.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_arena_inlines_and_the_page_parses_the_replay(tmp_path):
    replay = arena_replay.build_combined()
    replay_path = tmp_path / "replay.json"
    replay_path.write_text(json.dumps(replay), encoding="utf-8")
    out = tmp_path / "arena.html"

    _build_arena_module().main([
        "--template", str(ARENA / "index.template.html"),
        "--replay", str(replay_path),
        "--out", str(out),
    ])

    html = out.read_text(encoding="utf-8")
    assert "__REPLAY_JSON__" not in html                      # placeholder substituted
    match = re.search(r'id="replay-data"[^>]*>(.*?)</script>', html, re.S)
    assert match, "embedded replay script not found"
    embedded = json.loads(match.group(1))                      # the page's JSON parses
    assert len(embedded["scenarios"]) == len(replay["scenarios"]) > 0
    assert set(embedded["sims"]) == {"swarm_compromise", "feral_custody", "rtg"}
    # the three.js library and the scene bootstrap are present
    assert "three.min.js" in html and "buildScenario(REPLAY.scenarios[0])" in html


def test_built_page_carries_no_spiral_branding(tmp_path):
    replay = arena_replay.build_combined()
    replay_path = tmp_path / "replay.json"
    replay_path.write_text(json.dumps(replay), encoding="utf-8")
    out = tmp_path / "arena.html"
    _build_arena_module().main(["--template", str(ARENA / "index.template.html"), "--replay", str(replay_path), "--out", str(out)])
    html = out.read_text(encoding="utf-8")
    assert "SPIRAL" not in html and "Spiral" not in html
    assert "HIVE SWARM" in html
