import json

from spiral_ln import rtg_arena_export
from spiral_ln.diorama import SCHEMA_VERSION


def test_replay_is_schema_aligned_and_institutional():
    replay = rtg_arena_export.build_replay()
    assert replay["schema_version"] == SCHEMA_VERSION
    assert replay["sims"] == ["rtg"]
    assert replay["node_schema"] == "institution"  # buildings/accounts/agent, not people
    assert replay["safety_boundary"]["synthetic_only"] is True
    assert replay["scenarios"]


def test_frames_carry_the_day_clock_and_nodes_carry_venues():
    replay = rtg_arena_export.build_replay()
    for scenario in replay["scenarios"]:
        assert all("clock" in frame and "phase" in frame["clock"] for frame in scenario["frames"])
        assert all("venue" in node for node in scenario["nodes"])


def test_replay_is_byte_identical_across_runs():
    a = json.dumps(rtg_arena_export.build_replay(), sort_keys=True)
    b = json.dumps(rtg_arena_export.build_replay(), sort_keys=True)
    assert a == b
