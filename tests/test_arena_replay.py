import json

from spiral_ln import arena_replay
from spiral_ln.diorama import SCHEMA_VERSION


def test_combined_spans_all_three_sims():
    replay = arena_replay.build_combined()
    assert replay["schema_version"] == SCHEMA_VERSION
    assert replay["sims"] == ["swarm_compromise", "feral_custody", "rtg"]
    sims = {s["sim"] for s in replay["scenarios"]}
    assert sims == {"swarm_compromise", "feral_custody", "rtg"}
    for scenario in replay["scenarios"]:
        assert scenario["traits"] and scenario["nodes"] and scenario["frames"]
    assert replay["safety_note"]
    assert replay["safety_boundary"]["synthetic_only"] is True


def test_each_sim_keeps_its_own_trait_schema():
    replay = arena_replay.build_combined()
    by_sim = {}
    for scenario in replay["scenarios"]:
        by_sim.setdefault(scenario["sim"], scenario["traits"])
    assert "authority_deference" in by_sim["swarm_compromise"]
    assert "authority_deference" in by_sim["feral_custody"]   # grafted human traits
    assert "value" in by_sim["rtg"] and "authority_deference" not in by_sim["rtg"]


def test_combined_is_byte_identical_across_runs():
    a = json.dumps(arena_replay.build_combined(), sort_keys=True)
    b = json.dumps(arena_replay.build_combined(), sort_keys=True)
    assert a == b


def test_each_scenario_declares_whether_attacker_known_is_exported():
    replay = arena_replay.build_combined()
    for scenario in replay["scenarios"]:
        assert isinstance(scenario["attacker_known_exported"], bool)
        if scenario["sim"] == "feral_custody":
            assert scenario["attacker_known_exported"] is False   # no discovery model: sets are always empty
            assert all(not f["attacker_known"] for f in scenario["frames"])
        else:
            assert scenario["attacker_known_exported"] is True
