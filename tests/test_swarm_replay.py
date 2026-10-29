import json

from spiral_ln import swarm_replay
from spiral_ln.diorama import SCHEMA_VERSION


def test_replay_is_enriched_and_versioned():
    replay = swarm_replay.build_replay()
    assert replay["schema_version"] == SCHEMA_VERSION
    assert replay["sims"] == ["swarm_compromise"]
    assert replay["safety_boundary"]["synthetic_only"] is True
    assert replay["scenarios"]


def test_every_dossier_carries_a_character_and_track():
    replay = swarm_replay.build_replay()
    for scenario in replay["scenarios"]:
        rounds = scenario["rounds"]
        assert all("clock" in frame for frame in scenario["frames"])
        for dossier in scenario["dossiers"].values():
            character = dossier["character"]
            assert character["display_name"] and set(character["traits"])
            track = dossier["track"]
            assert len(track["pressure"]) == rounds
            assert all(0.0 <= v <= 1.0 for v in track["pressure"])
            if track["flip_round"] is not None:
                assert track["pressure"][track["flip_round"]] == 1.0


def test_replay_is_byte_identical_across_runs():
    a = json.dumps(swarm_replay.build_replay(), sort_keys=True)
    b = json.dumps(swarm_replay.build_replay(), sort_keys=True)
    assert a == b


def test_nodes_stand_on_their_exported_city_layout():
    replay = swarm_replay.build_replay()
    for scenario in replay["scenarios"]:
        layout = scenario["layout"]
        for node in scenario["nodes"]:
            assert node["pos"] == layout["anchors"][node["id"]]["desk"]
            assert node["pos"][1] == (layout["vault_y"] if node["airgapped"] else layout["ground_y"])
