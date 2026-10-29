import json

from spiral_ln import feral_custody_replay
from spiral_ln.diorama import SCHEMA_VERSION


def test_replay_builds_with_expected_schema():
    replay = feral_custody_replay.build_replay()
    assert replay["schema_version"] == SCHEMA_VERSION
    assert replay["generator"] == "spiral_ln.feral_custody_replay"
    assert replay["safety_note"]
    assert replay["scenarios"]
    for scenario in replay["scenarios"]:
        assert scenario["nodes"] and scenario["frames"] and scenario["dossiers"]
        assert len(scenario["frames"]) == scenario["rounds"]
        # every frame carries the exported day-cycle clock
        assert all("clock" in frame and "phase" in frame["clock"] for frame in scenario["frames"])


def test_replay_is_byte_identical_across_runs():
    a = json.dumps(feral_custody_replay.build_replay(), sort_keys=True)
    b = json.dumps(feral_custody_replay.build_replay(), sort_keys=True)
    assert a == b


def test_nodes_never_expose_truth_class_but_dossiers_do():
    replay = feral_custody_replay.build_replay()
    for scenario in replay["scenarios"]:
        for node in scenario["nodes"]:
            assert "truth_class" not in node  # attacker-facing render object
        for dossier in scenario["dossiers"].values():
            assert "truth_class" in dossier  # researcher dossier


def test_reassembly_windows_present_only_for_reassembling_strategies():
    replay = feral_custody_replay.build_replay()
    for scenario in replay["scenarios"]:
        if scenario["reassembles"]:
            assert scenario["reassembly_windows"]
        else:
            assert scenario["reassembly_windows"] == []


def test_result_accounting_holds_in_every_scenario():
    replay = feral_custody_replay.build_replay()
    for scenario in replay["scenarios"]:
        assert scenario["result"]["accounting_ok"] is True


def test_character_tracks_pin_pressure_at_flip():
    replay = feral_custody_replay.build_replay()
    for scenario in replay["scenarios"]:
        for dossier in scenario["dossiers"].values():
            track = dossier["track"]
            series = track["pressure"]
            assert len(series) == scenario["rounds"]
            assert all(0.0 <= v <= 1.0 for v in series)
            if track["flip_round"] is not None:
                assert series[track["flip_round"]] == 1.0


def test_personas_stand_on_their_exported_city_layout():
    replay = feral_custody_replay.build_replay()
    for scenario in replay["scenarios"]:
        layout = scenario["layout"]
        for node in scenario["nodes"]:
            assert node["pos"] == layout["anchors"][node["id"]]["desk"]
            if node["role"] == "enclave_operator":
                assert node["pos"][1] == layout["vault_y"]
