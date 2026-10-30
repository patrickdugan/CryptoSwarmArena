"""Acceptance tests for the purely synthetic repo-contagion instrument."""

import json
from dataclasses import replace

import pytest

from spiral_ln.repo_worm_alife import (
    CONFIG_SCHEMA, POSTURES, Config, build_graph, campaign, emit, run_episode,
    safety_boundary, verify,
)


def small_spec():
    return {
        "schema_version": CONFIG_SCHEMA,
        "design": dict(population_size=20, communities=2, rounds=12, intra_link=0.45,
                       inter_link=0.10, contacts_per_round=3, infectious_rounds=4,
                       benign_events_per_round=4, base_adoption=0.9),
        "seeds": [1, 2, 3, 4],
        "postures": list(POSTURES),
        "inference_modes": ["local", "remote"],
    }


def test_deterministic_seed_graph_and_log_chain():
    config = Config(**small_spec()["design"])
    left = run_episode(config, 42, "baseline_open", retain_events=True)
    right = run_episode(config, 42, "baseline_open", retain_events=True)
    assert left == right
    assert left.metrics["accounting_ok"]
    assert left.metrics["graph_edges"] == sum(map(len, left.graph)) // 2
    assert len(left.events) == left.metrics["ledger_events"]
    assert all(event["kind"] in {"marker", "benign"} for event in left.events)
    assert all(not any(key in event for key in ("payload", "prompt", "command", "url", "script")) for event in left.events)


def test_synthetic_only_boundary():
    assert all(value is False for key, value in safety_boundary().items() if key != "synthetic_only")
    assert safety_boundary()["synthetic_only"]


def test_graph_keeps_undirected_contacts_and_same_seed_across_postures():
    config = Config(**small_spec()["design"])
    graph = build_graph(config, 8)
    for i, neighbors in enumerate(graph):
        assert i not in neighbors
        for j in neighbors:
            assert i in graph[j]
    a = run_episode(config, 8, "baseline_open")
    b = run_episode(config, 8, "human_review")
    assert a.graph == b.graph
    assert a.metrics["graph_sha256"] == b.metrics["graph_sha256"]


def test_inference_modes_share_exact_behavior_but_differ_in_hypothetical_egress():
    config = Config(**small_spec()["design"])
    local = run_episode(config, 10, "provenance_gate", "local")
    remote = run_episode(config, 10, "provenance_gate", "remote")
    shared = ("graph_sha256", "lineage_sha256", "secondary_adoptions", "marker_contacts",
              "marker_detected", "false_alarms", "reproduction_observed", "abstract_inference_work_units")
    for field in shared:
        assert local.metrics[field] == remote.metrics[field]
    assert local.metrics["simulated_external_inference_bytes"] == 0
    assert local.metrics["simulated_external_inference_calls"] == 0
    assert remote.metrics["simulated_external_inference_calls"] == remote.metrics["ledger_events"]
    assert remote.metrics["simulated_external_inference_bytes"] > 0


def test_benign_null_and_false_alarm_denominator():
    config = replace(Config(**small_spec()["design"]), base_adoption=0.0)
    result = run_episode(config, 1, "human_review")
    assert result.metrics["secondary_adoptions"] == 0
    assert result.metrics["carrying_total"] == config.initial_markers
    assert result.metrics["benign_contacts"] == config.rounds * config.benign_events_per_round
    assert result.metrics["benign_false_alarm_rate"] is not None
    assert result.metrics["accounting_ok"]


def test_zero_link_null_no_invented_reproduction():
    config = replace(Config(**small_spec()["design"]), intra_link=0.0, inter_link=0.0)
    trial = run_episode(config, 2, "baseline_open")
    assert trial.metrics["graph_edges"] == 0
    assert trial.metrics["marker_contacts"] == 0
    assert trial.metrics["secondary_adoptions"] == 0
    assert trial.metrics["marker_detection_recall"] is None
    assert trial.metrics["reproduction_observed"] == 0


def test_validation_rejects_oversized_or_invalid_inputs():
    with pytest.raises(ValueError):
        Config(population_size=10000)
    with pytest.raises(ValueError):
        Config(rounds=-1)
    with pytest.raises(ValueError):
        Config(intra_link=float("nan"))
    with pytest.raises(ValueError):
        Config(initial_markers=32)
    with pytest.raises(ValueError):
        run_episode(Config(), 1, "unknown")
    spec = small_spec()
    spec["seeds"] = [1, 1]
    with pytest.raises(ValueError):
        campaign(spec)


def test_reproducible_campaign_and_matched_seed_comparisons():
    spec = small_spec()
    left, stats = campaign(spec)
    right, again = campaign(spec)
    assert left == right
    assert stats == again
    assert len(left) == 4 * 4 * 2
    assert all(ep.metrics["accounting_ok"] for ep in left)
    assert stats["paired_vs_baseline"]["local/human_review"]["delta_secondary_adoptions"]["n"] == 4


def test_emit_verify_detects_tampering(tmp_path):
    spec = small_spec()
    out = tmp_path / "evidence"
    emit(spec, out, retain_events=True)
    assert verify(out)
    event_path = out / "local_baseline_open_seed1.jsonl"
    original = event_path.read_text()
    event_path.write_text(original + '{"fake":true}\n')
    assert not verify(out)
    event_path.write_text(original)
    assert verify(out)
    summary_path = out / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["paired_vs_baseline"] = {}
    summary_path.write_text(json.dumps(summary))
    assert not verify(out)
