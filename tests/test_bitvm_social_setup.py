"""Causal social compromise → five-host ceremony → BitVMArena settlement.

These tests deliberately use the existing seeded SwarmCompromiseEnv. Source
event states, defender observations and actual voted quorum remain distinct.
"""

from __future__ import annotations

import copy
from dataclasses import asdict

import pytest

from spiral_ln import bitvm_social_setup as social
from spiral_ln.bitvm_ceremony import (
    DOMAIN, MONITOR, _digest, replay_session, run_session, scripted_decider,
)


@pytest.mark.parametrize("recipe", tuple(social.VECTOR_RECIPES))
def test_each_social_vector_is_resolved_by_the_existing_engine(recipe):
    settings = social.SocialSetupConfig(recipe=recipe, rounds=15)
    report = social.social_episode(seed=13, config=settings)
    assert report["evidence_level"] == "synthetic-model"
    assert report["schema"] == social.SCHEMA
    assert report["source_git_blob"] == social.SWARM_SOURCE_GIT_BLOB
    assert report["host_nodes"] == list(social.HOST_NODE_IDS)
    assert report["result"]["accounting_ok"] is True
    assert report["result"]["attempts"] == len(report["events"])
    assert report["result"]["rounds"] == 15
    assert report["config"] == asdict(settings)
    assert social.replay_social_episode(report) == report
    assert sorted(report["adversarial_compromised_hosts"]) == report["adversarial_compromised_hosts"]
    for idx in report["landed_host_indices"]:
        assert idx in range(5)
        assert any(event["target"] == f"N{idx:02d}" for event in report["landed_host_events"])


def test_attempts_and_passive_exfil_do_not_grant_signing_authority():
    for seed in range(6):
        settings = social.SocialSetupConfig(recipe="passive-leak", rounds=20)
        report = social.social_episode(seed, settings)
        assert report["attempts"]
        assert not report["landed_host_indices"]
        assert not report["adversarial_compromised_hosts"]
        assert all(event["vector"] == "emanation_tap" for event in report["events"])
        arena = run_session("quorum-covert", seed, social_config=settings)
        assert arena["referee"]["compromised_hosts"] == []
        assert arena["arms"]["presigned-bitvm"]["effective_score"]["unauthorized_sats"] == 0


def test_compromise_must_be_a_landed_event_not_a_suspicious_alert():
    settings = social.SocialSetupConfig(recipe="mixed", rounds=28)
    for seed in range(9):
        report = social.social_episode(seed, settings)
        causes = {
            social.HOST_NODE_IDS.index(e["target"])
            for e in report["landed_host_events"]
        }
        assert causes == set(report["landed_host_indices"])
        assert set(report["adversarial_compromised_hosts"]) == causes
        assert all(item["host"] in range(5) and type(item["flagged"]) is bool
                   for item in report["monitor_signals"])


def test_social_compromises_drive_signing_threshold_across_all_arms():
    settings = social.SocialSetupConfig(recipe="mixed", rounds=30)
    for seed in range(8):
        report = run_session("quorum-covert", seed, social_config=settings, run_nonce="a"*32)
        compromised = report["referee"]["compromised_hosts"]
        active_votes = report["referee"]["malicious_votes_after_quarantine"]
        assert report["compromise_source"] == "social-vector-causal"
        assert compromised == report["social_episode"]["adversarial_compromised_hosts"]
        assert active_votes == compromised  # reference host agent always votes when controlled
        expected = len(active_votes) >= 3
        assert report["arms"]["presigned-bitvm"]["effective_score"]["attacker_success"] == expected
        assert report["arms"]["keyless-txcommit"]["effective_score"]["attacker_success"] is False
        assert replay_session(report, expected_case="quorum-covert", expected_seed=seed) == report


def test_social_source_is_pinned_by_blob_hash(monkeypatch):
    monkeypatch.setattr(social, "SWARM_SOURCE_GIT_BLOB", "0" * 40)
    with pytest.raises(RuntimeError, match="source changed"):
        social.social_episode(5, social.SocialSetupConfig())


def test_authorized_control_is_a_benign_confound_even_if_landed():
    settings = social.SocialSetupConfig(hive_master="authorized_red_team", recipe="mixed", rounds=45)
    report = social.social_episode(5, settings)
    assert report["master_truth_class"] == "benign_authorized_confound"
    assert report["adversarial_compromised_hosts"] == []
    game = run_session("quorum-covert", 5, social_config=settings)
    assert game["referee"]["compromised_hosts"] == []
    assert game["arms"]["presigned-bitvm"]["effective_score"]["unauthorized_sats"] == 0


def test_full_cleanroom_suppresses_passive_leak_without_cracking_signers():
    settings = social.SocialSetupConfig(posture="full_hardening", recipe="passive-leak", rounds=40)
    report = social.social_episode(17, settings)
    assert report["result"]["covert_exfil_units"] == 0
    assert report["adversarial_compromised_hosts"] == []


def test_monitor_only_sees_observer_trace_not_true_landing_results():
    settings = social.SocialSetupConfig(recipe="mixed", rounds=28)
    observed = []
    def inspect(req):
        observed.append(req["observation"])
        return scripted_decider(req)

    report = run_session("quorum-covert", 3, social_config=settings, deciders={MONITOR: inspect})
    view = observed[0]
    expected = report["social_episode"]["monitor_signals"]
    assert view["social_telemetry"] == expected
    assert "compromised_hosts" not in view
    assert "landed_host_indices" not in view
    assert "events" not in view
    assert "seed" not in view
    assert all(set(t) == {"round", "host", "vector", "flagged"} for t in view["social_telemetry"])


def test_observed_flag_monitor_can_quarantine_without_hidden_truth():
    settings = social.SocialSetupConfig(recipe="mixed", rounds=35)
    for seed in range(4):
        baseline = run_session("quorum-covert", seed, social_config=settings,
                               monitor_policy="passive")
        triage = run_session("quorum-covert", seed, social_config=settings,
                             monitor_policy="observed-flags")
        assert triage["referee"]["compromised_hosts"] == baseline["referee"]["compromised_hosts"]
        visible_alerts = {t["host"] for t in triage["social_episode"]["monitor_signals"] if t["flagged"]}
        assert set(triage["monitor_decision"]["quarantine"]) == visible_alerts
        assert triage["arms"]["presigned-bitvm"]["effective_score"]["unauthorized_sats"] <= (
            baseline["arms"]["presigned-bitvm"]["effective_score"]["unauthorized_sats"]
        )
        assert replay_session(triage, expected_case="quorum-covert", expected_seed=seed) == triage


def test_social_report_tampering_is_rejected_after_forged_receipt_hash():
    original = run_session("quorum-covert", 2, social_config=social.SocialSetupConfig(rounds=30))
    forged = copy.deepcopy(original)
    forged["social_episode"]["adversarial_compromised_hosts"] = [0, 1, 2]
    body = {key: val for key, val in forged.items() if key != "evidence_hash"}
    forged["evidence_hash"] = _digest({"domain": DOMAIN + "/receipt", "body": body})
    with pytest.raises(ValueError, match="differs"):
        replay_session(forged, expected_case="quorum-covert", expected_seed=2)


@pytest.mark.parametrize("fields", [
    {"posture": "unknown"},
    {"recipe": "malware-exploit"},
    {"hive_master": "unknown"},
    {"rounds": 0},
    {"rounds": True},
    {"rounds": 1000},
])
def test_invalid_social_settings_fail_closed(fields):
    with pytest.raises(ValueError):
        social.SocialSetupConfig(**fields)


def test_synthetic_sweep_results_are_reproducible_from_fixed_seed_and_nonce():
    settings = social.SocialSetupConfig(recipe="mixed", rounds=28)
    same1 = run_session("quorum-covert", 12, social_config=settings, run_nonce="e"*32)
    same2 = run_session("quorum-covert", 12, social_config=settings, run_nonce="e"*32)
    assert same1 == same2
    assert same1["event_chain"] == same2["event_chain"]
    assert same1["evidence_hash"] == same2["evidence_hash"]
