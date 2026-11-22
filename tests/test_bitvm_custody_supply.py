"""Custody Wars IMPLANT/SUPPLY/PHISH events as causes of BitVM host control."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict

import pytest

from spiral_ln import bitvm_custody_supply as cws
from spiral_ln import bitvm_ceremony as ceremony


def test_custody_world_has_five_distinct_host_nodes_and_real_supply_edges():
    state = cws._world(4, cws.CustodySupplyConfig())
    assert len(cws.HOST_NODES) == 5
    assert len(set(cws.HOST_NODES)) == 5
    assert all(state.nodes[host].type == "SIGNER_DESK" for host in cws.HOST_NODES)
    assert state.downstream("cust.ci") >= list(cws.HOST_NODES)
    assert all("cust.ci" in state.upstream(host) for host in cws.HOST_NODES)
    assert "cust.ci" in state.downstream("vendor.walletsw")
    assert state.compromise_level("vendor.walletsw") == "NONE"
    assert all(cws._authority(state, host)[0] is False for host in cws.HOST_NODES)


@pytest.mark.parametrize("recipe", cws.RECIPES)
def test_real_engine_resolves_each_recipe_and_receipts_replay(recipe):
    cfg = cws.CustodySupplyConfig(recipe=recipe, posture="exposed", turns=12)
    for seed in (0, 3):
        receipt = cws.custody_episode(seed, cfg)
        assert receipt["schema"] == cws.SCHEMA
        assert receipt["source_git_blobs"] == cws.SOURCE_BLOBS
        assert receipt["credit_conserved"] is True
        assert len(receipt["attempts"]) == 12
        assert len(receipt["historical_host_control"]) == 12
        assert cws.replay_custody_episode(receipt) == receipt
        for i in receipt["adversarial_compromised_hosts"]:
            assert i in range(5)
            assert receipt["host_control"][i]["controlled"] is True


def test_implant_effects_require_real_propagation_from_vendor_or_pipeline():
    cfg = cws.CustodySupplyConfig(recipe="vendor-implant", turns=24)
    total = 0
    for seed in range(5):
        receipt = cws.custody_episode(seed, cfg)
        assert all(
            item["declared"] == [] or
            all(order["type"] == "IMPLANT" and order["target"] == "vendor.walletsw"
                for order in item["declared"])
            for item in receipt["attempts"]
        )
        for index in receipt["adversarial_compromised_hosts"]:
            total += 1
            host = cws.HOST_NODES[index]
            assert receipt["host_control"][index]["cause"] == "implanted-host"
            assert any(event["target"] == host for event in receipt["supply_host_events"])
        assert all(level != "CREDENTIAL" for level in receipt["final_compromise_levels"].values())
    assert total > 0  # instrument positive control, not an intrusion estimate


def test_phishing_foothold_is_not_a_signing_capability():
    one_turn = cws.custody_episode(3, cws.CustodySupplyConfig(recipe="host-phishing", turns=1))
    assert one_turn["adversarial_compromised_hosts"] == []
    assert one_turn["supply_host_events"] == []


def test_full_hardening_prevents_reported_host_control_under_each_recipe():
    for recipe in cws.RECIPES:
        for seed in range(4):
            receipt = cws.custody_episode(
                seed, cws.CustodySupplyConfig(recipe=recipe, posture="full-hardening", turns=24)
            )
            assert receipt["adversarial_compromised_hosts"] == []
            assert all(not item["controlled"] for item in receipt["host_control"])


def test_source_alerts_are_visibility_based_and_can_flag_uncompromised_hosts():
    config = cws.CustodySupplyConfig(recipe="mixed", turns=20)
    for seed in range(5):
        receipt = cws.custody_episode(seed, config)
        # A source alert becomes a *risk indicator* through public dependency
        # edges, never a fact of compromise or an authoritative signer vote.
        assert all(
            set(row) == {"round", "host", "vector", "flagged"}
            for row in receipt["monitor_signals"]
        )
        assert all(type(row["flagged"]) is bool for row in receipt["monitor_signals"])
        assert all(0 <= row["host"] < 5 for row in receipt["monitor_signals"])
        assert set(receipt["adversarial_compromised_hosts"]) == {
            row["host"] for row in receipt["host_control"] if row["controlled"]
        }


@pytest.mark.parametrize("recipe", cws.RECIPES)
def test_original_game_events_feed_bitvm_ceremony_and_all_three_arms(recipe):
    for seed in (0, 2):
        cfg = cws.CustodySupplyConfig(recipe=recipe, turns=16)
        report = ceremony.run_session(
            "quorum-covert", seed, custody_config=cfg, run_nonce="c"*32
        )
        assert report["compromise_source"] == "custody-wars-causal"
        assert report["social_episode"] is None
        assert report["custody_episode"]["config"] == asdict(cfg)
        assert report["referee"]["compromised_hosts"] == report["custody_episode"]["adversarial_compromised_hosts"]
        assert report["referee"]["malicious_votes_after_quarantine"] == report["referee"]["compromised_hosts"]
        assert (
            report["arms"]["presigned-bitvm"]["effective_score"]["attacker_success"]
            == (len(report["referee"]["compromised_hosts"]) >= 3)
        )
        assert not report["arms"]["keyless-txcommit"]["effective_score"]["attacker_success"]
        assert ceremony.replay_session(report, expected_case="quorum-covert", expected_seed=seed) == report


def test_defender_alerts_cannot_access_hidden_host_control_and_quarantine_costs_remain_visible():
    cfg = cws.CustodySupplyConfig(recipe="mixed", turns=24)
    captured = []
    def monitor(request):
        captured.append(request["observation"])
        return ceremony.flagged_telemetry_decider(request)

    report = ceremony.run_session(
        "quorum-covert", 7, custody_config=cfg,
        deciders={ceremony.MONITOR: monitor},
        monitor_policy="observed-flags",
    )
    view = captured[0]
    assert view["social_telemetry"] == report["custody_episode"]["monitor_signals"]
    assert "adversarial_compromised_hosts" not in view
    assert "host_control" not in view
    assert "events" not in view
    flagged = sorted({
        signal["host"] for signal in view["social_telemetry"] if signal["flagged"]
    })
    assert report["monitor_decision"]["quarantine"] == flagged
    assert len(report["referee"]["false_positive_quarantines"]) <= len(flagged)
    assert ceremony.replay_session(report, expected_case="quorum-covert", expected_seed=7) == report


def test_custody_and_legacy_social_simulations_are_disjoint():
    from spiral_ln.bitvm_social_setup import SocialSetupConfig

    with pytest.raises(ValueError, match="one causal"):
        ceremony.run_session(
            "quorum-covert", 1,
            social_config=SocialSetupConfig(rounds=1),
            custody_config=cws.CustodySupplyConfig(turns=1),
        )


def test_receipt_with_forged_compromise_or_alerts_cannot_replay():
    cfg = cws.CustodySupplyConfig(recipe="mixed", turns=15)
    baseline = ceremony.run_session("quorum-covert", 5, custody_config=cfg, run_nonce="f"*32)
    for mutation in ("hosts", "alerts"):
        forged = copy.deepcopy(baseline)
        if mutation == "hosts":
            forged["custody_episode"]["adversarial_compromised_hosts"] = [0, 1, 2]
        else:
            forged["custody_episode"]["monitor_signals"].append({
                "round": 0, "host": 4, "vector": "SIGNER", "flagged": True
            })
        body = {k: v for k, v in forged.items() if k != "evidence_hash"}
        forged["evidence_hash"] = ceremony._digest({
            "domain": ceremony.DOMAIN + "/receipt", "body": body
        })
        with pytest.raises(ValueError, match="differs"):
            ceremony.replay_session(forged, expected_case="quorum-covert", expected_seed=5)


@pytest.mark.parametrize("kwargs", [
    {"recipe": "actual-phishing"},
    {"posture": "testnet"},
    {"turns": 0},
    {"turns": True},
    {"turns": 100},
])
def test_invalid_game_config_rejected(kwargs):
    with pytest.raises(ValueError):
        cws.CustodySupplyConfig(**kwargs)


def test_world_rule_code_must_match_pinned_source(monkeypatch):
    monkeypatch.setitem(cws.SOURCE_BLOBS, "engine", "0" * 40)
    with pytest.raises(RuntimeError, match="source hash"):
        cws.custody_episode(1, cws.CustodySupplyConfig(turns=1))



def test_matched_custody_sweep_replays_and_separates_safety_from_liveness():
    from spiral_ln.bitvm_custody_sweep import sweep

    report = sweep(seeds=3, turns=12)
    assert report["episodes"] == 3 * 2 * 2 * 2
    assert len(report["summary"]) == 8
    assert report["evidence_level"] == "synthetic-model"
    by_source = {}
    for row in report["rows"]:
        pair = (row["seed"], row["posture"])
        by_source.setdefault(pair, row["source_hash"])
        assert row["source_hash"] == by_source[pair]
        assert row["fallbacks"] == 0
        assert row["host_controls"] in range(6)
        assert row["presigned"]["authorized_sats"] + row["presigned"]["unauthorized_sats"] + row["presigned"]["escrow_sats"] == 100_000
        assert row["keyless"]["attacker_success"] is False
        if row["posture"] == "full-hardening":
            assert not row["quorum_reached"]
        if row["case"] == "quorum-covert" and not row["quorum_reached"]:
            assert row["presigned"]["attacker_success"] is False
    assert report == sweep(seeds=3, turns=12)


def test_custody_sweep_rejects_bad_configuration_and_overwrite(tmp_path):
    from spiral_ln.bitvm_custody_sweep import sweep

    invalid = (
        {"seeds": 0}, {"seeds": True}, {"seeds": 99},
        {"postures": ("exposed", "exposed")},
        {"monitors": ("invented",)}, {"turns": 500},
    )
    for changes in invalid:
        with pytest.raises(ValueError):
            sweep(**changes)

    directory = tmp_path / "custody-run"
    first = sweep(seeds=1, turns=5, output=directory)
    assert first["episodes"] == 8
    assert (directory / "summary.json").is_file()
    assert (directory / "receipts" / "0.exposed.passive.honest.json").is_file()
    with pytest.raises(ValueError, match="overwrite"):
        sweep(seeds=1, turns=5, output=directory)
