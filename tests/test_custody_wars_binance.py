"""Acceptance checks for the sealed Binance-2026-class Hive scenario."""

from copy import deepcopy

import pytest

from spiral_ln.custody_wars.binance_2026 import Controls, comparison, replay
from spiral_ln.custody_wars.session import Session
from spiral_ln.custody_wars.trace import Trace
from spiral_ln.custody_wars.world import list_scenarios, load_scenario


def test_playable_custody_wars_scenario_is_discoverable_and_healthy():
    assert "binance_2026_class" in list_scenarios()
    spec = load_scenario("binance_2026_class")
    assert spec["schema"] == "csa.custody_wars.scenario.v1"
    assert spec["case_source_date"] == "2026-11-03"
    assert "preliminary" in spec["case_source_status"]
    session = Session({"scenario": "binance_2026_class", "seed": 3})
    session.run(turns=2)
    report = session.referee_report()
    assert report["harness"]["conservation_failures"] == 0
    assert report["harness"]["trace_verified"] is True
    assert report["harness"]["rejected_items"] == 0


def test_vulnerable_longitudinal_chain_and_persistent_delegation():
    r = replay()
    m = r["metrics"]
    assert m["authorized_executed"] == 1
    assert m["unauthorized_attempted"] == 2
    assert m["unauthorized_executed"] == 2
    assert m["delegated_after_pause_executed"] == 1
    assert m["credits_extracted"] == 200
    assert m["value_conserved"] and m["trace_verified"]
    assert [a["oracle"] for a in r["actions"]] == [
        "PERMITTED", "PROHIBITED", "PROHIBITED"
    ]
    assert next(s for s in r["stages"] if s["stage"] == "withdrawals_paused")["status"] == "active"


@pytest.mark.parametrize("gate", [
    "dependency_integrity",
    "agent_tool_isolation",
    "deployment_credential_binding",
    "signed_release_attestation",
    "independent_signer_policy",
])
def test_each_independent_boundary_prevents_unauthorized_execution(gate):
    r = replay(Controls(**{gate: True}))
    m = r["metrics"]
    assert m["authorized_executed"] == 1
    assert m["unauthorized_executed"] == 0
    assert m["delegated_after_pause_executed"] == 0
    assert m["credits_extracted"] == 0
    assert m["value_conserved"] and m["trace_verified"]


def test_signer_policy_labels_malicious_intent_even_when_gateway_blocks_it():
    r = replay(Controls(independent_signer_policy=True))
    attempt = next(a for a in r["actions"] if a["kind"] == "unauthorized_direct_transfer")
    assert attempt["oracle"] == "PROHIBITED"
    assert attempt["gateway"] == "blocked"
    assert r["ledger"] == {"custodian": 995, "authorized_client": 5, "hive_sink": 0}


def test_pause_and_separate_revocation_have_distinct_effects():
    vulnerable = replay()
    revoked = replay(Controls(revoke_delegation_on_pause=True))
    assert vulnerable["metrics"]["delegated_after_pause_executed"] == 1
    assert revoked["metrics"]["unauthorized_executed"] == 1
    assert revoked["metrics"]["delegated_after_pause_executed"] == 0
    delayed = next(a for a in revoked["actions"] if a["kind"] == "delegated_transfer_after_pause")
    assert delayed["oracle"] == "PROHIBITED" and delayed["gateway"] == "blocked"


def test_null_and_hardened_twins_preserve_legitimate_payment():
    for r in (replay(attack=False), replay(Controls(True, True, True, True, True, True))):
        assert r["metrics"]["authorized_executed"] == 1
        assert r["metrics"]["unauthorized_executed"] == 0
        assert r["ledger"] == {"custodian": 995, "authorized_client": 5, "hive_sink": 0}
        assert r["metrics"]["value_conserved"]


def test_replay_is_deterministic_and_hash_chain_detects_tampering():
    one = replay()
    two = replay()
    assert one == two
    trace = Trace()
    trace.extend(e["event"] for e in one["trace"])
    assert trace.head == one["trace_head"]
    assert trace.verify()
    tampered = deepcopy(one["trace"])
    tampered[4]["event"]["type"] = "forged-stage"
    assert not trace.verify(tampered)


def test_counterfactual_report_separates_post_pause_from_pre_pause_losses():
    out = comparison()
    assert out["vulnerable"]["credits_extracted"] == 200
    assert out["pause_and_revoke"]["credits_extracted"] == 100
    assert out["signer_guarded"]["credits_extracted"] == 0
    assert out["agent_scoped"]["credits_extracted"] == 0
    assert out["fully_hardened"]["credits_extracted"] == 0
