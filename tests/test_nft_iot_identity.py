"""Offline acceptance tests for the matched NFT/registry synthetic scenario."""
from spiral_ln.nft_iot_identity import ATTACKS, ARMS, fixture, decide, run


def test_all_fixtures_have_paired_arms():
    report = run()
    assert len(report["rows"]) == len(ATTACKS) * len(ARMS) == 24
    assert {r["arm"] for r in report["rows"]} == set(ARMS)


def test_no_tokenized_security_bonus():
    report = run()
    for name in ATTACKS:
        left = decide(fixture(name), "nft").copy()
        right = decide(fixture(name), "registry").copy()
        left.pop("arm")
        right.pop("arm")
        assert left == right


def test_revocation_and_replay_fail_closed():
    for name in ("revoked_key", "replayed_measurement", "device_clone", "counter_rollback"):
        for arm in ARMS:
            assert not decide(fixture(name), arm)["gateway_accepted"]


def test_hardware_truth_stays_distinct_from_signatures():
    for arm in ARMS:
        outcome = decide(fixture("valid_key_false_measurement"), arm)
        assert outcome["gateway_accepted"] and outcome["undetected_fraud"]
        assert outcome["fraud_credits"] == 400


def test_fraudulent_authorized_service():
    for arm in ARMS:
        outcome = decide(fixture("valid_maintenance_fraud"), arm)
        assert outcome["undetected_fraud"] and outcome["fraud_credits"] == 20


def test_consensus_outage_is_availability_failure():
    for arm in ARMS:
        outcome = decide(fixture("consensus_outage"), arm)
        assert outcome["availability_failure"]
        assert not outcome["undetected_fraud"]


def test_hash_is_stable():
    assert run() == run()
