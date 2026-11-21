"""Sealed multi-agent BitVM campaign; no network assets or real attackers."""

from __future__ import annotations

import copy
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from spiral_ln.bitvm_ceremony import (
    DOMAIN, HOSTS, MONITOR, SCHEMA, SEATS, WebhookDecider,
    _digest, _request, _validate, replay_session, run_session, scripted_decider,
)
from spiral_ln.bitvm_ceremony_bridge import (
    answer, anthropic_decision, config_from_env, make_bridge, validate_request,
)
from spiral_ln.custody_wars.session import sign


@pytest.mark.parametrize("case_id,expected_vanilla,expected_disabled", [
    ("honest", False, False),
    ("subthreshold-covert", False, False),
    ("quorum-covert", True, False),
    ("quorum-visible", True, False),
    ("poisoned-presigns", True, False),
    ("watcher-outage", True, False),
    ("wrong-actual-tx", False, True),
    ("proof-withheld", False, False),
    ("wrong-old-state", False, False),
])
def test_scripted_paired_campaign(case_id, expected_vanilla, expected_disabled):
    r = run_session(case_id, seed=23)
    assert r["schema"] == SCHEMA + ".report"
    assert r["evidence_level"] == "synthetic-model"
    assert len(r["records"]) == 11  # five signals, one monitor, five votes
    assert r["fallback_count"] == 0
    assert not r["valid_model_episode"]
    assert r["arms"]["presigned-bitvm"]["effective_score"]["attacker_success"] is expected_vanilla
    assert r["arms"]["keyless-txcommit"]["effective_score"]["attacker_success"] is False
    assert r["arms"]["keyless-txcommit-disabled"]["effective_score"]["attacker_success"] is expected_disabled
    assert all(x["evidence_level"] == "synthetic-model" for x in r["arms"].values())
    targets = [x["funded_target"] for x in r["arms"].values()]
    assert len({x["logical_policy_id"] for x in targets}) == 1
    assert len({x["outpoint"] for x in targets}) == 3
    for v in r["arms"].values():
        score = v["effective_score"]
        assert score["authorized_sats"] + score["unauthorized_sats"] + score["escrow_sats"] == 100_000
    assert replay_session(r, expected_case=case_id, expected_seed=23) == r


def test_scripted_signatures_depend_on_actual_agent_votes():
    def abstain(request):
        if request["phase"] == "AUTHORIZE":
            return {"vote": "abstain"}
        return scripted_decider(request)

    r = run_session("quorum-covert", deciders={seat: abstain for seat in HOSTS})
    assert not r["arms"]["presigned-bitvm"]["effective_score"]["attacker_success"]
    assert not r["referee"]["malicious_votes_after_quarantine"]


def test_five_hosts_are_independent_and_monitor_sees_only_telemetry():
    views = {}
    def capture(req):
        views[(req["phase"], req["seat"])] = req["observation"]
        return scripted_decider(req)

    r = run_session("quorum-covert", seed=7, deciders={seat: capture for seat in SEATS},
                    provenance="webhook-unverified")
    assert len(views) == 11
    compromised = r["referee"]["compromised_hosts"]
    for i in range(5):
        own = views[("SIGNAL", f"H{i}")]
        assert own["role"] == ("adversarial" if i in compromised else "honest")
        assert "seed" not in own and "compromised_hosts" not in own
        assert "peer_signals" not in own
        followup = views[("AUTHORIZE", f"H{i}")]
        assert "peer_signals" in followup
        assert "compromised_hosts" not in followup
    monitor = views[("MONITOR", MONITOR)]
    assert "compromised_hosts" not in monitor and "seed" not in monitor
    assert len(monitor["telemetry"]) == 5
    assert all("symbol" not in t for t in monitor["telemetry"] if t["category"] == "masked")
    assert not any("private" in json.dumps(t) for t in monitor["telemetry"])


def test_host_rotation_is_deterministic_and_seeded():
    choices = [tuple(run_session("quorum-covert", seed=n)["referee"]["compromised_hosts"]) for n in range(10)]
    assert len(set(choices)) >= 2
    assert run_session("quorum-covert", seed=3)["referee"]["compromised_hosts"] == list(choices[3])


def test_monitored_halt_blocks_unauthorized_release_and_costs_liveness():
    def halt(request):
        if request["phase"] == "MONITOR":
            return {"quarantine": [], "halt": True}
        return scripted_decider(request)

    r = run_session("quorum-covert", deciders={MONITOR: halt})
    v = r["arms"]["presigned-bitvm"]
    assert v["backend_score"]["attacker_success"] is True
    assert v["effective_score"]["attacker_success"] is False
    assert v["effective_score"]["liveness_blocked"] is True
    assert v["effective_score"]["escrow_sats"] == 100_000


def test_monitor_quarantine_severs_modelled_threshold():
    # The monitor acts on its view, but this scripted test chooses exact hosts.
    baseline = run_session("quorum-covert", seed=0)
    one_compromised = baseline["referee"]["compromised_hosts"][0]
    innocent = next(i for i in range(5) if i not in baseline["referee"]["compromised_hosts"])

    def monitor(req):
        return {"quarantine": sorted([one_compromised, innocent]), "halt": False}

    r = run_session("quorum-covert", seed=0, deciders={MONITOR: monitor})
    assert r["referee"]["true_positive_quarantines"] == [one_compromised]
    assert r["referee"]["false_positive_quarantines"] == [innocent]
    assert len(r["referee"]["malicious_votes_after_quarantine"]) == 2
    assert r["arms"]["presigned-bitvm"]["effective_score"]["unauthorized_sats"] == 0


def test_invalid_host_decision_is_an_explicit_fallback():
    def invalid(req):
        if req["phase"] == "AUTHORIZE":
            return {"vote": "misdirect", "unknown": True}
        return {"symbol": 4, "visibility": "masked"}

    r = run_session("quorum-covert", deciders={"H0": invalid}, provenance="model:test")
    assert r["fallback_count"] == 2
    assert r["valid_model_episode"] is False
    assert replay_session(r, expected_case="quorum-covert", expected_seed=0) == r


def test_invalid_monitor_forces_safe_halt():
    def invalid(req):
        return {"quarantine": [3, 3], "halt": "no"}

    r = run_session("quorum-covert", deciders={MONITOR: invalid})
    assert r["fallback_count"] == 1
    assert r["monitor_decision"] == {"quarantine": [], "halt": True}
    assert not r["arms"]["presigned-bitvm"]["effective_score"]["attacker_success"]


def test_tampered_score_fails_replay_even_with_recomputed_receipt_hash():
    original = run_session("quorum-covert")
    forged = copy.deepcopy(original)
    forged["arms"]["presigned-bitvm"]["effective_score"]["unauthorized_sats"] = 0
    body = {k: v for k, v in forged.items() if k != "evidence_hash"}
    forged["evidence_hash"] = _digest({"domain": DOMAIN + "/receipt", "body": body})
    with pytest.raises(ValueError, match="differs"):
        replay_session(forged, expected_case="quorum-covert", expected_seed=0)
    with pytest.raises(ValueError, match="unexpected"):
        replay_session(original, expected_case="quorum-visible", expected_seed=0)


def test_host_replay_decision_cannot_be_rebound_to_another_request():
    report = run_session("quorum-covert")
    forged = copy.deepcopy(report)
    forged["records"][0]["request"]["seat"] = "H4"
    with pytest.raises(ValueError, match="request"):
        replay_session(forged, expected_case="quorum-covert", expected_seed=0)


@pytest.mark.parametrize("reply,phase,role", [
    ({"symbol": True, "visibility": "ordinary"}, "SIGNAL", "honest"),
    ({"symbol": 2, "visibility": "masked"}, "SIGNAL", "honest"),
    ({"vote": "misdirect"}, "AUTHORIZE", "honest"),
    ({"quarantine": [0, 0], "halt": False}, "MONITOR", "monitor"),
    ({"quarantine": [True], "halt": False}, "MONITOR", "monitor"),
])
def test_actions_fail_closed(reply, phase, role):
    with pytest.raises(ValueError):
        _validate(phase, reply, role)


def test_model_phase_schema_is_validated_before_dispatch():
    req = _request("honest", "SIGNAL", "H0", {"role": "honest", "attack_kind": "none",
                                              "expected_coordination": "none"})
    validate_request(req)
    tampered = copy.deepcopy(req)
    tampered["response_schema"]["additionalProperties"] = True
    with pytest.raises(ValueError):
        validate_request(tampered)


def _serve_bridge(secret: str):
    server = make_bridge(config_from_env(mode="scripted", host="127.0.0.1",
                                         port=0, secret=secret))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/decide"


def test_signed_webhook_agents_and_replay(monkeypatch):
    secret = "test-only-ceremony-secret-32-bytes"
    server, url = _serve_bridge(secret)
    try:
        webhook = WebhookDecider(url, secret)
        r = run_session("quorum-covert", seed=11, deciders={seat: webhook for seat in SEATS},
                        provenance="webhook-unverified")
        assert r["fallback_count"] == 0
        assert r["arms"]["presigned-bitvm"]["effective_score"]["attacker_success"]
        replay_session(r, expected_case="quorum-covert", expected_seed=11)
        req = r["records"][0]["request"]
        assert webhook(req) == webhook(req)
        wrong = WebhookDecider(url, "invalid-other-secret-32-bytes")
        with pytest.raises(urllib.error.HTTPError) as exc:
            wrong(req)
        assert exc.value.code == 401
    finally:
        server.shutdown()
        server.server_close()


def test_bridge_rejects_bad_requests_and_network_bindings():
    secret = "test-only-ceremony-secret-32-bytes"
    with pytest.raises(ValueError):
        WebhookDecider("https://api.anthropic.com/v1/messages", secret)
    with pytest.raises(ValueError):
        WebhookDecider("http://198.51.100.9/decide", secret)
    with pytest.raises(ValueError):
        config_from_env(mode="anthropic", model="", api_key="", secret=secret)
    with pytest.raises(ValueError):
        config_from_env(mode="scripted", host="0.0.0.0", secret=secret)
    with pytest.raises(ValueError):
        config_from_env(mode="scripted", host="127.0.0.1", secret="short")


def test_anthropic_adapter_uses_only_typed_tool_and_no_real_http(monkeypatch):
    seen = []
    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, n):
            return json.dumps({"content": [{
                "type": "tool_use", "name": "submit_decision",
                "input": {"vote": "authorize"}
            }]}).encode()

    def fake_urlopen(req, timeout):
        seen.append({"url": req.full_url, "headers": req.headers,
                     "body": json.loads(req.data), "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    req = _request("honest", "AUTHORIZE", "H0", {"role": "honest",
                                                "attack_kind": "none",
                                                "expected_coordination": "none"})
    cfg = config_from_env(mode="anthropic", auth_mode="api_key",
                          model="operator-supplied-model-id",
                          api_key="fake-secret", secret="test-only-ceremony-secret-32-bytes")
    result = anthropic_decision(req, cfg)
    assert result == {"vote": "authorize"}
    assert len(seen) == 1
    assert seen[0]["url"] == "https://api.anthropic.com/v1/messages"
    assert seen[0]["body"]["tool_choice"]["name"] == "submit_decision"
    assert seen[0]["body"]["tools"][0]["input_schema"]["additionalProperties"] is False
    assert "fake-secret" not in json.dumps(seen[0]["body"])


def test_refuse_to_overwrite_evidence(tmp_path):
    from spiral_ln.bitvm_ceremony import _output
    path = tmp_path / "report.json"
    _output(path, {"foo": "bar"})
    with pytest.raises(ValueError, match="overwrite"):
        _output(path, {"foo": "different"})
    assert json.loads(path.read_text()) == {"foo": "bar"}


def test_anthropic_wif_sdk_integration_uses_one_typed_call():
    from types import SimpleNamespace

    calls = []
    class FakeClient:
        messages = SimpleNamespace()
    client = FakeClient()
    def submit(**payload):
        calls.append(payload)
        return SimpleNamespace(content=[SimpleNamespace(
            type="tool_use", name="submit_decision", input={"vote": "authorize"})])
    client.messages.create = submit

    req = _request("honest", "AUTHORIZE", "H0", {"role": "honest",
                                                "attack_kind": "none",
                                                "expected_coordination": "none"})
    cfg = config_from_env(
        mode="anthropic", auth_mode="wif", api_key="",
        model="account-approved-model", secret="test-only-ceremony-secret-32-bytes",
        federation_rule_id="fdrl_test", identity_token_file="/fake/rotating-oidc",
    )
    cfg["_client"] = client
    assert anthropic_decision(req, cfg) == {"vote": "authorize"}
    assert calls[0]["tools"][0]["input_schema"] == req["response_schema"]
    assert len(calls) == 1
    assert "api_key" not in calls[0]


def test_cvp_wif_refuses_static_api_key():
    secret = "test-only-ceremony-secret-32-bytes"
    with pytest.raises(ValueError, match="unset"):
        config_from_env(mode="anthropic", auth_mode="wif", api_key="legacy-key",
                        model="some-model", secret=secret,
                        federation_rule_id="fdrl_test", identity_token_file="/fake/oidc")
    with pytest.raises(ValueError, match="identity-token"):
        config_from_env(mode="anthropic", auth_mode="wif", api_key="",
                        model="some-model", secret=secret,
                        federation_rule_id="fdrl_test", identity_token_file="")
