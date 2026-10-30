"""Custody Wars HTTP harness, webhook bridge, pull mode and fallback accounting.

Everything binds to 127.0.0.1 on an ephemeral port; no external network."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from spiral_ln.custody_wars import Session
from spiral_ln.custody_wars.agent import play
from spiral_ln.custody_wars.bridge import config_from_env, make_bridge
from spiral_ln.custody_wars.server import make_server
from spiral_ln.custody_wars.session import sign, verify_signature
from spiral_ln.custody_wars.tournament import render_markdown, run_tournament


def _serve(httpd):
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{httpd.server_address[1]}"


@pytest.fixture
def harness():
    httpd = make_server("127.0.0.1", 0)
    url = _serve(httpd)
    yield url, httpd
    httpd.shutdown()


@pytest.fixture
def bridge():
    httpd = make_bridge(config_from_env(mode="policy", host="127.0.0.1", port=0, secret="s3cret"))
    url = _serve(httpd)
    yield url
    httpd.shutdown()


def _http(method, url, token=None, body=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_hmac_signatures_and_replay_window():
    ts = str(int(time.time()))
    sig = sign("k", ts, b"{}")
    assert verify_signature("k", ts, b"{}", sig)
    assert not verify_signature("other", ts, b"{}", sig)
    assert not verify_signature("k", ts, b"{ }", sig)
    old = str(int(time.time()) - 3600)
    assert not verify_signature("k", old, b"{}", sign("k", old, b"{}"))


def test_webhook_seats_play_through_a_signed_bridge(bridge):
    agents = {seat: {"type": "webhook", "url": bridge, "secret": "s3cret", "timeout_ms": 20000}
              for seat in ("BROKER", "SENTINEL")}
    s = Session({"scenario": "baseline", "seed": 3, "agents": agents, "max_turns": 3})
    s.run()
    rep = s.referee_report()
    assert rep["harness"]["fallbacks"]["BROKER"] == 0 and rep["harness"]["fallbacks"]["SENTINEL"] == 0
    assert rep["harness"]["agent_calls"]["BROKER"] == 9      # 3 decision phases x 3 turns
    assert rep["harness"]["conservation_failures"] == 0


def test_bad_signature_is_refused_and_counted_as_fallback(bridge):
    s = Session({"scenario": "baseline", "seed": 3, "max_turns": 1,
                 "agents": {"BROKER": {"type": "webhook", "url": bridge, "secret": "wrong", "retries": 0}}})
    s.run()
    rep = s.referee_report()
    assert rep["harness"]["fallbacks"]["BROKER"] == 3
    reasons = [b["event"]["data"]["reason"] for b in s.trace.entries if b["event"]["type"] == "agent_fallback"]
    assert all("401" in r for r in reasons)


def test_unreachable_webhook_falls_back_without_stalling_the_game():
    s = Session({"scenario": "baseline", "seed": 3, "max_turns": 1,
                 "agents": {"HIVE": {"type": "webhook", "url": "http://127.0.0.1:9/decide", "retries": 0,
                                     "timeout_ms": 1500}}})
    s.run()
    assert s.state.game_over
    assert s.referee_report()["harness"]["fallbacks"]["HIVE"] == 3


def test_codex_agent_type_uses_the_injected_decider_and_falls_back_on_error():
    calls = []

    def fake(request, model=None, timeout_s=0):
        calls.append(request["phase"])
        assert request["response_schema"]["additionalProperties"] is False
        return {"reasoning": "fake codex", "orders": [], "allocation": {"security": [], "research": [],
                                                                         "builds": [], "screen_level": None},
                "messages": [], "pacts": [], "institution_actions": [], "transfers": [], "attestations": [],
                "challenges": []}

    s = Session({"scenario": "baseline", "seed": 1, "max_turns": 1, "agents": {"REGULATOR": {"type": "codex"}}},
                codex_decider=fake)
    s.run()
    assert calls == ["NEGOTIATION", "ALLOCATION", "ACTION_DECLARATION"]
    assert s.referee_report()["harness"]["fallbacks"]["REGULATOR"] == 0

    def broken(request, model=None, timeout_s=0):
        raise RuntimeError("codex exec failed")

    s2 = Session({"scenario": "baseline", "seed": 1, "max_turns": 1, "agents": {"REGULATOR": {"type": "codex"}}},
                 codex_decider=broken)
    s2.run()
    assert s2.referee_report()["harness"]["fallbacks"]["REGULATOR"] == 3


def test_contracts_and_scenarios_are_served(harness):
    url, _ = harness
    assert _http("GET", url + "/health")[1]["ok"] is True
    code, contract = _http("GET", url + "/contract/agent-webhook")
    assert code == 200 and "x-csa-signature" in contract["headers"]
    code, schema = _http("GET", url + "/contract/decision-schema?phase=ACTION_DECLARATION")
    assert code == 200 and schema["additionalProperties"] is False
    assert _http("GET", url + "/contract/rules")[1]["seats"]["HIVE"]
    assert "bybit_class" in _http("GET", url + "/scenarios")[1]["scenarios"]


def test_pull_seats_are_token_scoped_and_play_to_completion(harness):
    url, _ = harness
    code, created = _http("POST", url + "/sessions", body={
        "scenario": "bybit_class", "seed": 2, "max_turns": 2,
        "agents": {"HIVE": {"type": "pull"}, "BROKER": {"type": "pull"}}})
    assert code == 201
    sid, admin, tokens = created["summary"]["session_id"], created["admin_token"], created["seat_tokens"]
    assert set(tokens) == {"HIVE", "BROKER"}
    base = f"{url}/sessions/{sid}"
    # scope: a seat token cannot read another seat or the referee
    assert _http("GET", f"{base}/observation?seat=BROKER", tokens["HIVE"])[0] == 401
    assert _http("GET", f"{base}/referee", tokens["HIVE"])[0] == 401
    assert _http("GET", f"{base}/observation?seat=HIVE", tokens["HIVE"])[0] == 200
    # the session will not advance past a pull seat without force
    assert _http("POST", f"{base}/step", admin, {})[0] == 409
    code, req = _http("GET", f"{base}/decision-request?seat=HIVE", tokens["HIVE"])
    assert code == 200 and req["phase"] == "NEGOTIATION" and req["seat"] == "HIVE"
    stale = _http("POST", f"{base}/decisions", tokens["HIVE"], {"seat": "HIVE", "request_id": "nope", "decision": {}})
    assert stale[0] == 400
    # two concurrent pull agents (scripted policy) finish the game through the auto-advance path
    results = {}
    threads = [threading.Thread(target=lambda seat=seat: results.__setitem__(
        seat, play(url, sid, seat, tokens[seat], mode="policy", poll_s=0.05, max_idle_s=60))) for seat in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert results == {"HIVE": 0, "BROKER": 0}
    summary = _http("GET", base)[1]
    assert summary["game_over"] is True
    code, ref = _http("GET", f"{base}/referee", admin)
    assert code == 200 and ref["harness"]["fallbacks"] == {s: 0 for s in ref["harness"]["fallbacks"]}
    assert ref["harness"]["trace_verified"] is True
    replay = _http("GET", f"{base}/replay", tokens["BROKER"])[1]
    assert all(e["channel"] not in ("referee", "private_diary", "private_speech") for e in replay["events"])


def test_resubmission_is_idempotent(harness):
    url, _ = harness
    _, created = _http("POST", url + "/sessions", body={"scenario": "baseline", "max_turns": 1,
                                                        "agents": {"SENTINEL": "pull"}})
    sid, tok = created["summary"]["session_id"], created["seat_tokens"]["SENTINEL"]
    base = f"{url}/sessions/{sid}"
    _, req = _http("GET", f"{base}/decision-request?seat=SENTINEL", tok)
    body = {"seat": "SENTINEL", "request_id": req["request_id"], "decision": {"messages": []}}
    first = _http("POST", f"{base}/decisions", tok, body)
    again = _http("POST", f"{base}/decisions", tok, body)
    assert first[0] == 200
    assert again[0] in (200, 400)   # replay of the same body is idempotent until the phase advances


def test_server_policy_refuses_codex_remote_webhooks_and_client_log_paths(harness):
    url, httpd = harness
    code, body = _http("POST", url + "/sessions", body={"agents": {"HIVE": {"type": "codex"}}})
    assert code == 403 and "allow-codex" in body["error"]
    code, body = _http("POST", url + "/sessions", body={"agents": {"HIVE": {"type": "webhook",
                                                                            "url": "http://198.51.100.7/decide"}}})
    assert code == 403 and "loopback" in body["error"]
    code, created = _http("POST", url + "/sessions", body={"log_dir": "C:/Windows/evil", "session_id": "chosen",
                                                           "admin_token": "weak", "max_turns": 1})
    assert code == 201
    s = httpd.registry.get(created["summary"]["session_id"])
    assert s.id != "chosen" and s.admin_token != "weak" and s.log_dir is None


def test_trace_hash_chain_survives_concurrent_appends():
    from spiral_ln.custody_wars.trace import Trace
    tr = Trace()
    workers = [threading.Thread(target=lambda n=n: [tr.append({"turn": 1, "channel": "session", "type": "t",
                                                                "visible_to": "ALL", "data": {"n": n, "i": i}})
                                                     for i in range(200)]) for n in range(8)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert len(tr.entries) == 1600 and tr.verify()


def test_small_tournament_is_healthy():
    result = run_tournament(["baseline", "regulated_compact"], seeds=[1, 2], mixes=["all_default", "greedy_broker"])
    assert result["health"]["conservation_failures"] == 0
    assert result["health"]["all_traces_verified"] is True
    soft = result["by_mode_mix"]["soft/greedy_broker"]
    hard = result["by_mode_mix"]["hard/greedy_broker"]
    assert hard["breaches_executed"] == 0
    assert soft["breaches_blocked"] == 0
    assert "Custody Wars tournament" in render_markdown(result)
