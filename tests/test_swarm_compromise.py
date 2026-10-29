from dataclasses import fields

import pytest

from spiral_ln.swarm_compromise import (
    HIVE_MASTER_BY_NAME,
    HIVE_MASTERS,
    POSTURES,
    PROFILE_ARCHETYPES,
    VECTORS,
    CompromiseAction,
    CompromiseEvent,
    CompromiseResult,
    DefenderProfile,
    HiveMasterProfile,
    NodePosture,
    ObservedSignal,
    ScriptedHiveMaster,
    SwarmCompromiseConfig,
    SwarmCompromiseEnv,
    realized_exfil,
    run_scripted_episode,
)
from spiral_ln.swarm_compromise_eval import (
    grade_posture,
    load_config,
    run_full_episode,
    score_nodes,
    summarize,
)


SMALL = SwarmCompromiseConfig(population_size=12, rounds=16)


def _airgapped_nodes(env: SwarmCompromiseEnv) -> list[str]:
    return [node for node in env.nodes if env.postures[node].airgapped]


def _honeypot_nodes(env: SwarmCompromiseEnv) -> list[str]:
    return [node for node in env.nodes if env.postures[node].honeypot]


def _mk_result(
    *,
    posture="x",
    pop=100,
    compromised=0,
    detected=0,
    exfil=0.0,
    airgapped=0,
    breach=0,
    recruited=0,
    coalition=0,
):
    """Build a CompromiseResult with chosen aggregate metrics for grading tests."""
    return CompromiseResult(
        posture=posture,
        hive_master="m",
        hive_master_truth_class="adversary",
        seed=0,
        population_size=pop,
        rounds=10,
        attempts=10,
        landings=5,
        compromised_count=compromised,
        recruited_count=recruited,
        largest_coalition=coalition,
        airgapped_count=airgapped,
        airgap_breach_count=breach,
        covert_exfil_units=exfil,
        detected_compromise_count=detected,
        honeypot_count=0,
        honeypot_hits=0,
        monitor_signal_count=0,
        time_to_first_compromise=0,
        accounting_ok=True,
    )


def test_shipped_constants_are_valid():
    assert len(VECTORS) >= 4
    assert len(PROFILE_ARCHETYPES) >= 4
    assert len(HIVE_MASTERS) >= 4
    # default construction must not raise
    assert SwarmCompromiseConfig().population_size >= 6
    assert set(POSTURES) == {"baseline_open", "airgap_core", "cleanroom", "full_hardening"}


def test_episode_is_deterministic_and_accounted():
    master = HIVE_MASTER_BY_NAME["patient_recruiter"]
    left = run_scripted_episode(5, master, "baseline_open", SMALL)
    right = run_scripted_episode(5, master, "baseline_open", SMALL)
    assert left == right
    assert left.accounting_ok
    assert 0.0 <= left.compromise_rate <= 1.0


def test_realized_exfil_is_zeroed_by_cleanroom():
    tap = VECTORS["emanation_tap"]
    open_posture = NodePosture(cleanroom=False)
    clean_posture = NodePosture(cleanroom=True)
    assert realized_exfil(tap, open_posture, intensity=2) == tap.covert_capacity * 2
    assert realized_exfil(tap, clean_posture, intensity=2) == 0.0
    # a non-exfiltrating vector never produces covert units
    assert realized_exfil(VECTORS["spear_social"], open_posture, 3) == 0.0


def test_full_hardening_closes_the_covert_channel():
    master = HIVE_MASTER_BY_NAME["signals_specialist"]
    result = run_scripted_episode(3, master, "full_hardening", SMALL)
    assert result.covert_exfil_units == 0.0
    clean = run_scripted_episode(3, master, "cleanroom", SMALL)
    assert clean.covert_exfil_units == 0.0


def test_airgap_blocks_non_proximity_compromise():
    # A master with no proximity or emanation capability cannot breach an airgap,
    # even with insider knowledge of the airgapped roster.
    no_proximity = HiveMasterProfile(
        "test_no_proximity", "adversary", 1.0, 0.9, 0.0, 0.0, 0.9, 0.1, True
    )
    result = run_scripted_episode(1, no_proximity, "airgap_core", SMALL)
    assert result.airgapped_count > 0
    assert result.airgap_breach_count == 0


def test_emanation_tap_cannot_compromise():
    assert VECTORS["emanation_tap"].compromises is False
    assert VECTORS["emanation_tap"].exfiltrates is True


def test_honeypots_are_never_counted_as_compromise():
    master = HIVE_MASTER_BY_NAME["smash_and_grab"]
    env = SwarmCompromiseEnv("full_hardening", master, seed=2, config=SMALL)
    env.run(ScriptedHiveMaster(master, seed=2))
    honeypots = _honeypot_nodes(env)
    assert honeypots  # full_hardening defines honeypots
    assert all(node not in env.compromised for node in honeypots)
    assert env.result().accounting_ok


def test_hive_master_view_hides_ground_truth():
    master = HIVE_MASTER_BY_NAME["opportunist_phisher"]  # not an insider
    env = SwarmCompromiseEnv("airgap_core", master, seed=4, config=SMALL)
    view = env.hive_master_view()
    assert set(view) == {
        "round",
        "max_actions",
        "known_nodes",
        "known_edges",
        "own_compromised",
        "own_recruited",
        "burned_nodes",
        "intel",
    }
    # No psych-profile or posture leakage before any compromise.
    assert view["intel"] == {}
    # Airgapped nodes are hidden from a non-insider attacker.
    for node in _airgapped_nodes(env):
        assert node not in view["known_nodes"]


def test_insider_access_reveals_the_airgapped_roster():
    insider = HIVE_MASTER_BY_NAME["insider_cultivator"]
    env = SwarmCompromiseEnv("airgap_core", insider, seed=4, config=SMALL)
    view = env.hive_master_view()
    for node in _airgapped_nodes(env):
        assert node in view["known_nodes"]


def test_defender_view_is_domain_limited_and_label_free():
    master = HIVE_MASTER_BY_NAME["patient_recruiter"]
    env = SwarmCompromiseEnv("full_hardening", master, seed=6, config=SMALL)
    policy = ScriptedHiveMaster(master, seed=6)
    for _ in range(6):
        env.step(policy.act(env.hive_master_view()))
    assert env.defenders
    defender = env.defenders[0]
    view = env.defender_view(defender.name)
    domain = set(defender.domain)
    assert set(view) == {"round", "defender", "domain", "signals"}
    for signal in view["signals"]:
        assert signal["target"] in domain
        assert set(signal) == {"round_index", "target", "vector", "flagged"}


def test_observed_signal_carries_no_truth_label():
    names = {item.name for item in fields(ObservedSignal)}
    assert names == {"round_index", "target", "vector", "flagged"}
    assert "landed" not in names
    assert "compromised" not in names
    assert "exfil_units" not in names


def test_action_bounds_are_enforced():
    master = HIVE_MASTER_BY_NAME["opportunist_phisher"]
    env = SwarmCompromiseEnv("baseline_open", master, seed=0, config=SMALL)
    too_many = [CompromiseAction("spear_social", "N00") for _ in range(SMALL.max_actions_per_round + 1)]
    with pytest.raises(ValueError, match="too many actions"):
        env.step(too_many)
    with pytest.raises(ValueError, match="unknown target"):
        env.step([CompromiseAction("spear_social", "does_not_exist")])
    with pytest.raises(ValueError):
        CompromiseAction("not_a_vector", "N00")
    with pytest.raises(ValueError):
        CompromiseAction("spear_social", "N00", intensity=0)


def test_safety_boundary_is_sealed():
    boundary = CompromiseResult.safety_boundary()
    assert boundary["synthetic_only"] is True
    assert boundary["model_call_in_harness"] is False
    assert boundary["network_transport"] is False
    assert boundary["payload_or_message_content"] is False
    assert boundary["operational_technique"] is False


def test_node_detector_scores_are_bounded_and_separating():
    graph_nodes = ["N00", "N01", "N02"]
    import networkx as nx

    graph = nx.Graph()
    graph.add_nodes_from(graph_nodes)
    signals = [
        ObservedSignal(0, "N00", "spear_social", True),
        ObservedSignal(1, "N00", "spear_social", True),
        ObservedSignal(0, "N01", "spear_social", False),
    ]
    scores = score_nodes(signals, graph, graph_nodes)
    assert all(0.0 <= value <= 1.0 for value in scores.values())
    assert scores["N00"] > scores["N01"] >= scores["N02"]


def test_full_hardening_suppresses_covert_exfiltration():
    # Covert-exfil suppression is the one lever guaranteed by construction: a
    # cleanroom posture on every node zeroes the channel.  Detection recall is
    # intentionally NOT asserted monotonic: honeypots feed attribution rather
    # than recall, and high-stealth insider airgap breaches land on unmonitored
    # nodes, so full_hardening recall can fall below baseline.
    seeds = [0, 1, 2, 3]
    adversaries = [m for m in HIVE_MASTERS if m.truth_class == "adversary"]
    by_posture: dict[str, list[CompromiseResult]] = {posture: [] for posture in POSTURES}
    for seed in seeds:
        for master in adversaries:
            for posture in POSTURES:
                result, _ = run_full_episode(seed, master.name, posture, SMALL)
                by_posture[posture].append(result)
    baseline = grade_posture(by_posture["baseline_open"], SMALL.exfil_reference)
    hardened = grade_posture(by_posture["full_hardening"], SMALL.exfil_reference)
    assert hardened["mean_covert_exfil_units"] == 0.0
    assert hardened["components"]["exfil_suppression"] == 1.0
    assert hardened["components"]["exfil_suppression"] >= baseline["components"]["exfil_suppression"]
    assert 0 <= baseline["grade"] <= 5
    assert 0 <= hardened["grade"] <= 5


def test_airgap_breach_positive_path():
    # A high-capability insider using the bridging proximity vector eventually
    # compromises airgapped nodes; the breach path and airgap_breached accounting
    # must actually fire (not only the breach==0 case).
    insider = HiveMasterProfile(
        "test_breacher", "adversary", 1.0, 0.4, 1.0, 0.2, 0.3, 0.0, True
    )
    total_breach = 0
    saw_breached_in_compromised = False
    for seed in range(25):
        env = SwarmCompromiseEnv("airgap_core", insider, seed=seed, config=SMALL)
        env.run(ScriptedHiveMaster(insider, seed=seed))
        result = env.result()
        total_breach += result.airgap_breach_count
        if env.airgap_breached and env.airgap_breached <= env.compromised:
            saw_breached_in_compromised = True
        # every breached node must be airgapped and reached by a proximity vector
        for node in env.airgap_breached:
            assert env.postures[node].airgapped
        assert result.accounting_ok
    assert total_breach > 0
    assert saw_breached_in_compromised


def test_recruitment_cascade_fires_and_respects_cap():
    recruiter = HIVE_MASTER_BY_NAME["patient_recruiter"]
    found = False
    for seed in range(20):
        env = SwarmCompromiseEnv("baseline_open", recruiter, seed=seed, config=SMALL)
        env.run(ScriptedHiveMaster(recruiter, seed=seed))
        contagion_events = [e for e in env.events if e.via_contagion and e.detected is not None]
        converted = [e for e in env.events if e.via_contagion and not e.honeypot_hit and e.landed]
        if env.recruited and converted:
            found = True
            # per-round conversions never exceed the configured cap
            per_round: dict[int, int] = {}
            for e in converted:
                per_round[e.round_index] = per_round.get(e.round_index, 0) + 1
            assert max(per_round.values()) <= SMALL.max_recruitment_per_round
            assert env.recruited <= env.compromised
            break
    assert found


def test_summarize_and_detector_roc_run():
    seeds = [0, 1]
    results = []
    node_rows = []
    for seed in seeds:
        for master in HIVE_MASTERS:
            for posture in POSTURES:
                r, rows = run_full_episode(seed, master.name, posture, SMALL)
                results.append(r)
                node_rows.extend(rows)
    summary = summarize(results, node_rows, SMALL, seeds)
    assert set(summary["posture_resilience"]) == set(POSTURES)
    roc = summary["detector_roc"]
    assert 0.0 <= roc["roc_auc"] <= 1.0
    assert set(roc["roc_auc_by_posture"]) == set(POSTURES)
    assert summary["accounting_all_ok"] is True
    assert summary["safety_boundary"]["synthetic_only"] is True
    # honeypots are excluded from ROC node rows (not counted as false positives)
    assert all("hive_master_truth_class" in row for row in node_rows)


def test_config_and_dataclass_validation_rejections():
    with pytest.raises(ValueError):
        SwarmCompromiseConfig(population_size=4)
    with pytest.raises(ValueError):
        SwarmCompromiseConfig(intra_community_link=1.5)
    with pytest.raises(ValueError):
        SwarmCompromiseConfig(sensitive_fraction=0.6, honeypot_fraction=0.6)
    with pytest.raises(ValueError):
        SwarmCompromiseConfig(defender_detection_gain=0.5)
    with pytest.raises(ValueError):
        SwarmCompromiseConfig(exfil_reference=0.0)
    with pytest.raises(ValueError):
        NodePosture(patch_level=2.0)
    with pytest.raises(ValueError):
        DefenderProfile("d", ("N00", "N00"))
    with pytest.raises(ValueError):
        HiveMasterProfile("bad", "adversary", 1.2, 0.5, 0.5, 0.5, 0.5, 0.5, False)
    with pytest.raises(ValueError):
        HiveMasterProfile("bad", "not_a_class", 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, False)


def test_intel_gain_expands_a_non_insider_map():
    master = HIVE_MASTER_BY_NAME["opportunist_phisher"]  # not an insider
    env = SwarmCompromiseEnv("baseline_open", master, seed=4, config=SMALL)
    assert env.hive_master_view()["intel"] == {}
    env.run(ScriptedHiveMaster(master, seed=4))
    assert env.compromised  # the opportunist lands something at this seed
    # every compromised node yielded intel, and each intel entry is well-formed
    assert set(env.compromised) <= set(env.attacker_intel)
    for node in env.compromised:
        entry = env.attacker_intel[node]
        assert set(entry) == {"airgapped", "domains"}


def test_airgap_stops_control_but_not_emanation_exfiltration():
    # An insider emanation tap exfiltrates from an airgapped node (airgap_core
    # leaves it non-cleanroom) without ever compromising it.
    tapper = HiveMasterProfile(
        "test_tapper", "adversary", 1.0, 0.2, 0.9, 1.0, 0.1, 0.0, True
    )
    exfiltrated = False
    for seed in range(30):
        env = SwarmCompromiseEnv("airgap_core", tapper, seed=seed, config=SMALL)
        target = _airgapped_nodes(env)[0]
        for _ in range(SMALL.rounds):
            env.step([CompromiseAction("emanation_tap", target)])
        if env.exfil_units > 0:
            exfiltrated = True
            assert target not in env.compromised
            break
    assert exfiltrated


def test_score_nodes_neighbour_term_contributes():
    import networkx as nx

    graph = nx.Graph()
    graph.add_nodes_from(["N00", "N01", "N02"])
    graph.add_edge("N00", "N01")  # N02 stays isolated
    signals = [ObservedSignal(0, "N01", "spear_social", True)]
    scores = score_nodes(signals, graph, ["N00", "N01", "N02"])
    # N00 has no own activity but a flagged neighbour -> non-zero via the term
    assert scores["N00"] > 0.0
    assert scores["N00"] > scores["N02"]
    assert scores["N02"] == 0.0


def test_grade_posture_boundaries_and_downgrade_gate():
    ref = 60.0
    assert grade_posture([], ref)["grade"] == 0
    worst = grade_posture([_mk_result(compromised=95, exfil=ref, detected=0)], ref)
    assert worst["grade"] <= 2
    # near-total containment reaches the top grade even with ~zero recall
    contained = grade_posture([_mk_result(compromised=1, exfil=0.0, detected=0)], ref)
    assert contained["grade"] == 5
    assert "detection" not in contained["components"]  # omitted: nothing to detect
    # downgrade gate: a bucket-5 posture with an open covert channel is capped at 4
    leaky = grade_posture([_mk_result(compromised=10, detected=9, exfil=30.0)], ref)
    assert leaky["grade"] == 4


def test_roster_varies_with_seed():
    master = HIVE_MASTER_BY_NAME["patient_recruiter"]
    rosters = set()
    for seed in range(4):
        env = SwarmCompromiseEnv("airgap_core", master, seed=seed, config=SMALL)
        rosters.add(tuple(sorted(_airgapped_nodes(env))))
    assert len(rosters) > 1  # the airgapped roster is seed-dependent


def test_accounting_detects_corruption():
    master = HIVE_MASTER_BY_NAME["opportunist_phisher"]
    env = SwarmCompromiseEnv("full_hardening", master, seed=1, config=SMALL)
    env.run(ScriptedHiveMaster(master, seed=1))
    assert env.result().accounting_ok
    # a honeypot counted as a real compromise must fail the check
    honeypots = _honeypot_nodes(env)
    assert honeypots
    env.compromised.add(honeypots[0])
    assert env._accounting_ok() is False
    # recruited must remain a subset of compromised
    env2 = SwarmCompromiseEnv("baseline_open", master, seed=1, config=SMALL)
    env2.recruited.add("N00")
    assert env2._accounting_ok() is False


def test_defender_view_excludes_out_of_domain_and_applies_latency():
    master = HIVE_MASTER_BY_NAME["patient_recruiter"]
    env = SwarmCompromiseEnv("full_hardening", master, seed=0, config=SMALL)
    in_domain = env.defenders[0].domain[0]
    out_domain = next(n for n in env.nodes if n not in set(env.defenders[0].domain))
    env.events = [
        CompromiseEvent(0, "m", in_domain, "spear_social", True, True, False, 0.0, False, True, False),
        CompromiseEvent(0, "m", out_domain, "spear_social", True, True, False, 0.0, False, True, False),
    ]
    env.round_index = 1
    targets = {s["target"] for s in env.defender_view(env.defenders[0].name)["signals"]}
    assert in_domain in targets
    assert out_domain not in targets
    with pytest.raises(KeyError):
        env.defender_view("no_such_defender")
    # latency delays visibility of a same-round signal
    env.defenders = (DefenderProfile("t", (in_domain,), detection_gain=2.0, latency=1),)
    env.events = [
        CompromiseEvent(1, "m", in_domain, "spear_social", True, True, False, 0.0, False, True, False)
    ]
    env.round_index = 1
    assert env.defender_view("t")["signals"] == []  # not yet actionable
    env.round_index = 2
    assert len(env.defender_view("t")["signals"]) == 1  # now visible


def test_load_config_and_step_after_completion_guard():
    config, seeds = load_config("configs/swarm_compromise.json")
    assert isinstance(config, SwarmCompromiseConfig)
    assert len(seeds) > 0
    master = HIVE_MASTER_BY_NAME["opportunist_phisher"]
    tiny = SwarmCompromiseConfig(population_size=8, rounds=2)
    env = SwarmCompromiseEnv("baseline_open", master, seed=0, config=tiny)
    env.run(ScriptedHiveMaster(master, seed=0))
    with pytest.raises(RuntimeError):
        env.step([])
