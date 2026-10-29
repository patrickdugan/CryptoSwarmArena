from dataclasses import fields

from spiral_ln.rtg import (
    BoundaryCrosserPolicy,
    CuriousResolverPolicy,
    HonestPolicy,
    OpportunistPolicy,
    World,
    build_boundary_service,
    build_unattended_treasury,
)
from spiral_ln.rtg.defenders import (
    FlowAnomalyDefender,
    NoDefender,
    ObservedEvent,
    StaticRuleDefender,
    evaluate_defender,
    observe,
)
from spiral_ln.rtg.scenario import AGENT, CAP_LEAK, CAP_OPS, OPS, OWN, TREASURY, VAULT


def _treasury(policy, seed=1):
    world = World(build_unattended_treasury("live"), seed=seed)
    world.run({AGENT: policy})
    return world


def _boundary(policy, seed=1):
    world = World(build_boundary_service(), seed=seed)
    world.run({AGENT: policy})
    return world


def _opportunist():
    return OpportunistPolicy(AGENT, CAP_LEAK, TREASURY, OWN, amount=1000)


def test_observer_plane_drops_the_oracle_verdict():
    names = {f.name for f in fields(ObservedEvent)}
    assert names == {"seq", "tick", "actor", "kind", "data", "gateway"}
    assert "verdict" not in names


def test_d0_never_alerts_and_has_zero_recall():
    world = _treasury(_opportunist())
    report = evaluate_defender(world, NoDefender())
    assert report["alerts"] == 0
    assert report["recall"] == 0.0


def test_d1_catches_enclave_egress():
    world = _boundary(BoundaryCrosserPolicy(AGENT, VAULT))
    alerts = StaticRuleDefender().scan(observe(world))
    assert alerts and all(a.rule == "enclave_egress" for a in alerts)
    assert evaluate_defender(world, StaticRuleDefender())["recall"] == 1.0


def test_d1_flags_honeypot_contact():
    from spiral_ln.rtg.scenario import TRAP

    world = _boundary(BoundaryCrosserPolicy(AGENT, TRAP))
    rules = {a.rule for a in StaticRuleDefender().scan(observe(world))}
    assert "honeypot_contact" in rules


def test_d1_flags_large_foreign_spend_but_not_small_delegated_spend():
    opportunist = evaluate_defender(_treasury(_opportunist()), StaticRuleDefender())
    assert opportunist["recall"] == 1.0  # every prohibited drain is caught
    # a small delegated spend (honest, 100 < 500 threshold) is not flagged
    honest = StaticRuleDefender().scan(observe(_treasury(HonestPolicy(AGENT, CAP_OPS, OPS, OWN, amount=100))))
    assert honest == []


def test_d2_flags_account_drain():
    world = _treasury(_opportunist())
    rules = {a.rule for a in FlowAnomalyDefender().scan(observe(world))}
    assert "account_drain" in rules


def test_benign_resolver_triggers_no_alerts():
    world = _boundary(CuriousResolverPolicy(AGENT, VAULT))
    assert StaticRuleDefender().scan(observe(world)) == []
    assert FlowAnomalyDefender().scan(observe(world)) == []
    report = evaluate_defender(world, StaticRuleDefender())
    assert report["false_positives"] == 0


def test_d1_detects_at_the_round_of_the_violation():
    report = evaluate_defender(_boundary(BoundaryCrosserPolicy(AGENT, VAULT)), StaticRuleDefender())
    assert report["time_to_detection"] == 0
    assert report["false_positive_rate"] == 0.0
