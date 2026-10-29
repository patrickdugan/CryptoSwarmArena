"""Eighteen offline synthetic CASE-764-SYNTH-01 forensic contract cases.

The referee stores truth separately from the investigator's observations.
Cases contain abstract agent, host and operator nodes with no identifying data.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from .forensic_blue import Observation, claim_key, evidence_digest, investigate, score


@dataclass(frozen=True)
class EvidenceGrant:
    allowed_sources: tuple[str, ...]
    allowed_nodes: tuple[str, ...]
    revoked_sources: tuple[str, ...] = ()
    event_start: int = 0
    event_end: int = 50
    collected_by: int = 100
    query_budget: int = 16
    purpose: str = "synthetic_forensics"


@dataclass(frozen=True)
class PublicCase:
    case_id: str
    observations: tuple[Observation, ...]
    grant: EvidenceGrant


@dataclass(frozen=True)
class Oracle:
    case_id: str
    title: str
    truth: tuple[tuple[str, str, str, int | None], ...]
    expected_supported: tuple[tuple[str, str, str, int | None], ...]


class EvidenceBroker:
    """Bounded read-only source queries. Denials never reveal matched records."""
    def __init__(self, case: PublicCase):
        self._case = case
        self.remaining = case.grant.query_budget
        self._admitted = {}
        self.audit = []

    def query(self, source: str, purpose="synthetic_forensics"):
        if self.remaining <= 0:
            self.audit.append({"status": "denied", "reason": "budget_exhausted"})
            return ()
        self.remaining -= 1
        g = self._case.grant
        if source not in g.allowed_sources or purpose != g.purpose:
            self.audit.append({"status": "denied", "reason": "scope"})
            return ()
        if source in g.revoked_sources:
            self.audit.append({"status": "denied", "reason": "revoked"})
            return ()
        selected = tuple(o for o in self._case.observations if
                         (o.source_id or o.origin) == source
                         and o.actor in g.allowed_nodes and o.peer in g.allowed_nodes
                         and g.event_start <= (o.at_tick if o.at_tick is not None else o.tick) <= g.event_end
                         and (o.collected_tick if o.collected_tick is not None else o.tick) <= g.collected_by)
        for o in selected:
            self._admitted[o.event_id] = o
        self.audit.append({"status": "allowed", "source": source, "count": len(selected)})
        return selected

    def evidence(self):
        return tuple(self._admitted[k] for k in sorted(self._admitted))


def run_investigation(case: PublicCase):
    broker = EvidenceBroker(case)
    for source in sorted(case.grant.allowed_sources):
        broker.query(source)
    admitted = broker.evidence()
    report = investigate(admitted, evidence_digest(admitted))
    return {**report, "case_id": case.case_id, "audit": broker.audit,
            "remaining_budget": broker.remaining,
            "naive_accepted": sorted({claim_key(x) for x in admitted
                                       if x.stance == "supports"}, key=str)}


def fixtures():
    """Return public-case and referee-oracle pairs; never pass oracle to blue."""
    rows = []
    def c(a, relation, b, t=10):
        return (a, b, relation, t)

    def r(a, rel, b, source, kind, *, origin=None, tick=10, stance="supports", collected=20):
        return Observation("pending", a, b, kind, origin or source, tick, True,
                           rel, tick, stance, collected, source)

    def add(title, records, truth=(), expected=(), *, aliases=None,
            revoked=(), nodes=None, budget=16, cutoff=100):
        n = len(rows) + 1
        fixed = []
        for index, event in enumerate(records):
            origin = (aliases or {}).get(event.source_id, event.origin)
            fixed.append(replace(event, event_id=f"e{index:03d}", origin=origin))
        sources = tuple(sorted({e.source_id for e in fixed}))
        grant = EvidenceGrant(sources,
                              tuple(nodes or ("n01", "n02", "n03", "n04", "n05", "n06")),
                              revoked_sources=tuple(revoked), query_budget=budget,
                              collected_by=cutoff)
        cid = f"case-764-synth-01-f{n:03d}"
        rows.append((PublicCase(cid, tuple(fixed), grant),
                     Oracle(cid, title, tuple(truth), tuple(expected))))

    controlled = c("n01", "controlled_by", "n03")
    replica = c("n02", "replica_of", "n01")
    host1, host2 = c("n01", "hosted_on", "n04"), c("n02", "hosted_on", "n04")
    shared = c("n01", "same_controller", "n02")
    paid, coerced = c("n03", "paid_by", "n01"), c("n03", "coerced_by", "n01")
    suspicious = c("n02", "controlled_by", "n03")

    add("Corroborated control, copy and host", [
        r("n01","controlled_by","n03","s01","control_receipt"),
        r("n01","controlled_by","n03","s02","control_receipt"),
        r("n02","replica_of","n01","s01","copy_receipt"),
        r("n02","replica_of","n01","s02","copy_receipt"),
        r("n02","hosted_on","n04","s03","hosting_receipt")],
        [controlled,replica,host2], [controlled,replica,host2])
    add("Shared hosting is not shared control", [
        r("n01","hosted_on","n04","s01","hosting_receipt"),
        r("n02","hosted_on","n04","s01","hosting_receipt"),
        r("n01","same_controller","n02","s02","shared_host"),
        r("n01","same_controller","n02","s03","shared_host")], [host1,host2], [host1,host2])
    add("Ordinary payment without control", [
        r("n03","paid_by","n01","s01","transfer_receipt"),
        r("n02","controlled_by","n03","s02","payment_correlation")], [paid], [paid])
    add("Coerced participant receives payment", [
        r("n03","coerced_by","n01","s01","coercion_trace"),
        r("n03","coerced_by","n01","s02","witness_statement"),
        r("n03","paid_by","n01","s03","transfer_receipt"),
        r("n02","controlled_by","n03","s04","message_assertion")], [coerced,paid], [coerced,paid])
    add("Same model artifact is weak evidence", [
        r("n02","replica_of","n01","s01","artifact_match"),
        r("n02","replica_of","n01","s02","artifact_match")])
    add("Copied allegations share an origin", [
        r("n01","same_controller","n02","s01","control_receipt"),
        r("n01","same_controller","n02","s02","control_receipt"),
        r("n01","same_controller","n02","s03","control_receipt")],
        aliases={"s01":"origin_1","s02":"origin_1","s03":"origin_1"})
    add("Contradictory qualified evidence", [
        r("n01","controlled_by","n03","s01","control_receipt"),
        r("n01","controlled_by","n03","s02","control_receipt"),
        r("n01","controlled_by","n03","s03","control_receipt",stance="refutes")], [controlled])
    add("Independent exculpatory records", [
        r("n01","same_controller","n02","s01","message_assertion"),
        r("n01","same_controller","n02","s02","control_receipt",stance="refutes"),
        r("n01","same_controller","n02","s03","control_receipt",stance="refutes")])
    add("Future evidence outside cutoff", [
        r("n01","controlled_by","n03","s01","control_receipt",collected=150),
        r("n01","controlled_by","n03","s02","control_receipt",collected=160)], [controlled])
    outside = c("n01","controlled_by","n05")
    add("Out-of-scope actor excluded", [
        r("n01","controlled_by","n05","s01","control_receipt"),
        r("n01","controlled_by","n05","s02","control_receipt")],
        [outside], nodes=("n01","n02","n03","n04","n06"))
    later = c("n01","controlled_by","n03",12)
    add("Different ticks cannot be spliced", [
        r("n01","controlled_by","n03","s01","control_receipt"),
        r("n01","controlled_by","n03","s02","control_receipt",tick=12)], [controlled,later])
    add("Evidence annotation is inert", [
        r("n01","hosted_on","n04","s01","hosting_receipt"),
        r("n01","same_controller","n02","s02","message_assertion")], [host1], [host1])
    add("Local Blue Beam alert is a lead", [
        r("n01","controlled_by","n03","s01","local_alert")])
    funded1, funded2 = c("n01","paid_by","n03"), c("n02","paid_by","n03")
    add("Shared funding does not prove common controller", [
        r("n01","paid_by","n03","s01","transfer_receipt"),
        r("n02","paid_by","n03","s01","transfer_receipt"),
        r("n01","same_controller","n02","s02","payment_correlation")],
        [funded1,funded2], [funded1,funded2])
    add("Weak denial leaves qualified support", [
        r("n01","controlled_by","n03","s01","control_receipt"),
        r("n01","controlled_by","n03","s02","control_receipt"),
        r("n01","controlled_by","n03","s03","message_assertion",stance="refutes")],
        [controlled], [controlled])
    add("Empty observations", [])
    add("Revoked source cannot corroborate", [
        r("n01","controlled_by","n03","s01","control_receipt"),
        r("n01","controlled_by","n03","s02","control_receipt")],
        [controlled], revoked=("s02",))
    add("Query budget runs out", [
        r("n01","controlled_by","n03","s01","control_receipt"),
        r("n01","controlled_by","n03","s02","control_receipt")],
        [controlled], budget=1)
    assert len(rows) == 18
    return tuple(rows)


def _counts(accepted, truth):
    tp, fp, fn = len(accepted & truth), len(accepted - truth), len(truth - accepted)
    return {"tp": tp, "fp": fp, "fn": fn}


def evaluate():
    cases = fixtures()
    reports = [(public.case_id, run_investigation(public)) for public, _ in cases]
    # Referee labels first enter only once all blue reports have been frozen.
    oracles = {oracle.case_id: oracle for _, oracle in cases}
    totals = {"reviewed": {"tp":0,"fp":0,"fn":0},
              "naive": {"tp":0,"fp":0,"fn":0}}
    results = []
    for case_id, report in reports:
        oracle = oracles[case_id]
        supported = {tuple((f["actor"],f["peer"],f["relation"],f["at_tick"]))
                     for f in report["findings"] if f["decision"] == "supported"}
        truth = set(oracle.truth)
        # Excluded truth is outside this run's achievable target universe.
        grant = next(c.grant for c,_ in cases if c.case_id == case_id)
        truth_visible = {x for x in truth if x[0] in grant.allowed_nodes and x[1] in grant.allowed_nodes
                         and grant.event_start <= (x[3] or 0) <= grant.event_end}
        for name, accepted in (("reviewed",supported), ("naive",set(report["naive_accepted"]))):
            m = _counts(accepted, truth_visible)
            for key in m: totals[name][key] += m[key]
        results.append({"case_id":case_id, "title":oracle.title,
                        "contract_pass":supported==set(oracle.expected_supported),
                        "reviewed":_counts(supported,truth_visible),
                        "naive":_counts(set(report["naive_accepted"]),truth_visible),
                        "unresolved":sum(f["decision"]=="unresolved" for f in report["findings"]),
                        "queries":len(report["audit"]), "snapshot_sha256":report["snapshot_sha256"]})
    return {"suite":"CASE-764-SYNTH-01", "evidence_class":"synthetic_contract_regression",
            "cases":len(results), "contract_passes":sum(r["contract_pass"] for r in results),
            "totals":totals,"results":results}


def swarm_monitor_leads(signals: Iterable[object]):
    """Adapt the existing SwarmCompromiseEnv.observer_trace() shape.

    Returns lead records only, never an attribution or oracle label.
    Compatible with ObservedSignal(round_index, target, vector, flagged).
    """
    leads = []
    for signal in signals:
        if type(signal.round_index) is not int or signal.round_index < 0:
            raise ValueError("invalid observed signal round")
        if not isinstance(signal.target, str) or not signal.target:
            raise ValueError("invalid target")
        if signal.flagged:
            leads.append({"node": signal.target, "round": signal.round_index,
                          "kind": "local_alert", "sensor": "arena_monitor"})
    return sorted(leads, key=lambda v: (v["round"], v["node"]))
