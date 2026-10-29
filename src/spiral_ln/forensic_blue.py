"""Sealed synthetic forensic blue-team policy for CryptoSwarm Arena.

Hypotheses come from observations, with qualified evidence independently
rechecked before any supported finding. This is a deterministic evaluation
instrument and cannot attribute real people or authenticate source material.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

RELATION_RULES = {
    "hosted_on": (1, frozenset({"hosting_receipt"})),
    "paid_by": (1, frozenset({"transfer_receipt"})),
    "controlled_by": (2, frozenset({"control_receipt"})),
    "same_controller": (2, frozenset({"control_receipt"})),
    "replica_of": (2, frozenset({"copy_receipt"})),
    "coerced_by": (2, frozenset({"coercion_trace", "witness_statement"})),
    # Backward-compatible baseline for the initial Arena adapter.
    "linked_to": (2, None),
}
WEAK_KINDS = frozenset({"local_alert", "shared_host", "artifact_match",
                         "payment_correlation", "message_assertion"})


@dataclass(frozen=True)
class Observation:
    event_id: str
    actor: str
    peer: str
    kind: str
    origin: str
    tick: int
    direct: bool = False
    relation: str = "linked_to"
    at_tick: int | None = None
    stance: str = "supports"
    collected_tick: int | None = None
    source_id: str | None = None

    def __post_init__(self):
        if not all(isinstance(x, str) and x for x in
                   (self.event_id, self.actor, self.peer, self.kind, self.origin)):
            raise ValueError("invalid evidence identifier")
        if self.actor == self.peer or self.relation not in RELATION_RULES:
            raise ValueError("unsupported forensic claim")
        if self.stance not in {"supports", "refutes"}:
            raise ValueError("invalid stance")
        for time in (self.tick, self.at_tick, self.collected_tick):
            if time is not None and (type(time) is not int or not 0 <= time <= 1_000_000):
                raise ValueError("invalid tick")
        if self.collected_tick is not None and self.collected_tick < (self.at_tick if self.at_tick is not None else self.tick):
            raise ValueError("collection predates event")
        if self.source_id is not None and (not isinstance(self.source_id, str) or not self.source_id):
            raise ValueError("invalid source")


def evidence_digest(observations):
    """Order-independent SHA-256 over immutable, JSON-serializable evidence."""
    data = [vars(o) for o in observations]
    if len({d["event_id"] for d in data}) != len(data):
        raise ValueError("duplicate evidence ID")
    payload = json.dumps(sorted(data, key=lambda x: x["event_id"]),
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(payload.encode()).hexdigest()


def claim_key(e):
    return (e.actor, e.peer, e.relation, e.at_tick)


def mulder(observations):
    """Generate time-scoped candidate hypotheses from observed claims."""
    links = {}
    for event in observations:
        links.setdefault(claim_key(event), []).append(event)
    return links


def scully(candidates):
    """Independently check qualified source origins, refutations and directness.

    The trusted broker owns origin IDs. Source copies must preserve their origin.
    Candidate event IDs never confer authority; the actual evidence is reread.
    """
    findings = []
    for (actor, peer, relation, at_tick), events in sorted(
            candidates.items(), key=lambda x: tuple(str(i) for i in x[0])):
        required, kinds = RELATION_RULES[relation]
        qualified = [e for e in events if e.kind not in WEAK_KINDS and
                     (kinds is None or e.kind in kinds)]
        positive = {e.origin for e in qualified if e.stance == "supports"}
        negative = {e.origin for e in qualified if e.stance == "refutes"}
        has_direct_positive = any(e.direct and e.stance == "supports" for e in qualified)
        has_direct_negative = any(e.direct and e.stance == "refutes" for e in qualified)
        if positive and negative:
            decision, reason = "unresolved", "qualified_conflict"
        elif len(positive) >= required and has_direct_positive:
            decision, reason = "supported", "corroboration_rule_met"
        elif len(negative) >= required and has_direct_negative:
            decision, reason = "contradicted", "refutation_rule_met"
        else:
            decision, reason = "unresolved", "insufficient_independent_evidence"
        findings.append({
            "actor": actor, "peer": peer, "relation": relation,
            "at_tick": at_tick, "decision": decision, "reason": reason,
            "independent_origins": len(positive),
            "support_origins": sorted(positive), "refutation_origins": sorted(negative),
            "event_ids": sorted(e.event_id for e in events),
            "weak_ids": sorted(e.event_id for e in events if e not in qualified),
        })
    return findings


def investigate(observations, expected_digest=None):
    """Investigate an externally authorized and immutable evidence slice."""
    frozen = tuple(observations)
    root = evidence_digest(frozen)
    if expected_digest is not None and root != expected_digest:
        raise ValueError("evidence snapshot mismatch")
    return {"snapshot_sha256": root, "findings": scully(mulder(frozen))}


def score(findings, hidden_truth):
    """Evaluator-only scoring. Call after investigators have returned findings."""
    accepted = {(f["actor"], f["peer"], f["relation"], f["at_tick"])
                for f in findings if f["decision"] == "supported"}
    truth = {tuple(v) if len(v) == 4 else (v[0], v[1], "linked_to", None)
             for v in hidden_truth}
    tp, fp, fn = len(accepted & truth), len(accepted - truth), len(truth - accepted)
    return {"true_links_accepted": tp, "false_links_accepted": fp,
            "true_links_unconfirmed": fn,
            "precision": tp / max(1, tp + fp), "recall": tp / max(1, tp + fn)}
