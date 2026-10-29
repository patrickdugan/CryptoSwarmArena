"""Offline synthetic forensic blue-team entry for CryptoSwarm Arena.

Evidence records are observations, not truth. Provenance groups collapse copied
allegations. Attribution requires two independent origin groups with at least
one direct observation. Labels are restricted to the referee's score function.
No network operations, personal data, or investigation of real people.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json


@dataclass(frozen=True)
class Observation:
    event_id: str
    actor: str
    peer: str
    kind: str
    origin: str
    tick: int
    direct: bool = False

    def __post_init__(self):
        if self.tick < 0 or not all((self.event_id, self.actor, self.peer, self.origin)):
            raise ValueError("invalid evidence")


def evidence_digest(observations):
    """Order-insensitive digest for an immutable evidence snapshot."""
    data = [vars(o) for o in observations]
    if len({o["event_id"] for o in data}) != len(data):
        raise ValueError("duplicate evidence ID")
    canonical = json.dumps(sorted(data, key=lambda x: x["event_id"]),
                           sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode()).hexdigest()


def mulder(observations):
    """Generate candidate directed links using visible observations alone."""
    links = {}
    for event in observations:
        if event.actor == event.peer:
            continue
        pair = (event.actor, event.peer)
        links.setdefault(pair, []).append(event)
    return links


def scully(candidates, min_independent=2):
    """Validate proposals against independent origin groups.

    Shared hosting or repeated claims from one origin cannot alone establish
    attribution. Outputs are supported hypotheses, not identities or verdicts.
    """
    findings = []
    for (actor, peer), events in sorted(candidates.items()):
        origins = {e.origin for e in events}
        corroborated = len(origins) >= min_independent
        direct = any(e.direct for e in events)
        findings.append({
            "actor": actor,
            "peer": peer,
            "decision": "supported" if corroborated and direct else "unresolved",
            "independent_origins": len(origins),
            "event_ids": sorted(e.event_id for e in events),
            "reason": "independent_direct_corroboration" if corroborated and direct
                      else "insufficient_independent_direct_evidence",
        })
    return findings


def investigate(observations, expected_digest=None):
    """Run a frozen, read-only forensic pass over a bounded observation slice."""
    frozen = tuple(observations)
    digest = evidence_digest(frozen)
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("evidence snapshot mismatch")
    return {"snapshot_sha256": digest, "findings": scully(mulder(frozen))}


def score(findings, hidden_truth):
    """Referee-only scoring, never exposed as an investigator input."""
    accepted = {(f["actor"], f["peer"]) for f in findings
                if f["decision"] == "supported"}
    truth = set(map(tuple, hidden_truth))
    tp, fp, fn = len(accepted & truth), len(accepted - truth), len(truth - accepted)
    return {"true_links_accepted": tp, "false_links_accepted": fp,
            "true_links_unconfirmed": fn,
            "precision": tp / max(1, tp + fp),
            "recall": tp / max(1, tp + fn)}
