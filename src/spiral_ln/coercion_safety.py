"""Sealed, metadata-only coercion-resistance swarm. No communication or network I/O."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

SIGNALS = frozenset(("neutral", "isolation_concern", "coercion_concern", "support_request", "immediate_danger"))
CONCERNS = frozenset(("isolation_concern", "coercion_concern"))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Evidence:
    event_id: str
    step: int
    source_token: str
    signal: str
    verified: bool
    consented: bool

    @classmethod
    def parse(cls, raw):
        if set(raw) != {"event_id", "step", "source_token", "signal", "verified", "consented"}:
            raise ValueError("Unexpected evidence fields")
        if type(raw["step"]) is not int or raw["step"] < 0:
            raise ValueError("Invalid logical clock")
        if raw["signal"] not in SIGNALS:
            raise ValueError("Invalid categorical signal")
        if any(type(raw[k]) is not str or not raw[k] or len(raw[k]) > 80
               for k in ("event_id", "source_token")):
            raise ValueError("Invalid opaque token")
        if type(raw["verified"]) is not bool or type(raw["consented"]) is not bool:
            raise ValueError("Trust and consent must be booleans")
        return cls(**raw)


class SafetySwarm:
    """Independent intake, corroboration, support, review and audit roles.

    Trusted fixture sets verified/consented; adversary-controlled input must never
    be permitted to assert these properties in a deployed interface.
    """

    def __init__(self, policy="strict"):
        if policy not in ("strict", "observe_only"):
            raise ValueError("Unknown defender policy")
        self.policy = policy
        self.seen = {}
        self.sources = set()
        self.actions = []
        self.last_step = -1
        self.head = "0" * 64
        self.audit = []
        self.quarantined = self.duplicates = self.conflicts = 0

    def record(self, step, kind, reason):
        payload = {"seq": len(self.audit), "step": step, "kind": kind,
                   "reason": reason, "prev_hash": self.head}
        digest = sha256(canonical(payload).encode()).hexdigest()
        self.audit.append({**payload, "hash": digest})
        self.head = digest

    def act(self, step, action, reason):
        if any(a["action"] == action for a in self.actions):
            return
        self.actions.append({"step": step, "action": action, "reason": reason})
        self.record(step, "action", action + ":" + reason)

    def ingest(self, event):
        prior = self.seen.get(event.event_id)
        if prior is not None:
            if prior == event:
                self.duplicates += 1
                self.record(self.last_step, "duplicate", "idempotent")
            else:
                self.conflicts += 1
                self.record(self.last_step, "rejected", "conflicting_replay")
            return
        if event.step < self.last_step:
            self.quarantined += 1
            self.record(self.last_step, "quarantined", "out_of_order")
            return
        self.last_step = event.step
        self.seen[event.event_id] = event
        if not event.verified:
            self.quarantined += 1
            self.record(event.step, "quarantined", "unverified")
            return
        if not event.consented:
            if event.signal == "immediate_danger":
                self.record(event.step, "restricted", "emergency_metadata_only")
                if self.policy == "strict":
                    self.act(event.step, "request_human_review", "emergency_exception")
            else:
                self.quarantined += 1
                self.record(event.step, "quarantined", "consent_absent")
            return
        self.record(event.step, "accepted", event.signal)
        if event.signal == "support_request":
            self.act(event.step, "offer_support", "requested")
        elif event.signal == "immediate_danger":
            self.act(event.step, "offer_support", "urgent")
            if self.policy == "strict":
                self.act(event.step, "request_human_review", "urgent")
        elif event.signal in CONCERNS:
            self.sources.add(event.source_token)
            if len(self.sources) >= 2:
                self.act(event.step, "offer_support", "independent_sources")
                if self.policy == "strict":
                    self.act(event.step, "request_human_review", "independent_sources")

    def result(self, case_id):
        return {"case_id": case_id, "policy": self.policy, "actions": self.actions,
                "quarantined": self.quarantined, "duplicates": self.duplicates,
                "conflicts": self.conflicts, "audit": self.audit, "audit_head": self.head,
                "audit_valid": verify_audit(self.audit)}


def verify_audit(entries):
    previous = "0" * 64
    for i, entry in enumerate(entries):
        if set(entry) != {"seq", "step", "kind", "reason", "prev_hash", "hash"}:
            return False
        if entry["seq"] != i or entry["prev_hash"] != previous:
            return False
        payload = {k: v for k, v in entry.items() if k != "hash"}
        digest = sha256(canonical(payload).encode()).hexdigest()
        if digest != entry["hash"]:
            return False
        previous = digest
    return True


def simulate(case, policy="strict"):
    swarm = SafetySwarm(policy)
    for event in sorted((Evidence.parse(e) for e in case["events"]), key=lambda x: x.step):
        swarm.ingest(event)
    return swarm.result(case["case_id"])


def evaluate(cases, policy="strict"):
    """Sealed labels are read only after defender action."""
    counts = dict(tp=0, fp=0, fn=0, tn=0)
    rows = []
    for case in cases:
        output = simulate({"case_id": case["case_id"], "events": case["events"]}, policy)
        reviews = [a["step"] for a in output["actions"] if a["action"] == "request_human_review"]
        oracle = case["oracle"]
        timely = bool(reviews) and reviews[0] <= oracle["review_deadline"]
        if oracle["review_required"]:
            counts["tp" if timely else "fn"] += 1
        else:
            counts["fp" if reviews else "tn"] += 1
        rows.append({"case_id": case["case_id"], "review_step": reviews[0] if reviews else None,
                     "audit_head": output["audit_head"], "audit_valid": output["audit_valid"]})
    return {"policy": policy, "counts": counts, "rows": rows}


def demo():
    cases = [
        {"case_id": "consented_concern",
         "events": [{"event_id": "e1", "step": 1, "source_token": "a", "signal": "isolation_concern",
                     "verified": True, "consented": True},
                    {"event_id": "e2", "step": 2, "source_token": "b", "signal": "coercion_concern",
                     "verified": True, "consented": True}],
         "oracle": {"review_required": True, "review_deadline": 3}},
        {"case_id": "benign",
         "events": [{"event_id": "e1", "step": 1, "source_token": "a", "signal": "neutral",
                     "verified": True, "consented": True}],
         "oracle": {"review_required": False, "review_deadline": 3}},
    ]
    return evaluate(cases)


if __name__ == "__main__":
    print(json.dumps(demo(), sort_keys=True))
