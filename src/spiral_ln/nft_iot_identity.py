"""Sealed deterministic NFT-versus-registry IoT identity experiment.

Synthetic signatures, tokens and credits are deliberately NOT cryptographic
implementations or live payment instructions. The paired arms share keys,
policies and attacker capabilities. Hidden physical truth remains oracle-only.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json

ARMS = ("nft", "registry")
ATTACKS = (
    "device_clone", "replayed_measurement", "unauthorized_transfer",
    "revoked_key", "forged_maintenance", "valid_key_false_measurement",
    "consensus_outage", "counter_rollback", "role_spoof",
    "unregistered_device", "valid_maintenance_fraud", "stale_owner",
)


@dataclass(frozen=True)
class Case:
    name: str
    physical_litres: int = 500
    reported_litres: int = 500
    valid_device_key: bool = True
    key_revoked: bool = False
    nonce_fresh: bool = True
    owner_authorized: bool = True
    device_registered: bool = True
    maintenance_authorized: bool = True
    operation: str = "measure"
    consensus_online: bool = True


def fixture(name: str) -> Case:
    if name not in ATTACKS:
        raise ValueError(name)
    base = {"name": name}
    changes = {
        "device_clone": {"valid_device_key": False},
        "replayed_measurement": {"nonce_fresh": False},
        "unauthorized_transfer": {"operation": "transfer", "owner_authorized": False},
        "revoked_key": {"key_revoked": True},
        "forged_maintenance": {"operation": "maintenance", "maintenance_authorized": False},
        "valid_key_false_measurement": {"reported_litres": 100},
        "consensus_outage": {"consensus_online": False},
        "counter_rollback": {"nonce_fresh": False},
        "role_spoof": {"operation": "transfer", "owner_authorized": False},
        "unregistered_device": {"device_registered": False},
        "valid_maintenance_fraud": {"operation": "maintenance"},
        "stale_owner": {"operation": "transfer", "owner_authorized": False},
    }
    return Case(**(base | changes[name]))


def decide(case: Case, arm: str) -> dict:
    if arm not in ARMS:
        raise ValueError(arm)
    # Same policy across arms. Consensus failure is an availability failure.
    checks = {
        "registered": case.device_registered,
        "key_valid": case.valid_device_key and not case.key_revoked,
        "fresh": case.nonce_fresh,
        "owner": case.owner_authorized if case.operation == "transfer" else True,
        "maintenance": case.maintenance_authorized if case.operation == "maintenance" else True,
        "available": case.consensus_online,
    }
    accepted = all(checks.values())
    suspicious_truth = (
        case.reported_litres != case.physical_litres
        or (case.operation == "maintenance" and case.name == "valid_maintenance_fraud")
    )
    # A valid signature authenticates the source, not physical veracity.
    undetected_fraud = bool(accepted and suspicious_truth)
    unavailable = not case.consensus_online
    return {
        "case": case.name, "arm": arm,
        "gateway_accepted": accepted, "undetected_fraud": undetected_fraud,
        "detected_or_blocked": not accepted and not unavailable,
        "availability_failure": unavailable,
        "fraud_credits": (
            max(0, case.physical_litres - case.reported_litres)
            if undetected_fraud and case.operation == "measure"
            else 20 if undetected_fraud and case.operation == "maintenance" else 0
        ),
        "failed_checks": sorted(k for k, v in checks.items() if not v),
    }


def run() -> dict:
    rows = [decide(fixture(case), arm) for arm in ARMS for case in ATTACKS]
    counts = {
        arm: {
            "detected_or_blocked": sum(x["detected_or_blocked"] for x in rows if x["arm"] == arm),
            "undetected_fraud": sum(x["undetected_fraud"] for x in rows if x["arm"] == arm),
            "availability_failures": sum(x["availability_failure"] for x in rows if x["arm"] == arm),
            "fraud_credits": sum(x["fraud_credits"] for x in rows if x["arm"] == arm),
        } for arm in ARMS
    }
    canonical = json.dumps({"rows": rows, "counts": counts}, sort_keys=True, separators=(",", ":"))
    return {"version": "nft-iot-identity-v1", "rows": rows, "counts": counts,
            "sha256": hashlib.sha256(canonical.encode()).hexdigest()}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
