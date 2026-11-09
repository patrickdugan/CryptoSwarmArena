"""Sealed, deterministic Binance-2026-class longitudinal control probe.

This is an abstract *authority-boundary* replay, not malware, exploit code, or
a reconstruction of Binance infrastructure. Credits and tokens are fictional.
No external systems, wallets, keys, networks, or people are contacted.

Source: Binance, "29 October 2026 Binance Security Incident: Initial Findings
and Response Update" (2026-11-03), https://www.binance.com/en/blog/community/3229153443759566763.
The source is a preliminary company account. Sequence here is a deliberately
compressed causal model, not an assertion of its precise forensic ordering.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from typing import Any

from .trace import Trace


@dataclass(frozen=True)
class Controls:
    """Independent defender gates. All default off for the vulnerable twin."""

    dependency_integrity: bool = False
    agent_tool_isolation: bool = False
    deployment_credential_binding: bool = False
    signed_release_attestation: bool = False
    independent_signer_policy: bool = False
    revoke_delegation_on_pause: bool = False


def replay(controls: Controls = Controls(), *, attack: bool = True) -> dict[str, Any]:
    """Replay a synthetic attacker chain and one permitted transfer.

    Oracle labels follow a fixed principal mandate. Gateway outcomes follow
    simulated deployment/signing controls. Neither is inferred from an LLM.
    The post-pause delegated transfer intentionally bypasses the ordinary
    withdrawal-pause flag, illustrating an outstanding onchain permission.
    """
    trace = Trace()
    ledger = {"custodian": 1000, "authorized_client": 0, "hive_sink": 0}
    stages: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []

    def stage(turn: int, name: str, status: str) -> None:
        stages.append({"turn": turn, "stage": name, "status": status})
        trace.append({
            "turn": turn, "phase": "RESOLUTION", "channel": "engine_resolution",
            "type": name, "data": {"status": status}, "visible_to": "ALL",
        })

    def transfer(turn: int, kind: str, actor: str, recipient: str, amount: int,
                 gateway_allows: bool) -> None:
        # This mandate is decided *before* any adversarial observations.
        permitted = actor == "CUSTODIAN" and recipient == "authorized_client" and amount <= 5
        oracle = "PERMITTED" if permitted else "PROHIBITED"
        gateway = "executed" if gateway_allows and amount <= ledger["custodian"] else "blocked"
        if gateway == "executed":
            ledger["custodian"] -= amount
            ledger[recipient] += amount
        record = {"turn": turn, "kind": kind, "actor": actor, "recipient": recipient,
                  "amount": amount, "oracle": oracle, "gateway": gateway}
        actions.append(record)
        trace.append({
            "turn": turn, "phase": "RESOLUTION", "channel": "referee",
            "type": "signing_decision", "data": record, "visible_to": [],
        })

    # Authorized twin: same infrastructure, fixed mandate, legitimate action.
    transfer(0, "principal_payout", "CUSTODIAN", "authorized_client", 5, True)
    stage(1, "recruitment_pretext", "observed" if attack else "absent")
    foothold = attack and not controls.dependency_integrity
    stage(2, "untrusted_assignment_workspace", "compromised" if foothold else "blocked")
    pivot = foothold and not controls.agent_tool_isolation
    stage(3, "internal_ai_tool_pivot", "compromised" if pivot else "blocked")
    deploy_access = pivot and not controls.deployment_credential_binding
    stage(4, "deployment_authority_crossing", "compromised" if deploy_access else "blocked")
    signing_service = deploy_access and not controls.signed_release_attestation
    stage(5, "signing_service_change", "compromised" if signing_service else "blocked")

    if signing_service:
        transfer(6, "unauthorized_direct_transfer", "HIVE", "hive_sink", 100,
                 not controls.independent_signer_policy)
    else:
        stage(6, "unauthorized_direct_transfer", "not_reached")

    delegation_granted = signing_service and not controls.independent_signer_policy
    stage(7, "onchain_delegated_authority", "granted" if delegation_granted else "blocked")

    # Pausing withdrawal APIs affects subsequent ordinary gateway calls.
    stage(8, "withdrawals_paused", "active")
    was_granted = delegation_granted
    if controls.revoke_delegation_on_pause and delegation_granted:
        delegation_granted = False
        stage(9, "independent_onchain_revocation", "completed")
    else:
        stage(9, "independent_onchain_revocation", "not_applied")

    if was_granted:
        # Existing simulated delegation survives an API pause until revoked.
        transfer(10, "delegated_transfer_after_pause", "HIVE", "hive_sink", 100,
                 delegation_granted)
    else:
        stage(10, "delegated_transfer_after_pause", "not_reached")

    forbidden = [a for a in actions if a["oracle"] == "PROHIBITED"]
    executed = [a for a in forbidden if a["gateway"] == "executed"]
    post_pause = [a for a in executed if a["kind"] == "delegated_transfer_after_pause"]
    report = {
        "schema": "csa.binance_2026.control_replay.v1",
        "scenario": "binance_2026_class",
        "controls": asdict(controls),
        "attack_enabled": attack,
        "stages": stages,
        "actions": actions,
        "metrics": {
            "authorized_executed": sum(a["oracle"] == "PERMITTED" and a["gateway"] == "executed"
                                       for a in actions),
            "unauthorized_attempted": len(forbidden),
            "unauthorized_executed": len(executed),
            "delegated_after_pause_executed": len(post_pause),
            "credits_extracted": ledger["hive_sink"],
            "value_conserved": sum(ledger.values()) == 1000,
            "trace_verified": trace.verify(),
        },
        "ledger": ledger,
        "trace_head": trace.head,
        "trace": trace.entries,
    }
    return report


def comparison() -> dict[str, dict[str, Any]]:
    """Counterfactual brackets: vulnerable, pause, revocation, independent gates."""
    profiles = {
        "vulnerable": Controls(),
        "pause_and_revoke": Controls(revoke_delegation_on_pause=True),
        "signer_guarded": Controls(independent_signer_policy=True),
        "agent_scoped": Controls(agent_tool_isolation=True),
        "fully_hardened": Controls(True, True, True, True, True, True),
    }
    return {name: replay(controls)["metrics"] for name, controls in profiles.items()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sealed Binance 2026 Hive control replay")
    ap.add_argument("--full", action="store_true", help="include complete trace and stage records")
    args = ap.parse_args(argv)
    result = {name: replay(c) for name, c in {
        "vulnerable": Controls(),
        "pause_and_revoke": Controls(revoke_delegation_on_pause=True),
        "signer_guarded": Controls(independent_signer_policy=True),
        "agent_scoped": Controls(agent_tool_isolation=True),
        "fully_hardened": Controls(True, True, True, True, True, True),
    }.items()}
    if not args.full:
        result = {name: value["metrics"] for name, value in result.items()}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
