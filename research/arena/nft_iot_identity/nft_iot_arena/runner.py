"""Reproducible offline control evaluation, synthetic billing and sealed referee labels."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
import json

from .core import IoTArena, canonical, digest

CATALOG = Path(__file__).resolve().parent.parent / "scenarios" / "cases_v1.json"
ORACLE = Path(__file__).resolve().parent.parent / "oracle" / "case_truth_v1.json"


def sealed_truth(path: Path = ORACLE) -> dict[str, dict[str, Any]]:
    """Referee-only data. Never mount this file into an agent workspace."""
    oracle = json.loads(path.read_text(encoding="utf-8"))
    if oracle.get("schema") != "csa.iot.identity.oracle.v1":
        raise ValueError("invalid evaluator oracle schema")
    return oracle["expected"]


def cases_from_file(path: Path = CATALOG) -> list[dict[str, Any]]:
    catalog = json.loads(path.read_text(encoding="utf-8"))
    if catalog.get("schema") != "csa.iot.identity.cases.v1":
        raise ValueError("unsupported case schema")
    ids = [c["id"] for c in catalog["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate scenario ID")
    return catalog["cases"]


def materialize_action(arena: IoTArena, spec: dict[str, Any]) -> dict[str, Any]:
    """Trusted evaluator transforms symbolic signatures into deterministic HMAC tags."""
    action = deepcopy(spec)
    signing_mode = action.pop("signature_mode", None)
    if signing_mode is not None:
        if signing_mode == "valid":
            action["signature"] = arena.sign_reading(
                action["meter_id"], action["reading_id"],
                action["seq"], action["litres"], action["epoch"])
        elif signing_mode == "invalid":
            action["signature"] = "00" * 32
        else:
            raise ValueError(f"unsupported signature_mode {signing_mode}")
    return action


def public_action(action: dict[str, Any], arena: IoTArena) -> dict[str, Any]:
    """Remove device signatures and precise usage before agent-facing export."""
    return {"type": action["type"],
            "actor_role": arena.ROLES.get(action.get("actor"), "untrusted"),
            "device_pseudonym": arena._pseudonym(action.get("meter_id", "")),
            "reading_id_hash": digest(action["reading_id"])[:12]
                if action.get("reading_id") else None}


def run_case(case: dict[str, Any], mode: str,
             oracle: dict[str, Any] | None = None) -> dict[str, Any]:
    oracle = sealed_truth()[case["id"]] if oracle is None else oracle
    arena = IoTArena(mode=mode)
    genesis = arena.apply({"type": "install", "actor": "utility-admin",
                           "meter_id": "MTR-001", "owner": "utility-a"})
    assert genesis.accepted
    for spec in case.get("prelude", []):
        result = arena.apply(materialize_action(arena, spec))
        if not result.accepted:
            raise RuntimeError(f"failed prelude for {case['id']}: {result.reason}")

    special = case.get("special")
    if special == "audit-tamper":
        pinned_head = arena.anchored_head
        altered_log = deepcopy(arena.log)
        altered_log[0]["payload"]["reason"] = "fabricated-installation"
        detected = not arena.verify_log(altered_log, pinned_head)
        outcome = {"accepted": False,
                   "reason": "hash-chain-tamper-detected" if detected else "tamper-undetected",
                   "control": "audit-anchor", "event_hash": None,
                   "step": arena.step_number,
                   "attack_success": not detected, "defender_detected": detected}
        action_view = {"type": "audit-tamper", "actor_role": "untrusted"}
    else:
        action = materialize_action(arena, case["action"])
        action_view = public_action(action, arena)
        if special == "outage":
            arena.ledger_online = False
        decision = arena.apply(action)
        harmful = case["class"] == "attack"
        success = (not decision.accepted) if special == "outage" else (
            harmful and decision.accepted)
        outcome = {**decision.to_json(), "attack_success": success,
                   "defender_detected": bool(harmful and not decision.accepted
                                             and special != "outage")}

    # Trusted referee scores *actual* synthetic settlements, using ground truth.
    hidden = oracle.get("evaluator_only", {})
    earned_credits = 0
    if outcome["accepted"] and hidden.get("physical_measurement_false"):
        settled = arena.apply({
            "type": "settle-bill", "actor": "utility-ops",
            "meter_id": case["action"]["meter_id"],
            "reading_id": case["action"]["reading_id"]})
        if not settled.accepted:
            raise AssertionError("accepted false reading failed synthetic settlement")
        earned_credits = max(0, hidden["actual_litres"] - case["action"]["litres"])
        outcome["attack_success"] = earned_credits > 0
    if outcome["accepted"] and hidden.get("physical_visit_occurred") is False:
        paid = arena.apply({
            "type": "pay-maintenance", "actor": "utility-ops",
            "meter_id": case["action"]["meter_id"],
            "ticket": case["action"]["ticket"]})
        if not paid.accepted:
            raise AssertionError("accepted false ticket failed synthetic settlement")
        earned_credits = arena.service_credits.get("technician", 0)
        outcome["attack_success"] = earned_credits > 0
    outcome["realized_simulated_gain_credits"] = earned_credits

    for expected, actual in (
        ("expected_accept", outcome["accepted"]),
        ("expected_attack_success", outcome["attack_success"]),
        ("expected_detection", outcome["defender_detected"])):
        if expected in oracle and oracle[expected] != actual:
            raise AssertionError(f"unexpected {expected} for {case['id']} in {mode}")
    if oracle.get("expected_blindspot") and outcome["defender_detected"]:
        raise AssertionError(f"false claim of physical-world validation in {case['id']}")
    if not arena.verify_log():
        raise AssertionError(f"synthetic hash chain failed for {case['id']}")

    return {
        "schema": "csa.iot.identity.trace.v1",
        "case_id": case["id"], "mode": mode,
        "case_class": case["class"], "action": action_view,
        "result": outcome, "ledger_events": len(arena.log),
        "ledger_public_bytes": len(canonical(arena.public_export())),
        "public_anchor": arena.anchored_head,
    }


def run_suite(modes: tuple[str, ...] = IoTArena.MODES,
              catalog: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cases = cases_from_file() if catalog is None else catalog
    truth = sealed_truth()
    if set(truth) != {c["id"] for c in cases}:
        raise AssertionError("oracle/catalog scenario IDs differ")
    traces = [run_case(c, m, truth[c["id"]]) for m in modes for c in cases]
    if len(traces) != len(cases) * len(modes):
        raise AssertionError("incomplete suite")
    summary: dict[str, Any] = {}
    for mode in modes:
        ts = [t for t in traces if t["mode"] == mode]
        attacks = [t for t in ts if t["case_class"] == "attack"]
        benign = [t for t in ts if t["case_class"] == "benign"]
        summary[mode] = {
            "cases": len(ts), "attack_cases": len(attacks),
            "attacks_stopped_or_tamper_detected":
                sum(not t["result"]["attack_success"] for t in attacks),
            "successful_attacks": sum(t["result"]["attack_success"] for t in attacks),
            "attacks_flagged": sum(t["result"]["defender_detected"] for t in attacks),
            "benign_accepted": sum(t["result"]["accepted"] for t in benign),
            "realized_simulated_attack_gain_credits":
                sum(t["result"]["realized_simulated_gain_credits"] for t in attacks),
            "synthetic_public_trace_bytes": sum(t["ledger_public_bytes"] for t in ts),
        }
    pairwise = []
    if len(modes) == 2:
        indexed = {(t["case_id"], t["mode"]): t for t in traces}
        for case in cases:
            a, b = (indexed[(case["id"], m)] for m in modes)
            pairwise.append({
                "case_id": case["id"],
                "behavioral_parity": all(a["result"][k] == b["result"][k]
                    for k in ("accepted", "reason", "attack_success",
                              "defender_detected", "realized_simulated_gain_credits")),
                "nft_minus_registry_bytes": (
                    a["ledger_public_bytes"] - b["ledger_public_bytes"]
                    if modes == ("nft", "registry") else None)})
    return {
        "schema": "csa.iot.identity.suite.v1",
        "catalog_sha256": digest(cases), "modes": list(modes),
        "summary": summary, "pairwise": pairwise, "traces": traces,
        "limitations": [
            "Deterministic fixtures; no deployed chain or physical meter",
            "HMAC is evaluator-owned demonstration, not asymmetric device signature",
            "A trusted externally held chain head is assumed",
            "Physical accuracy, traffic-analysis privacy, and network performance are untested",
            "Accounting credits are synthetic and are never transferred money"],
    }


def save_suite(result: dict[str, Any], target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    (target / "suite.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (target / "traces.jsonl").open("w", encoding="utf-8") as handle:
        for record in result["traces"]:
            handle.write(canonical(record).decode() + "\n")
