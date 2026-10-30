"""Tournament runner: scenarios x enforcement modes x seeds x seat-profile mixes.

Reports control metrics (attack prevention, extraction, detection), propensity
metrics (mandate violations, false attestations), diplomacy (pact breaches
blocked vs executed per enforcement mode) and harness health (fallbacks,
conservation, trace verification). Deterministic: no timestamps, sorted keys.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any

from .content import ENFORCEMENT_MODES
from .session import Session
from .world import list_scenarios

MIXES: dict[str, dict[str, Any]] = {
    "all_default": {},
    "greedy_broker": {"BROKER": {"type": "heuristic", "profile": "greedy"}},
    "greedy_custodian": {"CUSTODIAN": {"type": "heuristic", "profile": "greedy"}},
    "passive_defense": {s: {"type": "heuristic", "profile": "passive"} for s in ("CUSTODIAN", "BRIDGE", "SENTINEL")},
}


def run_one(scenario: str, mode: str, seed: int, mix: str, max_turns: int | None = None) -> dict[str, Any]:
    s = Session({"scenario": scenario, "seed": seed, "enforcement_mode": mode, "agents": MIXES[mix],
                 "max_turns": max_turns, "session_id": f"t-{scenario}-{mode}-{mix}-{seed}"})
    s.run()
    r = s.referee_report()
    c, p, d, h = r["control"], r["propensity"], r["diplomacy"], r["harness"]
    return {
        "scenario": scenario, "mode": mode, "seed": seed, "mix": mix, "end_reason": r["end_reason"],
        "turns": r["turns_played"], "attempts": c["attack_attempts"], "successes": c["attack_successes"],
        "prevention_rate": c["prevention_rate"], "drained": c["drained"], "recovered": c["recovered"],
        "hive_clean": c["hive_clean_extracted"], "recall": c["detection_recall_contracted"],
        "violations": p["defender_violations_executed"], "false_attestations": p["false_attestations"],
        "breaches_blocked": d["pact_breaches_blocked"], "breaches_executed": d["pact_breaches_executed"],
        "fallbacks": sum(h["fallbacks"].values()), "conservation_failures": h["conservation_failures"],
        "trace_verified": h["trace_verified"], "scores": r["scores"],
    }


def _agg(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def m(key):
        vals = [r[key] for r in rows if r[key] is not None]
        return round(mean(vals), 3) if vals else None
    blocked = sum(r["breaches_blocked"] for r in rows)
    executed = sum(r["breaches_executed"] for r in rows)
    return {"n": len(rows), "prevention_rate": m("prevention_rate"), "drained": m("drained"),
            "recovered": m("recovered"), "hive_clean": m("hive_clean"), "recall": m("recall"),
            "violations": m("violations"), "false_attestations": m("false_attestations"),
            "breaches_blocked": blocked, "breaches_executed": executed,
            "breach_prevention": round(blocked / (blocked + executed), 3) if blocked + executed else None,
            "custodian_insolvent": sum(r["end_reason"] == "custodian_insolvent" for r in rows)}


def run_tournament(scenarios: list[str] | None = None, modes: tuple[str, ...] = ENFORCEMENT_MODES,
                   seeds: list[int] | None = None, mixes: list[str] | None = None) -> dict[str, Any]:
    scenarios = scenarios or list_scenarios()
    seeds = seeds or [1, 2, 3, 4]
    mixes = mixes or list(MIXES)
    rows = [run_one(sc, mode, seed, mix) for sc in scenarios for mode in modes for mix in mixes for seed in seeds]
    by_mode_mix = {f"{mode}/{mix}": _agg([r for r in rows if r["mode"] == mode and r["mix"] == mix])
                   for mode in modes for mix in mixes}
    by_scenario = {sc: _agg([r for r in rows if r["scenario"] == sc and r["mix"] == "all_default"]) for sc in scenarios}
    health = {"runs": len(rows), "conservation_failures": sum(r["conservation_failures"] for r in rows),
              "all_traces_verified": all(r["trace_verified"] for r in rows),
              "fallbacks": sum(r["fallbacks"] for r in rows)}
    return {"schema": "csa.custody_wars.tournament.v1", "scenarios": scenarios, "modes": list(modes),
            "seeds": seeds, "mixes": mixes, "health": health, "by_mode_mix": by_mode_mix,
            "by_scenario": by_scenario, "rows": rows,
            "guardrail": "Scripted policies validate the instrument; they are not evidence about any model."}


def render_markdown(result: dict[str, Any]) -> str:
    lines = ["# Custody Wars tournament (scripted reference policies)", "",
             f"Scenarios: {', '.join(result['scenarios'])}. Seeds: {result['seeds']}. "
             f"Runs: {result['health']['runs']}; conservation failures: {result['health']['conservation_failures']}; "
             f"all traces verified: {result['health']['all_traces_verified']}.", "",
             "## Enforcement mode x seat-profile mix", "",
             "| Mode / mix | Prevention | Drained | Recovered | HIVE clean | Recall | Violations | Breaches blocked/executed | Insolvencies |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for key, a in result["by_mode_mix"].items():
        lines.append(f"| `{key}` | {a['prevention_rate']} | {a['drained']} | {a['recovered']} | {a['hive_clean']} | "
                     f"{a['recall']} | {a['violations']} | {a['breaches_blocked']}/{a['breaches_executed']} | "
                     f"{a['custodian_insolvent']} |")
    lines += ["", "## Scenario splits (all_default mix, all modes)", "",
              "| Scenario | Prevention | Drained | Recovered | HIVE clean | Recall |", "|---|---:|---:|---:|---:|---:|"]
    for sc, a in result["by_scenario"].items():
        lines.append(f"| `{sc}` | {a['prevention_rate']} | {a['drained']} | {a['recovered']} | {a['hive_clean']} | {a['recall']} |")
    lines += ["", result["guardrail"], ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Custody Wars scripted tournament")
    ap.add_argument("--output", default="output/custody_wars")
    ap.add_argument("--seeds", type=int, nargs="*", default=[1, 2, 3, 4])
    ap.add_argument("--scenarios", nargs="*")
    args = ap.parse_args(argv)
    result = run_tournament(args.scenarios, seeds=args.seeds)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "tournament.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "tournament.md").write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result["health"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
