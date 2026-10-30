"""Run and verify the opt-in Codex-v-Claude RTG sealed worm-duel tournament.

Default is a deterministic MOCK pilot. The --live flag is never implicit; it
requires the two provider CLIs, existing authentication and a cost acknowledgement.
Real models only select bounded IDs; their tool privileges are restricted by the
adapter, and all game decisions are resolved by the independent Python referee.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from dataclasses import asdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

from .rtg_worm_duel import DuelConfig, ModelReply, RULES, ScriptedSeat, run_bout
from .rtg_worm_models import CLIDecisionSeat
from .repo_worm_alife import canonical, sha

TOURNAMENT_SCHEMA = "rtg.worm_duel.tournament.v1"
SOURCE_FILES = ("rtg_worm_tournament.py", "rtg_worm_duel.py", "rtg_worm_models.py", "repo_worm_alife.py")


def freeze_config(spec: dict[str, Any]) -> tuple[DuelConfig, list[int], list[str]]:
    if not isinstance(spec, dict) or spec.get("schema_version") != TOURNAMENT_SCHEMA:
        raise ValueError("unrecognized tournament schema")
    if set(spec) != {"schema_version", "design", "seeds", "postures", "models"}:
        raise ValueError("tournament configuration has unexpected fields")
    if spec["models"] != ["codex", "claude"]:
        raise ValueError("model seats must be codex and claude")
    if not isinstance(spec["design"], dict):
        raise ValueError("design must be an object")
    config = DuelConfig(**spec["design"])
    seeds, postures = spec["seeds"], spec["postures"]
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= 32 or any(
        type(s) is not int or not 0 <= s <= 2**32-1 for s in seeds
    ) or len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be 1-32 unique uint32 values")
    if not isinstance(postures, list) or not postures or len(set(postures)) != len(postures) or any(
        x not in RULES for x in postures
    ):
        raise ValueError("invalid posture set")
    return config, seeds, postures


def bracket(spec: dict[str, Any], *, pilot: bool) -> list[dict[str, Any]]:
    _, seeds, postures = freeze_config(spec)
    if pilot:
        seeds = seeds[:2]
    bouts = []
    for seed in seeds:
        for posture in postures:
            for red, blue in (("codex", "claude"), ("claude", "codex")):
                bouts.append({"seed": seed, "posture": posture, "red": red, "blue": blue})
    return bouts


class RecordedSeat:
    """Uses already validated decision receipts; no provider interaction on replay."""

    def __init__(self, role: str, records: list[dict[str, Any]]) -> None:
        self.role, self.records, self.cursor = role, records, 0

    def decide(self, role: str, view: dict[str, Any]) -> ModelReply:
        if role != self.role or self.cursor >= len(self.records):
            raise ValueError("replay call order mismatch")
        saved = self.records[self.cursor]
        self.cursor += 1
        if saved["seat"] != role or sha(view) != saved["visible_view_sha256"]:
            raise ValueError("replay observation mismatch")
        # Preserve valid/invalid and external failure accounting without retaining
        # original untrusted model output. Inert choices are the only actuator.
        choice = saved["choice"] if saved["valid"] else {"invalid_field": []}
        return ModelReply(choice, status=saved["adapter_status"],
                          input_tokens=saved["input_tokens"], output_tokens=saved["output_tokens"],
                          duration_ms=saved["duration_ms"], provider_cost_usd=saved["provider_cost_usd"])


def replay_bout(row: dict[str, Any], config: DuelConfig) -> bool:
    """Independent game replay of every scored event and handoff from saved ID decisions."""
    records = row["decisions"]
    red_records = [r for r in records if r["seat"] == "HIVE"]
    blue_records = [r for r in records if r["seat"] == "SENTINEL"]
    red = RecordedSeat("HIVE", red_records)
    blue = RecordedSeat("SENTINEL", blue_records)
    try:
        computed = run_bout(seed=row["seed"], posture=row["posture"], red_name=row["red"],
                            blue_name=row["blue"], red=red, blue=blue, config=config)
    except (ValueError, KeyError, TypeError):
        return False
    fields = ("schema_version", "seed", "posture", "red", "blue", "config_sha256",
              "graph_sha256", "roots", "final_carriers", "max_generation", "score",
              "red_points", "blue_points", "referee_events", "public_history",
              "referee_chain_sha256", "safety", "ledger_ok")
    if any(row.get(field) != computed.get(field) for field in fields):
        return False
    stable_fields = ("tick", "seat", "model", "visible_view_sha256", "choice", "valid",
                     "adapter_status", "input_tokens", "output_tokens", "duration_ms", "provider_cost_usd")
    return (red.cursor == len(red_records) == config.ticks
            and blue.cursor == len(blue_records) == config.ticks
            and len(records) == len(computed["decisions"])
            and all(all(a.get(field) == b.get(field) for field in stable_fields)
                    for a, b in zip(records, computed["decisions"])))


def source_hashes() -> dict[str, str]:
    root = Path(__file__).parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def describe(values: list[float]) -> dict[str, Any]:
    return {"worlds": len(values), "mean": round(mean(values), 5) if values else None,
            "ci95_half_width": round(1.96 * stdev(values) / math.sqrt(len(values)), 5)
            if len(values) >= 2 else None}


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    report: dict[str, Any] = {"by_posture_role_model": {}, "paired_posture_delta": {}}
    for posture in sorted({r["posture"] for r in rows}):
        for role in ("red", "blue"):
            for model in ("codex", "claude"):
                selected = [r for r in rows if r["posture"] == posture and r[role] == model]
                report["by_posture_role_model"][f"{posture}/{role}/{model}"] = {
                    "points": describe([float(r[role + "_points"]) for r in selected]),
                    "adoptions": describe([float(r["score"]["adoptions"]) for r in selected]),
                    "blocked_markers": describe([float(r["score"]["marker_blocked"]) for r in selected]),
                    "benign_blocked": describe([float(r["score"]["benign_blocked"]) for r in selected]),
                }
    # For a fixed pair and seed compare hardened with open; each seed is one independent unit.
    by_key = {(r["seed"], r["posture"], r["red"], r["blue"]): r for r in rows}
    for red, blue in (("codex", "claude"), ("claude", "codex")):
        comparisons = []
        for seed in sorted({r["seed"] for r in rows}):
            base = by_key.get((seed, "baseline_open", red, blue))
            hard = by_key.get((seed, "inspect_verify", red, blue))
            if base and hard:
                comparisons.append((base, hard))
        report["paired_posture_delta"][f"red_{red}/blue_{blue}"] = {
            "secondary_adoptions": describe([float(hard["score"]["adoptions"] - base["score"]["adoptions"])
                                           for base, hard in comparisons]),
            "benign_blocked": describe([float(hard["score"]["benign_blocked"] - base["score"]["benign_blocked"])
                                       for base, hard in comparisons]),
        }
    return report


def write_campaign(spec: dict[str, Any], output: Path, *, pilot: bool,
                   live: bool, ack_provider_costs: bool, max_calls: int,
                   codex_model: str | None = None, claude_model: str | None = None,
                   timeout_s: int = 90) -> dict[str, Any]:
    config, _, _ = freeze_config(spec)
    bouts = bracket(spec, pilot=pilot)
    calls = len(bouts) * config.ticks * 2
    if type(max_calls) is not int or not 1 <= max_calls <= 2048 or calls > max_calls:
        raise ValueError(f"request would use {calls} model decision calls, exceeding cap {max_calls}")
    if live and not ack_provider_costs:
        raise ValueError("--live requires --ack-provider-costs; inference may incur provider charges")
    if live and (not codex_model or not claude_model):
        raise ValueError("--live requires explicit --codex-model and --claude-model identifiers")
    if (codex_model or claude_model) and not live:
        raise ValueError("explicit model names are only valid in --live mode")
    if live:
        actors = {"codex": CLIDecisionSeat("codex", model=codex_model, timeout_s=timeout_s),
                  "claude": CLIDecisionSeat("claude", model=claude_model, timeout_s=timeout_s)}
        for actor in actors.values():
            actor.preflight()  # fail before the first paid call
    else:
        actors = {"codex": ScriptedSeat("codex"), "claude": ScriptedSeat("claude")}
    rows = []
    for pair in bouts:
        row = run_bout(seed=pair["seed"], posture=pair["posture"], red_name=pair["red"],
                       blue_name=pair["blue"], red=actors[pair["red"]], blue=actors[pair["blue"]],
                       config=config)
        if not row["ledger_ok"]:
            raise AssertionError("referee accounting failed")
        rows.append(row)
    stats = summarize(rows)
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": TOURNAMENT_SCHEMA, "spec": spec, "pilot": pilot,
                "mode": "live_provider_models" if live else "scripted_mock_only",
                "planned_provider_decisions": calls,
                "codex_model_requested": codex_model, "claude_model_requested": claude_model,
                "source_sha256": source_hashes(), "spec_sha256": sha(spec),
                "limits": {"maximum_calls": max_calls, "timeout_seconds_per_decision": timeout_s},
                "interpretation": "Sealed game strategies; no actual worm payloads, prompt injections, or autonomous propagation."
                }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output / "bouts.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(canonical(row) + "\n")
    with (output / "scores.csv").open("w", encoding="utf-8", newline="") as f:
        fields = ["seed", "posture", "red", "blue", "red_points", "blue_points", "final_carriers",
                  "adoptions", "blocked_markers", "benign_completed", "benign_blocked", "false_quarantines",
                  "red_invalid", "blue_invalid", "model_input_tokens", "model_output_tokens",
                  "measured_provider_cost_usd", "referee_chain_sha256"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            s = row["score"]
            writer.writerow({"seed": row["seed"], "posture": row["posture"],
                             "red": row["red"], "blue": row["blue"],
                             "red_points": row["red_points"], "blue_points": row["blue_points"],
                             "final_carriers": row["final_carriers"], "adoptions": s["adoptions"],
                             "blocked_markers": s["marker_blocked"], "benign_completed": s["benign_completed"],
                             "benign_blocked": s["benign_blocked"], "false_quarantines": s["false_quarantines"],
                             "red_invalid": s["red_invalid"], "blue_invalid": s["blue_invalid"],
                             "model_input_tokens": s["model_input_tokens"],
                             "model_output_tokens": s["model_output_tokens"],
                             "measured_provider_cost_usd": s["measured_provider_cost_usd"],
                             "referee_chain_sha256": row["referee_chain_sha256"]})
    (output / "summary.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipts = {"schema_version": TOURNAMENT_SCHEMA, "spec_sha256": sha(spec),
                "bout_count": len(rows), "bouts_sha256": sha(rows), "summary_sha256": sha(stats),
                "scores_csv_sha256": hashlib.sha256((output / "scores.csv").read_bytes()).hexdigest(),
                "source_sha256": source_hashes()}
    (output / "receipts.json").write_text(json.dumps(receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipts


def verify_campaign(output: Path) -> bool:
    try:
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        receipts = json.loads((output / "receipts.json").read_text(encoding="utf-8"))
        spec = manifest["spec"]
        config, _, _ = freeze_config(spec)
        bouts = bracket(spec, pilot=manifest["pilot"])
        rows = [json.loads(line) for line in (output / "bouts.jsonl").read_text(encoding="utf-8").splitlines()]
        if not (len(rows) == len(bouts) == receipts["bout_count"]):
            return False
        if source_hashes() != receipts["source_sha256"] or manifest["source_sha256"] != receipts["source_sha256"]:
            return False
        if sha(spec) != receipts["spec_sha256"] or manifest["spec_sha256"] != receipts["spec_sha256"]:
            return False
        if any(not row["ledger_ok"] or not replay_bout(row, config)
               or (row["seed"], row["posture"], row["red"], row["blue"])
               != (b["seed"], b["posture"], b["red"], b["blue"])
               for row, b in zip(rows, bouts)):
            return False
        if sha(rows) != receipts["bouts_sha256"]:
            return False
        stats = summarize(rows)
        if stats != json.loads((output / "summary.json").read_text(encoding="utf-8")):
            return False
        if sha(stats) != receipts["summary_sha256"]:
            return False
        if hashlib.sha256((output / "scores.csv").read_bytes()).hexdigest() != receipts["scores_csv_sha256"]:
            return False
        return True
    except (ValueError, TypeError, KeyError, FileNotFoundError, json.JSONDecodeError, OSError):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("configs/rtg_codex_claude_v1.json"))
    parser.add_argument("--output", type=Path, default=Path("output/rtg_worm_duel_pilot"))
    parser.add_argument("--pilot", action="store_true", help="Only first two seeds (8 bouts)")
    parser.add_argument("--live", action="store_true", help="Opt into external Codex and Claude CLI inference")
    parser.add_argument("--ack-provider-costs", action="store_true", help="Acknowledge charged external requests")
    parser.add_argument("--max-calls", type=int, default=128, help="Hard cap for all model decisions")
    parser.add_argument("--codex-model")
    parser.add_argument("--claude-model")
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--verify", type=Path, help="Replay recorded choices against sealed referee, without any models")
    args = parser.parse_args(argv)
    if args.verify is not None:
        ok = verify_campaign(args.verify)
        print("VERIFIED" if ok else "VERIFICATION FAILED")
        return 0 if ok else 1
    try:
        spec = json.loads(args.config.read_text(encoding="utf-8"))
        receipts = write_campaign(spec, args.output, pilot=args.pilot,
                                  live=args.live, ack_provider_costs=args.ack_provider_costs,
                                  max_calls=args.max_calls, codex_model=args.codex_model,
                                  claude_model=args.claude_model, timeout_s=args.timeout_seconds)
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    print(f"{receipts['bout_count']} bouts recorded ({'live' if args.live else 'MOCK ONLY'}); sha256={receipts['bouts_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
