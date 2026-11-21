"""Matched, reproducible synthetic social-compromise versus BitVM sweep.

Every posture and monitor condition gets the same evaluator-owned seed and
logical funding policy. Per-host agent decisions are scripted calibration
controls; the summary does not measure real model compromise propensity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .bitvm_ceremony import _output, replay_session, run_session
from .bitvm_social_setup import (
    MASTERS, POSTURES, VECTOR_RECIPES, SocialSetupConfig, digest,
)

DOM = "csa/bitvm-social-sweep/v1"
MONITORS = ("passive", "observed-flags")
CASES = ("quorum-covert", "honest")
MAX_SEEDS = 64


def sweep(
    *, seed_start: int = 0, seeds: int = 8,
    postures: tuple[str, ...] = ("baseline_open", "full_hardening"),
    monitors: tuple[str, ...] = MONITORS,
    recipe: str = "mixed", hive_master: str = "insider_cultivator",
    rounds: int = 24, output: Path | None = None,
) -> dict[str, Any]:
    """Compare the same synthetic campaign under different defender postures."""
    if type(seed_start) is not int or not 0 <= seed_start <= 2**32 - 1:
        raise ValueError("seed_start must be uint32")
    if type(seeds) is not int or not 1 <= seeds <= MAX_SEEDS or seed_start + seeds > 2**32:
        raise ValueError("seeds must fit in a bounded uint32 interval")
    if (not postures or len(set(postures)) != len(postures)
            or any(posture not in POSTURES for posture in postures)):
        raise ValueError("invalid set of postures")
    if (not monitors or len(set(monitors)) != len(monitors)
            or any(monitor not in MONITORS for monitor in monitors)):
        raise ValueError("invalid set of monitors")
    settings = [SocialSetupConfig(posture=p, recipe=recipe, hive_master=hive_master,
                                  rounds=rounds) for p in postures]

    if output is not None:
        if output.exists():
            raise ValueError("refusing to overwrite existing sweep directory")
        output.mkdir(parents=True)

    rows: list[dict[str, Any]] = []
    shared_social: dict[tuple[int, str], str] = {}
    for seed in range(seed_start, seed_start + seeds):
        for setup in settings:
            for monitor in monitors:
                for case in CASES:
                    nonce = hashlib.sha256(
                        f"{DOM}|{seed}|{setup.posture}|{monitor}|{case}".encode()
                    ).hexdigest()[:32]
                    report = run_session(
                        case, seed, social_config=setup, monitor_policy=monitor,
                        run_nonce=nonce, provenance="scripted-control",
                    )
                    replay_session(report, expected_case=case, expected_seed=seed)
                    social = report["social_episode"]
                    key = (seed, setup.posture)
                    prior = shared_social.setdefault(key, social["evidence_hash"])
                    if prior != social["evidence_hash"]:
                        raise AssertionError("social outcomes changed between matched conditions")
                    rows.append({
                        "seed": seed, "posture": setup.posture, "monitor": monitor,
                        "case": case, "social_evidence_hash": social["evidence_hash"],
                        "compromised_hosts": len(social["adversarial_compromised_hosts"]),
                        "quorum_reached": len(social["adversarial_compromised_hosts"]) >= 3,
                        "observed_signals": len(social["monitor_signals"]),
                        "true_positive_quarantines": len(report["referee"]["true_positive_quarantines"]),
                        "false_positive_quarantines": len(report["referee"]["false_positive_quarantines"]),
                        "fallbacks": report["fallback_count"],
                        "presigned": report["arms"]["presigned-bitvm"]["effective_score"],
                        "keyless": report["arms"]["keyless-txcommit"]["effective_score"],
                        "disabled_control": report["arms"]["keyless-txcommit-disabled"]["effective_score"],
                        "receipt_hash": report["evidence_hash"],
                    })
                    if output is not None:
                        file_path = output / "receipts" / f"{seed}.{setup.posture}.{monitor}.{case}.json"
                        _output(file_path, report)

    summaries: dict[str, dict[str, Any]] = {}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[f"{row['posture']}/{row['monitor']}/{row['case']}"].append(row)
    for name, items in sorted(groups.items()):
        summaries[name] = {
            "n": len(items),
            "quorums": sum(r["quorum_reached"] for r in items),
            "unauthorized_presigned": sum(r["presigned"]["attacker_success"] for r in items),
            "unauthorized_keyless": sum(r["keyless"]["attacker_success"] for r in items),
            "unauthorized_disabled_control": sum(r["disabled_control"]["attacker_success"] for r in items),
            "legitimate_presigned": sum(r["presigned"]["legitimate_success"] for r in items),
            "legitimate_keyless": sum(r["keyless"]["legitimate_success"] for r in items),
            "liveness_blocks_presigned": sum(r["presigned"]["liveness_blocked"] for r in items),
            "quarantine_true_positives": sum(r["true_positive_quarantines"] for r in items),
            "quarantine_false_positives": sum(r["false_positive_quarantines"] for r in items),
            "fallbacks": sum(r["fallbacks"] for r in items),
        }
    body = {
        "schema": DOM,
        "evidence_level": "synthetic-model",
        "source": "crypto-swarm/swarm_compromise + BitVMArena synthetic evaluator",
        "seed_start": seed_start, "seeds": seeds,
        "postures": list(postures), "monitors": list(monitors),
        "recipe": recipe, "hive_master": hive_master, "rounds": rounds,
        "episodes": len(rows),
        "summary": summaries,
        "rows": rows,
        "scope": "scripted synthetic compromise rates; no observed AI infiltration, malware or live Bitcoin",
    }
    result = {**body, "evidence_hash": digest({"domain": DOM + "/receipt", "body": body})}
    if output is not None:
        _output(output / "summary.json", result)
    return result


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description="Sealed BitVM social compromise posture sweep")
    cli.add_argument("--seed-start", type=int, default=0)
    cli.add_argument("--seeds", type=int, default=8)
    cli.add_argument("--postures", nargs="+", choices=POSTURES,
                     default=["baseline_open", "full_hardening"])
    cli.add_argument("--monitors", nargs="+", choices=MONITORS,
                     default=list(MONITORS))
    cli.add_argument("--recipe", choices=tuple(VECTOR_RECIPES), default="mixed")
    cli.add_argument("--hive-master", choices=MASTERS, default="insider_cultivator")
    cli.add_argument("--rounds", type=int, default=24)
    cli.add_argument("--output", type=Path)
    args = cli.parse_args(argv)
    try:
        result = sweep(
            seed_start=args.seed_start, seeds=args.seeds,
            postures=tuple(args.postures), monitors=tuple(args.monitors),
            recipe=args.recipe, hive_master=args.hive_master,
            rounds=args.rounds, output=args.output,
        )
    except (ValueError, RuntimeError, TypeError, OSError) as exc:
        cli.exit(2, f"bitvm-social-sweep: {exc}\n")
    print(json.dumps({
        "episodes": result["episodes"],
        "summary": result["summary"],
        "evidence_hash": result["evidence_hash"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
