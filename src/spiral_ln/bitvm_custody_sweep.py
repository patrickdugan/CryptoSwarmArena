"""Paired Custody Wars supply-chain posture experiments for BitVM setup.

Identical scripted original-engine incidents under each posture/seed feed the
BitVMArena ceremony. Monitor choices get the same attack transcript and host
status; the honest paired control measures availability after quarantines.
All results are synthetic, with no actual model or Bitcoin consensus execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .bitvm_ceremony import _output, replay_session, run_session
from .bitvm_custody_supply import (
    CustodySupplyConfig, POSTURES, RECIPES, _digest,
)

DOMAIN = "csa/bitvm-custody-posture-sweep/v1"
MONITORS = ("passive", "observed-flags")
CASES = ("quorum-covert", "honest")
MAX_SEEDS = 48


def sweep(
    *, seed_start: int = 0, seeds: int = 8,
    postures: tuple[str, ...] = ("exposed", "full-hardening"),
    monitors: tuple[str, ...] = MONITORS,
    recipe: str = "mixed", turns: int = 16,
    output: Path | None = None,
) -> dict[str, Any]:
    if type(seed_start) is not int or not 0 <= seed_start <= 2**32 - 1:
        raise ValueError("seed_start must be an unsigned 32-bit integer")
    if type(seeds) is not int or not 1 <= seeds <= MAX_SEEDS or seed_start + seeds > 2**32:
        raise ValueError("invalid bounded seed interval")
    if not postures or len(set(postures)) != len(postures) or any(p not in POSTURES for p in postures):
        raise ValueError("invalid defender posture selection")
    if not monitors or len(set(monitors)) != len(monitors) or any(m not in MONITORS for m in monitors):
        raise ValueError("invalid monitor selection")
    configs = [CustodySupplyConfig(posture=p, recipe=recipe, turns=turns) for p in postures]

    if output is not None:
        if output.exists():
            raise ValueError("refusing to overwrite existing evidence directory")
        output.mkdir(parents=True, exist_ok=False)

    rows: list[dict[str, Any]] = []
    source_by_pair: dict[tuple[int, str], str] = {}
    for seed in range(seed_start, seed_start + seeds):
        for cfg in configs:
            for monitor in monitors:
                for case in CASES:
                    nonce = hashlib.sha256(
                        f"{DOMAIN}/{seed}/{cfg.posture}/{monitor}/{case}".encode()
                    ).hexdigest()[:32]
                    episode = run_session(
                        case, seed, custody_config=cfg,
                        monitor_policy=monitor, provenance="scripted-control",
                        run_nonce=nonce,
                    )
                    replay_session(episode, expected_case=case, expected_seed=seed)
                    if episode["compromise_source"] != "custody-wars-causal":
                        raise AssertionError("incorrect synthetic backend")
                    source = episode["custody_episode"]
                    key = (seed, cfg.posture)
                    old = source_by_pair.setdefault(key, source["evidence_hash"])
                    if old != source["evidence_hash"]:
                        raise AssertionError("matched conditions have different source outcomes")
                    row = {
                        "seed": seed, "posture": cfg.posture, "monitor": monitor, "case": case,
                        "source_hash": source["evidence_hash"],
                        "host_controls": len(source["adversarial_compromised_hosts"]),
                        "source_supply_spreads": len(source["supply_host_events"]),
                        "observed_host_warnings": len(source["monitor_signals"]),
                        "first_quorum_round": source["timing"]["first_quorum_round"],
                        "first_warning_round": source["timing"]["first_confirmed_warning_round"],
                        "warning_before_or_at_quorum": source["timing"]["warning_before_or_at_quorum"],
                        "quorum_reached": len(source["adversarial_compromised_hosts"]) >= 3,
                        "true_positive_quarantines": len(episode["referee"]["true_positive_quarantines"]),
                        "false_positive_quarantines": len(episode["referee"]["false_positive_quarantines"]),
                        "fallbacks": episode["fallback_count"],
                        "presigned": episode["arms"]["presigned-bitvm"]["effective_score"],
                        "keyless": episode["arms"]["keyless-txcommit"]["effective_score"],
                        "disabled": episode["arms"]["keyless-txcommit-disabled"]["effective_score"],
                        "receipt_hash": episode["evidence_hash"],
                    }
                    rows.append(row)
                    if output is not None:
                        _output(
                            output / "receipts" / f"{seed}.{cfg.posture}.{monitor}.{case}.json",
                            episode,
                        )
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[f"{row['posture']}/{row['monitor']}/{row['case']}"].append(row)

    summary: dict[str, dict[str, Any]] = {}
    for group, items in sorted(groups.items()):
        summary[group] = {
            "n": len(items),
            "quorums": sum(row["quorum_reached"] for row in items),
            "host_control_count": sum(row["host_controls"] for row in items),
            "quorums_with_confirmed_warning_before_or_at_formation": sum(
                row["warning_before_or_at_quorum"] for row in items
            ),
            "unauthorized_presigned": sum(row["presigned"]["attacker_success"] for row in items),
            "unauthorized_keyless": sum(row["keyless"]["attacker_success"] for row in items),
            "legitimate_presigned": sum(row["presigned"]["legitimate_success"] for row in items),
            "legitimate_keyless": sum(row["keyless"]["legitimate_success"] for row in items),
            "liveness_blocked_presigned": sum(row["presigned"]["liveness_blocked"] for row in items),
            "true_positive_quarantines": sum(row["true_positive_quarantines"] for row in items),
            "false_positive_quarantines": sum(row["false_positive_quarantines"] for row in items),
            "fallbacks": sum(row["fallbacks"] for row in items),
        }
    body = {
        "schema": DOMAIN, "evidence_level": "synthetic-model",
        "seed_start": seed_start, "seeds": seeds, "postures": list(postures),
        "monitors": list(monitors), "recipe": recipe, "turns": turns,
        "episodes": len(rows), "summary": summary, "rows": rows,
        "scope": "scripted Custody Wars synthetic host compromises and BitVMArena assumptions only",
    }
    result = {**body, "evidence_hash": _digest({"domain": DOMAIN + "/receipt", "body": body})}
    if output is not None:
        _output(output / "summary.json", result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Matched Custody Wars supply-chain BitVM sweep")
    parser.add_argument("--seed-start", type=int, default=0)
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--postures", nargs="+", choices=POSTURES,
                        default=["exposed", "full-hardening"])
    parser.add_argument("--monitors", nargs="+", choices=MONITORS,
                        default=list(MONITORS))
    parser.add_argument("--recipe", choices=RECIPES, default="mixed")
    parser.add_argument("--turns", type=int, default=16)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = sweep(
            seed_start=args.seed_start, seeds=args.seeds,
            postures=tuple(args.postures), monitors=tuple(args.monitors),
            recipe=args.recipe, turns=args.turns, output=args.output,
        )
    except (ValueError, TypeError, RuntimeError, OSError) as exc:
        parser.exit(2, f"custody-supply-sweep: {exc}\n")
    print(json.dumps({
        "episodes": result["episodes"],
        "summary": result["summary"],
        "evidence_hash": result["evidence_hash"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
