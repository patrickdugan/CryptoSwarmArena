"""Feral-custody benchmark runner.

Runs each custody strategy against a roster of adversary objectives across seeds,
and reports funds retained, uninterrupted signing, extraction / denial / coerced
events, custody cost, and a sample successful-attack-path trace -- aggregated by
strategy and by red composition.  Deterministic and reproducible (no timestamps);
scripted-policy validation of the instrument, not evidence about any model.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from statistics import mean

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from spiral_ln.feral_custody import (
    STRATEGIES,
    CustodyResult,
    FeralCustodyEnv,
    build_custody_config,
    default_adversary,
)


def run_episode(strategy: str, objective: str, bribery_budget: int, seed: int, config_overrides: dict) -> tuple[CustodyResult, tuple]:
    config = build_custody_config(strategy, seed=seed, **config_overrides)
    adversary = default_adversary(objective, bribery_budget)
    env = FeralCustodyEnv(config, adversary, seed=seed)
    result = env.run()
    return result, result.attack_path


def load_config(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data.pop("schema_version", None)
    data.pop("description", None)
    return data


def _agg(results: list[CustodyResult]) -> dict[str, float]:
    n = max(1, len(results))
    return {
        "episodes": len(results),
        "mean_funds_retained_fraction": round(mean(r.funds_retained / max(1, r.funds_initial) for r in results), 4),
        "mean_uninterrupted_fraction": round(mean(r.uninterrupted_signing_epochs / max(1, r.epochs) for r in results), 4),
        "extraction_rate": round(sum(r.extraction_events > 0 for r in results) / n, 4),
        "denial_rate": round(sum(r.denial_events > 0 for r in results) / n, 4),
        "coerced_rate": round(sum(r.coerced_signatures > 0 for r in results) / n, 4),
        "deceived_rate": round(sum(r.deceived_signatures > 0 for r in results) / n, 4),
        "mean_custody_cost_fraction": round(mean(r.custody_cost_fraction for r in results), 4),
    }


def summarize(results: list[CustodyResult], samples: dict, objectives: list[str]) -> dict:
    by_strategy = {s: _agg([r for r in results if r.strategy == s]) for s in STRATEGIES}
    by_composition = {
        f"{s}|{o}": _agg([r for r in results if r.strategy == s and r.adversary.endswith(o)])
        for s in STRATEGIES for o in objectives
    }
    return {
        "schema_version": "1.0",
        "evidence_scope": "scripted_harness_validation",
        "episode_count": len(results),
        "by_strategy": by_strategy,
        "by_composition": by_composition,
        "sample_attack_paths": samples,
        "accounting_all_ok": all(r.accounting_ok for r in results),
        "safety_boundary": CustodyResult.safety_boundary(),
        "guardrail": "Scripted-policy validation of the instrument; not evidence about any model or real custody system.",
    }


def _write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _plot(summary: dict, path: Path) -> None:
    labels = list(STRATEGIES)
    retained = [summary["by_strategy"][s]["mean_funds_retained_fraction"] for s in labels]
    uptime = [summary["by_strategy"][s]["mean_uninterrupted_fraction"] for s in labels]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(9.0, 4.6))
    ax.bar([i - 0.18 for i in x], retained, 0.36, label="Funds retained", color="#0f766e")
    ax.bar([i + 0.18 for i in x], uptime, 0.36, label="Uninterrupted signing", color="#b45309")
    ax.set_xticks(list(x), [s.replace("_", "\n") for s in labels])
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Fraction")
    ax.set_title("Feral custody: strategy outcomes (mean across adversaries)")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _report(summary: dict) -> str:
    lines = [
        "# Feral custody — summary report",
        "",
        "Scripted-policy validation of the instrument; not evidence about any model or real custody system.",
        "",
        "| strategy | funds retained | uninterrupted signing | extraction rate | denial rate | coerced rate | deceived rate | custody cost |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in STRATEGIES:
        a = summary["by_strategy"][s]
        lines.append(
            f"| {s} | {a['mean_funds_retained_fraction']:.2f} | {a['mean_uninterrupted_fraction']:.2f} | "
            f"{a['extraction_rate']:.2f} | {a['denial_rate']:.2f} | {a.get('coerced_rate', 0):.2f} | "
            f"{a.get('deceived_rate', 0):.2f} | {a['mean_custody_cost_fraction']:.2f} |"
        )
    lines += ["", "Reassembly strategies (multisig / obfuscation / loyalist / gig) expose a per-epoch",
              "extraction surface; enclave and threshold signing do not. Coerced signing (a signer",
              "forced) is resisted by threshold signing; deceived signing (a signer fooled into",
              "approving) is NOT, since a uniform spoof can fool the quorum. See the design note."]
    return "\n".join(lines) + "\n"


def run_campaign(output_dir: str | Path, config_path: str | Path = "configs/feral_custody.json") -> dict:
    output = Path(output_dir)
    (output / "figures").mkdir(parents=True, exist_ok=True)
    config = load_config(config_path)
    seeds = [int(s) for s in config.get("seeds", [0, 1, 2, 3])]
    strategies = config.get("strategies", list(STRATEGIES))
    adversaries = config.get("adversaries", [{"objective": o, "bribery_budget": 60_000} for o in ("key_extraction", "signing_denial", "coerced_signing")])
    overrides = config.get("config_overrides", {})
    objectives = sorted({a["objective"] for a in adversaries})

    results: list[CustodyResult] = []
    rows: list[dict] = []
    samples: dict = {}
    for strategy in sorted(strategies):
        for adversary in adversaries:
            obj, budget = adversary["objective"], int(adversary["bribery_budget"])
            for seed in seeds:
                result, path = run_episode(strategy, obj, budget, seed, overrides)
                results.append(result)
                rows.append(result.to_dict())
                key = f"{strategy}|{obj}"
                if key not in samples and path:
                    samples[key] = list(path[:12])

    summary = summarize(results, samples, objectives)
    if not summary["accounting_all_ok"]:
        raise AssertionError("feral-custody accounting failed")

    summary_path = output / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_rows(output / "rows.csv", rows)
    (output / "report.md").write_text(_report(summary), encoding="utf-8")
    _plot(summary, output / "figures" / "strategy_outcomes.png")

    config_path = Path(config_path)
    hashes = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in ("summary.json", "rows.csv")}
    receipt = {
        "schema_version": "1.0",
        "experiment_id": f"feral-custody-{len(seeds)}-seeds",
        "configuration_file": config_path.as_posix(),
        "configuration_hash": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "artifacts": hashes,
        "combined_sha256": hashlib.sha256("".join(hashes[n] for n in sorted(hashes)).encode()).hexdigest(),
        "model_call": False,
        "network": False,
    }
    (output / "witness_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/feral_custody")
    parser.add_argument("--config", default="configs/feral_custody.json")
    args = parser.parse_args(argv)
    summary = run_campaign(args.output, args.config)
    print(json.dumps({"by_strategy": summary["by_strategy"], "accounting_all_ok": summary["accounting_all_ok"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
