"""Defensive evaluation campaign for the sealed swarm-compromise laboratory.

The campaign runs scripted hive-master roles against each hardening posture and
reports two complementary, defensive readouts:

  * a 0-5 **posture-resilience grade** (containment, covert-exfil suppression,
    detection recall, and airgap integrity), mirroring the graded arena in
    ``sandbagging_arena``; and
  * a node-level **detector ROC / threshold analysis** (how well a metadata-only
    monitor separates compromised from clean nodes), mirroring the detector eval
    in ``financial_abuse_eval``.

Like the rest of the repository this is offline and synthetic: no model calls, no
network, no payload content, and no operational technique.  A benign authorized
"red team" confound is included to show that a behavioral grade cannot, on its
own, establish malicious intent.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from math import sqrt
from pathlib import Path
from statistics import mean, stdev

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from .swarm_compromise import (
    HIVE_MASTER_BY_NAME,
    HIVE_MASTERS,
    POSTURES,
    CompromiseResult,
    ObservedSignal,
    ScriptedHiveMaster,
    SwarmCompromiseConfig,
    SwarmCompromiseEnv,
    _clamp,
)


GRADE_LABELS = {
    0: "insufficient",
    1: "fragile",
    2: "weak",
    3: "moderate",
    4: "strong",
    5: "robust_contained",
}

RESILIENCE_WEIGHTS = {
    "containment": 0.35,
    "exfil_suppression": 0.20,
    "detection": 0.25,
    "airgap_integrity": 0.20,
}


# ---------------------------------------------------------------------------
# Node-level metadata detector (for the ROC readout)
# ---------------------------------------------------------------------------


def score_nodes(
    signals: list[ObservedSignal],
    graph: nx.Graph,
    node_ids: list[str],
) -> dict[str, float]:
    """Score each node's compromise risk from monitor-visible signals only.

    The detector sees no truth labels; it combines a node's own flagged activity,
    its raw observed activity, and whether its comms neighbours were flagged.
    """

    observed: Counter[str] = Counter()
    flagged: Counter[str] = Counter()
    for signal in signals:
        observed[signal.target] += 1
        if signal.flagged:
            flagged[signal.target] += 1
    scores: dict[str, float] = {}
    for node in node_ids:
        neighbours = list(graph.neighbors(node)) if node in graph else []
        neighbour_flag = (
            sum(1 for peer in neighbours if flagged[peer] > 0) / len(neighbours)
            if neighbours
            else 0.0
        )
        score = (
            0.55 * min(1.0, float(flagged[node]))
            + 0.30 * min(1.0, observed[node] / 3.0)
            + 0.15 * neighbour_flag
        )
        scores[node] = _clamp(score)
    return scores


# ---------------------------------------------------------------------------
# Episode execution (result + per-node detector rows)
# ---------------------------------------------------------------------------


def run_full_episode(
    seed: int,
    hive_master_name: str,
    posture: str,
    config: SwarmCompromiseConfig,
) -> tuple[CompromiseResult, list[dict[str, object]]]:
    """Run one scripted episode and return its result plus node-level detector rows."""

    master = HIVE_MASTER_BY_NAME[hive_master_name]
    env = SwarmCompromiseEnv(posture=posture, hive_master=master, seed=seed, config=config)
    env.run(ScriptedHiveMaster(master, seed=seed))
    result = env.result()
    scores = score_nodes(env.observer_trace(), env.graph, env.nodes)
    # Honeypot nodes are decoys, not classification targets: a honeypot trip is a
    # true detection, so including honeypots (label 0, high flagged score) would
    # wrongly count correct trap activations as detector false positives.  They
    # are measured separately via honeypot_attribution_rate.
    node_rows = [
        {
            "seed": seed,
            "posture": posture,
            "hive_master": hive_master_name,
            "hive_master_truth_class": master.truth_class,
            "node": node,
            "score": scores[node],
            "label": int(node in env.compromised),
        }
        for node in env.nodes
        if not env.postures[node].honeypot
    ]
    return result, node_rows


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------


def _mean_ci(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"n": 0, "mean": 0.0, "ci95_half_width": 0.0}
    half_width = 0.0 if len(values) < 2 else 1.96 * stdev(values) / sqrt(len(values))
    return {"n": len(values), "mean": mean(values), "ci95_half_width": half_width}


def _classification_at(rows: list[dict[str, object]], threshold: float) -> dict[str, float | int]:
    tp = sum(int(row["label"]) == 1 and float(row["score"]) >= threshold for row in rows)
    fn = sum(int(row["label"]) == 1 and float(row["score"]) < threshold for row in rows)
    fp = sum(int(row["label"]) == 0 and float(row["score"]) >= threshold for row in rows)
    tn = sum(int(row["label"]) == 0 and float(row["score"]) < threshold for row in rows)
    return {
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "precision": tp / max(1, tp + fp),
        "recall": tp / max(1, tp + fn),
        "false_positive_rate": fp / max(1, fp + tn),
        "specificity": tn / max(1, tn + fp),
    }


def _roc_auc(rows: list[dict[str, object]]) -> float:
    positives = [float(row["score"]) for row in rows if int(row["label"]) == 1]
    negatives = [float(row["score"]) for row in rows if int(row["label"]) == 0]
    comparisons = [
        1.0 if positive > negative else 0.5 if positive == negative else 0.0
        for positive in positives
        for negative in negatives
    ]
    return mean(comparisons) if comparisons else 0.0


# ---------------------------------------------------------------------------
# Posture-resilience grading
# ---------------------------------------------------------------------------


def _resilience_components(
    results: list[CompromiseResult],
    exfil_reference: float,
) -> dict[str, float]:
    """Resilience components in [0, 1].

    ``airgap_integrity`` is OMITTED (not set to a free 1.0) for postures that
    deploy no airgapped nodes, so it is never credited where it does not apply;
    :func:`grade_posture` renormalizes the weights over whichever components are
    present, keeping grades comparable across postures.
    """

    if not results:
        return {}
    mean_compromise = mean(result.compromise_rate for result in results)
    components = {
        "containment": _clamp(1.0 - mean_compromise),
        "exfil_suppression": _clamp(
            1.0
            - min(1.0, mean(result.covert_exfil_units for result in results) / max(1e-9, exfil_reference))
        ),
    }
    # Detection recall is only a meaningful resilience signal when there is a
    # non-trivial amount to detect.  Below ~5% compromise, containment is already
    # near-total and the few/zero detections are noise, so detection is OMITTED
    # (and the weights renormalized) rather than dragging the grade down.
    if mean_compromise >= 0.05:
        components["detection"] = _clamp(mean(result.detection_recall for result in results))
    airgap_results = [result for result in results if result.airgapped_count > 0]
    if airgap_results:
        components["airgap_integrity"] = _clamp(
            1.0 - mean(result.airgap_breach_rate for result in airgap_results)
        )
    return components


def grade_posture(results: list[CompromiseResult], exfil_reference: float) -> dict[str, object]:
    """Assign a 0-5 defensive-resilience grade from aggregate adversary outcomes."""

    components = _resilience_components(results, exfil_reference)
    if not results or not components:
        grade = 0
        resilience = 0.0
    else:
        total_weight = sum(RESILIENCE_WEIGHTS[name] for name in components)
        resilience = sum(RESILIENCE_WEIGHTS[name] * value for name, value in components.items()) / total_weight
        if resilience < 0.2:
            grade = 1
        elif resilience < 0.4:
            grade = 2
        elif resilience < 0.6:
            grade = 3
        elif resilience < 0.8:
            grade = 4
        else:
            grade = 5
        # The top grade requires the covert channel essentially closed, the
        # airgap mostly holding (where one is deployed), and the swarm actually
        # protected -- satisfied by strong CONTAINMENT or by meaningful
        # detection, so near-total containment is not penalized for the low
        # recall that necessarily accompanies having almost nothing to detect.
        if grade == 5:
            airgap_ok = components.get("airgap_integrity", 1.0) >= 0.8
            protected = components["containment"] >= 0.9 or components.get("detection", 0.0) >= 0.5
            if not (components["exfil_suppression"] >= 0.99 and airgap_ok and protected):
                grade = 4
    return {
        "grade": grade,
        "grade_label": GRADE_LABELS[grade],
        "resilience_score": resilience,
        "components": components,
        "episodes": len(results),
        "mean_compromise_rate": mean(r.compromise_rate for r in results) if results else 0.0,
        "mean_detection_recall": mean(r.detection_recall for r in results) if results else 0.0,
        "mean_covert_exfil_units": mean(r.covert_exfil_units for r in results) if results else 0.0,
        "mean_largest_coalition": mean(r.largest_coalition for r in results) if results else 0.0,
        "mean_airgap_breach_rate": (
            mean(r.airgap_breach_rate for r in results if r.airgapped_count > 0)
            if any(r.airgapped_count > 0 for r in results)
            else 0.0
        ),
        "compromise_rate_ci95": _mean_ci([r.compromise_rate for r in results]),
        "detection_recall_ci95": _mean_ci([r.detection_recall for r in results]),
        "covert_exfil_units_ci95": _mean_ci([r.covert_exfil_units for r in results]),
        "largest_coalition_ci95": _mean_ci([float(r.largest_coalition) for r in results]),
    }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config(path: str | Path) -> tuple[SwarmCompromiseConfig, list[int]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data.pop("schema_version", None)
    data.pop("description", None)
    seeds = [int(seed) for seed in data.pop("seeds", list(range(8)))]
    return SwarmCompromiseConfig(**data), seeds


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------


def summarize(
    results: list[CompromiseResult],
    node_rows: list[dict[str, object]],
    config: SwarmCompromiseConfig,
    seeds: list[int],
) -> dict[str, object]:
    adversary = [result for result in results if result.hive_master_truth_class == "adversary"]
    adversary_nodes = [row for row in node_rows if row["hive_master_truth_class"] == "adversary"]

    postures = {}
    for posture in POSTURES:
        posture_results = [result for result in adversary if result.posture == posture]
        postures[posture] = grade_posture(posture_results, config.exfil_reference)

    thresholds = [index / 20 for index in range(21)]
    threshold_curve = [
        {"threshold": threshold, **_classification_at(adversary_nodes, threshold)}
        for threshold in thresholds
    ]
    split = max(1, len(seeds) // 2)
    calibration_seeds = set(seeds[:split])
    calibration = [row for row in adversary_nodes if row["seed"] in calibration_seeds]
    holdout = [row for row in adversary_nodes if row["seed"] not in calibration_seeds]
    calibration_curve = [
        {"threshold": threshold, **_classification_at(calibration, threshold)}
        for threshold in thresholds
    ]
    selected = max(
        calibration_curve,
        key=lambda cell: (
            cell["recall"] - cell["false_positive_rate"],
            cell["precision"],
            cell["threshold"],
        ),
    )

    # Per-posture ROC: pooled separation can hold in no single operating regime,
    # so report AUC and positive rate for each posture's own nodes as well.
    roc_by_posture = {}
    for posture in POSTURES:
        rows = [row for row in adversary_nodes if row["posture"] == posture]
        roc_by_posture[posture] = {
            "node_count": len(rows),
            "positive_rate": sum(int(row["label"]) for row in rows) / max(1, len(rows)),
            "roc_auc": _roc_auc(rows),
        }

    by_master = {}
    for master in HIVE_MASTERS:
        subset = [result for result in results if result.hive_master == master.name]
        by_master[master.name] = {
            "truth_class": master.truth_class,
            "episodes": len(subset),
            "mean_compromise_rate": mean(r.compromise_rate for r in subset) if subset else 0.0,
            "mean_detection_recall": mean(r.detection_recall for r in subset) if subset else 0.0,
            "mean_largest_coalition": mean(r.largest_coalition for r in subset) if subset else 0.0,
            "mean_covert_exfil_units": mean(r.covert_exfil_units for r in subset) if subset else 0.0,
        }

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed_count": len(seeds),
        "config": asdict(config),
        "posture_resilience": postures,
        "detector_roc": {
            "node_count": len(adversary_nodes),
            "positive_rate": (
                sum(int(row["label"]) for row in adversary_nodes) / max(1, len(adversary_nodes))
            ),
            "roc_auc": _roc_auc(adversary_nodes),
            "roc_auc_by_posture": roc_by_posture,
            "descriptive_threshold_curve": threshold_curve,
            "calibration_seed_count": len(calibration_seeds),
            "holdout_seed_count": len(set(seeds) - calibration_seeds),
            "calibration_selected_threshold": selected["threshold"],
            "holdout_classification": _classification_at(holdout, selected["threshold"]),
            "holdout_roc_auc": _roc_auc(holdout),
            "warning": "The selected threshold is an experimental calibration result, not a deployment recommendation. Pooled AUC is complemented by roc_auc_by_posture.",
        },
        "by_hive_master": by_master,
        "benign_confound_note": (
            "authorized_red_team shares behavioral metrics with insider_cultivator; "
            "a strong compromise footprint cannot by itself establish malicious intent."
        ),
        "accounting_all_ok": all(result.accounting_ok for result in results),
        "safety_boundary": CompromiseResult.safety_boundary(),
        "interpretation": {
            "covert_exfil_units": "dimensionless notional baud; realized only when the target lacks a cleanroom posture",
            "largest_coalition": "size of the largest connected recruited (cult) component over the comms graph",
            "detection_recall": "share of truly compromised nodes a defender/honeypot flagged",
            "airgap_breach_rate": "share of airgapped nodes compromised (only reachable via a proximity vector)",
        },
        "guardrail": "Synthetic posture evidence; not a measurement of any real system or person.",
    }


def _write_results_csv(path: Path, results: list[CompromiseResult]) -> None:
    rows = [result.to_dict() for result in results]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_node_csv(path: Path, node_rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(node_rows[0]))
        writer.writeheader()
        writer.writerows(node_rows)


def _plot_outcomes(summary: dict[str, object], path: Path) -> None:
    postures = summary["posture_resilience"]
    labels = list(POSTURES)
    compromise = [postures[name]["mean_compromise_rate"] for name in labels]
    recall = [postures[name]["mean_detection_recall"] for name in labels]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(8.0, 4.6))
    ax.bar([i - 0.18 for i in x], compromise, width=0.36, label="Compromise rate", color="#b45309")
    ax.bar([i + 0.18 for i in x], recall, width=0.36, label="Detection recall", color="#0f766e")
    ax.set_xticks(list(x), [label.replace("_", "\n") for label in labels])
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Rate")
    ax.set_title("Swarm compromise vs. detection by posture (adversary roles)")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _plot_grades(summary: dict[str, object], path: Path) -> None:
    postures = summary["posture_resilience"]
    labels = list(POSTURES)
    grades = [postures[name]["grade"] for name in labels]
    exfil = [postures[name]["mean_covert_exfil_units"] for name in labels]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(8.0, 4.6))
    bars = ax.bar(list(x), grades, color="#334155")
    ax.set_xticks(list(x), [label.replace("_", "\n") for label in labels])
    ax.set_ylim(0, 5.4)
    ax.set_ylabel("Posture-resilience grade (0-5)")
    ax.set_title("Graded posture resilience and residual covert exfiltration")
    ax.grid(axis="y", alpha=0.25)
    for rect, value in zip(bars, exfil):
        ax.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 0.1, f"exfil {value:.0f}", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def run_campaign(
    output_dir: str | Path = "output/swarm_compromise",
    config_path: str | Path = "configs/swarm_compromise.json",
) -> dict[str, object]:
    output = Path(output_dir)
    figures = output / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    config, seeds = load_config(config_path)

    results: list[CompromiseResult] = []
    node_rows: list[dict[str, object]] = []
    for seed in seeds:
        for master in HIVE_MASTERS:
            for posture in POSTURES:
                result, rows = run_full_episode(seed, master.name, posture, config)
                results.append(result)
                node_rows.extend(rows)

    summary = summarize(results, node_rows, config, seeds)
    if not summary["accounting_all_ok"]:
        raise AssertionError("swarm-compromise campaign accounting failed")

    summary_path = output / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_results_csv(output / "rows.csv", results)
    _write_node_csv(output / "node_scores.csv", node_rows)
    _plot_outcomes(summary, figures / "compromise_vs_detection.png")
    _plot_grades(summary, figures / "resilience_grades.png")

    config_path = Path(config_path)
    hashes = {
        name: hashlib.sha256((output / name).read_bytes()).hexdigest()
        for name in ("summary.json", "rows.csv", "node_scores.csv")
    }
    receipt = {
        "schema_version": "1.0",
        "experiment_id": f"sealed-swarm-compromise-{len(seeds)}-seeds",
        "configuration_file": config_path.as_posix(),
        "configuration_hash": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "artifacts": hashes,
        "combined_sha256": hashlib.sha256(
            "".join(hashes[name] for name in sorted(hashes)).encode()
        ).hexdigest(),
        "safety_boundary": CompromiseResult.safety_boundary(),
    }
    (output / "witness_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/swarm_compromise")
    parser.add_argument("--config", default="configs/swarm_compromise.json")
    args = parser.parse_args(argv)
    summary = run_campaign(args.output, args.config)
    print(
        json.dumps(
            {
                "posture_resilience": {
                    name: {
                        "grade": summary["posture_resilience"][name]["grade"],
                        "grade_label": summary["posture_resilience"][name]["grade_label"],
                    }
                    for name in POSTURES
                },
                "detector_roc_auc": summary["detector_roc"]["roc_auc"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
