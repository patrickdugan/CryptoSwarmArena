"""Campaign runner for the key-value binding probe.

The default run uses scripted binders only: it validates ``spiral_ln.rtg.keyvalue``
against sources whose geometry and binding are planted, and fails unless they are
recovered.  It makes no model call.

A model is attached through a file, never a library: ``--export-prompts`` writes
the rendered prompts, ``rtg_r/capture.py`` (the one place that loads weights)
turns them into per-layer states at the decision token, and ``--activations``
reads those back.  The file is refused unless it was captured for exactly the
prompts this configuration builds.  A model result is exploratory: forward passes
on static prompts, no arena episode, no generation, nothing steered.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .rtg.awareness import Prompt, ProbePolicy, contrast_hash
from .rtg.keyvalue import (
    CONCEPTS,
    HEADLINE_CONTRASTS,
    SCRIPTED_BINDING,
    ScriptedBinder,
    analyze,
    contrast_prompts,
    target_prompts,
)
from .rtg_awareness_eval import SAFETY_BOUNDARY, _rounded, chatml


def export_prompts(path: str | Path, prompts: Sequence[Prompt]) -> str:
    """Write the rendered prompts for an external capture; returns their hash."""

    digest = contrast_hash(prompts)
    Path(path).write_text(
        json.dumps({"sha256": digest, "texts": [chatml(prompt) for prompt in prompts]}), encoding="utf-8"
    )
    return digest


@dataclass(frozen=True)
class SavedActivations:
    """States captured elsewhere for a known prompt list: ``acts`` of shape
    (prompts, layers, dim) and a JSON ``meta`` string carrying ``prompt_sha256``."""

    path: str

    def meta(self) -> dict[str, Any]:
        with np.load(self.path) as data:
            return json.loads(str(data["meta"]))

    @property
    def name(self) -> str:
        meta = self.meta()
        return f"saved:{meta['model']}@{meta['revision'][:12]}:{meta['quantization']}"

    def capture(self, prompts: Sequence[Prompt]) -> np.ndarray:
        expected = contrast_hash(prompts)
        with np.load(self.path) as data:
            found = json.loads(str(data["meta"]))["prompt_sha256"]
            if found != expected:
                raise ValueError(f"activations were captured for prompts {found[:12]}, not {expected[:12]}")
            return np.asarray(data["acts"], dtype=np.float32)


def load_config(path: str | Path) -> tuple[int, int, list[ScriptedBinder], ProbePolicy]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    binders = [ScriptedBinder(kind, seed) for kind in raw["binder_kinds"] for seed in raw["binder_seeds"]]
    return int(raw["state_count"]), int(raw["target_state_count"]), binders, ProbePolicy(**raw.get("policy", {}))


def _scripted_acceptance(binders: Sequence[ScriptedBinder], reports: dict[str, dict]) -> dict[str, bool]:
    """All must hold before a model result is interpretable."""

    planted = [(b, reports[b.name]) for b in binders if b.kind in SCRIPTED_BINDING]
    value = lambda report, contrast: report["targets"].get("value", {}).get("contrasts", {}).get(contrast, {}).get("mean")
    near = lambda found, wanted, tolerance: found is not None and abs(found - wanted) <= tolerance
    return {
        "concept_verdicts_match": all(
            {c: r["concepts"][c]["verdict"] for c in CONCEPTS}
            == {c: f"{c}_signal" if b.kind != "null" else "no_signal" for c in CONCEPTS}
            for b, r in ((b, reports[b.name]) for b in binders)
        ),
        "planted_cosine_recovered": all(
            near(r["topology"][-1]["cosine"]["eval~value"], b.value_eval_cosine, 0.15) for b, r in planted
        ),
        # The level carries word-level offsets (a key turn and an inert turn use
        # different words); the interaction cancels them, hence the tighter bound.
        "key_lift_recovered": all(
            near(value(r, "key_lift@mainnet"), SCRIPTED_BINDING[b.kind][0], 0.25) for b, r in planted
        ),
        "disclosure_on_key_lift_recovered": all(
            near(value(r, "disclosure_on_key_lift@mainnet"), SCRIPTED_BINDING[b.kind][1], 0.2) for b, r in planted
        ),
        "disclosure_moves_eval": all(
            near(r["targets"].get("eval", {}).get("contrasts", {}).get("disclosure_on_inert@mainnet", {}).get("mean"), 1.0, 0.25)
            for _, r in planted
        ),
        "lexical_baselines_at_chance": all(
            abs(r["concepts"][c]["confirmation"]["lexical_transfer_auroc"] - 0.5) <= 0.05
            for r in reports.values()
            for c in CONCEPTS
        ),
    }


def _plot_topology(report: dict[str, Any], title: str, path: Path) -> None:
    layers = [row["layer"] for row in report["topology"]]
    colors = {"eval": "#0f766e", "value": "#b45309", "reward": "#1d4ed8"}
    fig, axes = plt.subplots(1, 3, figsize=(15.0, 4.4))

    for concept in CONCEPTS:
        axes[0].plot(layers, [row["transfer_auroc"][concept] for row in report["topology"]], color=colors[concept], label=concept)
    axes[0].axhline(0.5, color="#94a3b8", linewidth=0.8)
    axes[0].set_ylim(0.0, 1.05)
    axes[0].set_ylabel("Leave-one-family-out AUROC (confirmation forms)")
    axes[0].set_title("Where each concept direction transfers")

    for pair, color in zip(report["topology"][0]["cosine"], ("#334155", "#be123c", "#7c3aed")):
        axes[1].plot(layers, [row["cosine"][pair] for row in report["topology"]], color=color, label=pair.replace("~", " · "))
    axes[1].axhline(0.0, color="#94a3b8", linewidth=0.8)
    axes[1].set_ylim(-1.0, 1.0)
    axes[1].set_ylabel("Cosine between directions")
    axes[1].set_title("Geometry (read only where both transfer)")

    styles = dict(zip(HEADLINE_CONTRASTS, ("-", ":", "--")))
    for concept in ("eval", "value"):
        for contrast in ("disclosure_on_key@mainnet", "disclosure_on_key_lift@mainnet"):
            axes[2].plot(
                layers,
                [(row["contrasts"][concept] or {}).get(contrast, float("nan")) for row in report["topology"]],
                styles[contrast],
                color=colors[concept],
                label=f"{concept}: {contrast.split('@')[0].replace('_', ' ')}",
            )
    axes[2].axhline(0.0, color="#94a3b8", linewidth=0.8)
    axes[2].set_ylabel("Index shift (centroid units)")
    axes[2].set_title("Told it is a fake testnet (mainnet mask)")

    for ax in axes:
        ax.set_xlabel("Layer")
        ax.grid(axis="y", alpha=0.25)
        ax.legend(fontsize=8)
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def run_campaign(
    output_dir: str | Path = "output/rtg_keyvalue",
    config_path: str | Path = "configs/rtg_keyvalue.json",
    activations: str | Path | None = None,
) -> dict[str, Any]:
    output = Path(output_dir)
    figures = output / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    config_path = Path(config_path)
    state_count, target_state_count, binders, policy = load_config(config_path)
    prompts = contrast_prompts(state_count) + target_prompts(target_state_count)

    reports = {b.name: analyze(b.name, b.capture(prompts), prompts, policy) for b in binders}
    acceptance = _scripted_acceptance(binders, reports)
    if not all(acceptance.values()):
        raise AssertionError(f"key-value instrument failed scripted acceptance: {acceptance}")

    model_reports = {}
    receipt_extra: dict[str, Any] = {}
    if activations is not None:
        source = SavedActivations(str(activations))
        model_reports[source.name] = analyze(source.name, source.capture(prompts), prompts, policy)
        receipt_extra = {
            "activations_sha256": hashlib.file_digest(open(activations, "rb"), "sha256").hexdigest(),
            "capture": source.meta(),
        }

    rows: list[dict[str, Any]] = []
    for report in list(reports.values()) + list(model_reports.values()):
        rows += report.pop("rows", [])
    summary = _rounded(
        {
            "schema_version": "1.0",
            "prompts": {
                "sha256": contrast_hash(prompts),
                "count": len(prompts),
                "state_count": state_count,
                "target_state_count": target_state_count,
                "concept_families": {concept: list(families) for concept, (_, families) in CONCEPTS.items()},
            },
            "policy": asdict(policy),
            "scripted_acceptance": acceptance,
            "scripted_sources": reports,
            "model_sources": model_reports,
            "guardrail": (
                "Scripted results validate the instrument and are not evidence about any model. "
                "A model result is exploratory and describes decodable shifts, not intent or behavior."
            ),
            "safety_boundary": SAFETY_BOUNDARY + " Every key-like string is an invalid decoy.",
        }
    )

    artifacts = ["summary.json", "rows.csv"]
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output / "rows.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["source", "concept", "condition", "state", "form", "index"])
        writer.writeheader()
        writer.writerows(_rounded(rows))
    shown = next(iter(model_reports.items()), None) or next(
        (name, report) for name, report in summary["scripted_sources"].items() if ":bound:" in name
    )
    _plot_topology(summary["model_sources"].get(shown[0]) or summary["scripted_sources"][shown[0]], shown[0], figures / "topology.png")

    hashes = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in artifacts}
    receipt = {
        "schema_version": "1.0",
        "experiment_id": f"rtg-keyvalue-{len(binders)}-binders-{len(model_reports)}-models",
        "configuration_file": config_path.as_posix(),
        "configuration_hash": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "prompt_sha256": summary["prompts"]["sha256"],
        "artifacts": hashes,
        "combined_sha256": hashlib.sha256("".join(hashes[name] for name in sorted(hashes)).encode()).hexdigest(),
        "safety_boundary": summary["safety_boundary"],
        **receipt_extra,
    }
    (output / "witness_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="output/rtg_keyvalue")
    parser.add_argument("--config", default="configs/rtg_keyvalue.json")
    parser.add_argument("--export-prompts", help="write the rendered prompts to this JSON file and exit")
    parser.add_argument("--activations", help="npz written by rtg_r/capture.py for the exported prompts")
    args = parser.parse_args(argv)
    if args.export_prompts:
        state_count, target_state_count, _, _ = load_config(args.config)
        prompts = contrast_prompts(state_count) + target_prompts(target_state_count)
        print(json.dumps({"prompts": len(prompts), "sha256": export_prompts(args.export_prompts, prompts)}))
        return 0
    summary = run_campaign(args.output, args.config, args.activations)
    brief = {
        name: {
            "concepts": {c: [v["verdict"], v.get("selected_layer")] for c, v in report["concepts"].items()},
            "targets": {
                c: {contrast: [s["mean"], s["two_sided_sign_p_value"]] for contrast, s in t["contrasts"].items()}
                for c, t in report["targets"].items()
            },
        }
        for name, report in summary["model_sources"].items()
    }
    print(json.dumps({"scripted_acceptance": summary["scripted_acceptance"], "model_sources": brief}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
