"""Counterfactual defensive-control sweep over the staged kill chains.

For each multi-stage case, re-runs its composed kill chain under one control at a
time and records whether that single control would have broken the chain:

  - phishing_resistant_entry  -- the social-engineering foothold never lands
    (phishing-resistant MFA, training): `foothold_override=False`.
  - clear_signing             -- every signer fully verifies the payload
    (clear-signing / independent verification): `diligence_override=1.0`.
  - device_integrity_patch    -- the ui_confusion / supply_chain advisories on the
    signing stack are fixed (front-end / supply-chain integrity): a patched catalog.

It is a sealed, deterministic what-if study on the sim, turning the corpus into a
defensive-ROI table: which single control breaks each historical chain, and which
control breaks the most chains and dollars.  It stages mechanisms, not technique.
"""

from __future__ import annotations

import argparse
import json
from itertools import combinations
from pathlib import Path

from .software_surface import SoftwareCatalog
from .staged_hacks import load_corpus, stage_chain

CONTROLS = ("phishing_resistant_entry", "clear_signing", "device_integrity_patch")
_LABEL = {"phishing_resistant_entry": "anti-phishing entry",
          "clear_signing": "clear-signing", "device_integrity_patch": "device integrity"}


def patched_catalog(catalog_path: str | Path) -> SoftwareCatalog:
    """Catalog with every ui_confusion / supply_chain advisory marked fixed."""
    data = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    data.pop("schema_version", None)
    data.pop("description", None)
    for advisory in data.get("advisories", []):
        if advisory.get("surface_class") in ("ui_confusion", "supply_chain"):
            advisory["status"] = "fixed"
    return SoftwareCatalog.from_dict(data)


def sweep_chain(record: dict, catalog: SoftwareCatalog, patched: SoftwareCatalog, seed: int = 1) -> dict:
    base = stage_chain(record, catalog, seed)
    row = {"id": record["id"], "name": record["name"], "chain": record["mechanism_chain"],
           "primary_mechanism": record["primary_mechanism"], "usd_millions": record["usd_millions"],
           "surface": record.get("surface", ""), "baseline_success": base["chain_success"]}
    if not base["chain_success"]:
        row["broke_chain"] = {c: False for c in CONTROLS}
        row["broken_by"] = []
        return row
    outcomes = {
        "phishing_resistant_entry": stage_chain(record, catalog, seed, foothold_override=False)["chain_success"],
        "clear_signing": stage_chain(record, catalog, seed, diligence_override=1.0)["chain_success"],
        "device_integrity_patch": stage_chain(record, patched, seed)["chain_success"],
    }
    row["broke_chain"] = {c: (not ok) for c, ok in outcomes.items()}
    row["broken_by"] = [c for c in CONTROLS if row["broke_chain"][c]]
    return row


def sweep_all(corpus: dict, catalog: SoftwareCatalog, patched: SoftwareCatalog, seed: int = 1) -> list[dict]:
    return [sweep_chain(h, catalog, patched, seed) for h in corpus["hacks"] if len(h["mechanism_chain"]) >= 2]


def summarize(rows: list[dict]) -> dict:
    active = [r for r in rows if r["baseline_success"]]
    effect = {}
    for c in CONTROLS:
        broke = [r for r in active if r["broke_chain"][c]]
        effect[c] = {"chains_broken": len(broke), "usd_millions_broken": round(sum(r["usd_millions"] for r in broke), 2),
                     "chains": [r["id"] for r in broke]}
    only = {}
    for r in active:
        if len(r["broken_by"]) == 1:
            only.setdefault(r["broken_by"][0], []).append(r["id"])
    return {"chains": len(active), "control_effect": effect,
            "sole_control": only,
            "chains_broken_by_any": [r["id"] for r in active if r["broken_by"]],
            "chains_broken_by_none": [r["id"] for r in active if not r["broken_by"]]}


def coverage_sets(rows: list[dict]) -> dict:
    """Which SETS of controls cover every live chain (a set covers a chain if any
    of its controls breaks it), and the minimal such sets."""
    active = [r for r in rows if r["baseline_success"]]
    ids = {r["id"] for r in active}

    def covered_by(subset):
        return {r["id"] for r in active if any(r["broke_chain"][c] for c in subset)}

    covering = []
    for k in range(1, len(CONTROLS) + 1):
        for combo in combinations(CONTROLS, k):
            cov = covered_by(combo)
            if cov == ids:
                covering.append(list(combo))
    minimal = [s for s in covering if not any(set(o) < set(s) for o in covering)]
    return {"n_chains": len(active), "covering_sets": covering, "minimal_covering_sets": minimal}


def render_report(rows: list[dict], summary: dict) -> str:
    L = ["# Crypto hacks — single-control defensive ROI", "",
         "For each staged kill chain, which *single* control would have broken it. Sealed, "
         "deterministic what-if on the sim; a control \"breaks\" a chain when the end-to-end drain "
         "no longer occurs. Device integrity only applies to device deception (tampered front-end / "
         "supply chain), not to pure social deception.", "",
         "| case | $M | surface | " + " | ".join(_LABEL[c] for c in CONTROLS) + " |",
         "|---|---|---|" + "---|" * len(CONTROLS)]
    for r in sorted(rows, key=lambda r: -r["usd_millions"]):
        cells = " | ".join("breaks" if r["broke_chain"][c] else "—" for c in CONTROLS)
        L.append(f"| {r['name']} | {r['usd_millions']:.1f} | {r['surface']} | {cells} |")
    L += ["", "## Control effectiveness (over the staged chains)", "",
          "| control | chains broken | $M broken |", "|---|---|---|"]
    for c in CONTROLS:
        e = summary["control_effect"][c]
        L.append(f"| {_LABEL[c]} | {e['chains_broken']}/{summary['chains']} | {e['usd_millions_broken']:.1f} |")
    L += ["", "## Reading it", "",
          "- **Anti-phishing entry** breaks all of these chains **by construction**: every staged "
          "chain is entered through a social foothold that gates its terminal, so removing the "
          "entry necessarily breaks it. The 9/9 is a property of how these chains are modeled, "
          "not a measured ranking — the informative comparison is among the *downstream* controls.",
          "- **Clear-signing** (independent payload verification) breaks the signer-manipulation "
          "chains (5 blind-signing — Ledger, DMM, WazirX, Radiant, Bybit — plus BitPay's "
          "impersonation approval) regardless of how the attacker got in: the robust control for "
          "the signer terminal, and the historical lesson after WazirX/Bybit.",
          "- **Device integrity** (front-end / supply-chain patch) faithfully breaks *device* "
          "deception (Bybit's tampered Safe front-end) but not *social* deception (BitPay's "
          "impersonation email). For the credential-terminal chains (Coincheck, Ronin) it breaks "
          "them only because the model routes every chain's key-theft through one supply_chain "
          "implant — a modeling choice, not those cases' real surfaces (hot-wallet / validator "
          "key theft)."]
    cov = coverage_sets(rows)
    L += ["", "## Minimal control sets", "",
          "A set covers a chain if any of its controls breaks it. Minimal sets that cover all "
          f"{cov['n_chains']} chains:"]
    for s in cov["minimal_covering_sets"]:
        L.append(f"- {{ {', '.join(_LABEL[c] for c in s)} }}")
    L += ["",
          "So either a phishing-resistant entry alone (by construction), **or** clear-signing "
          "plus front-end/supply-chain integrity together — defense-in-depth that does not rely "
          "on stopping the social-engineering entry."]
    if summary["sole_control"]:
        L += ["", "Chains where exactly one control would have worked:"]
        for c, ids in sorted(summary["sole_control"].items()):
            L.append(f"- only **{_LABEL[c]}**: {', '.join(ids)}")
    return "\n".join(L) + "\n"


def robustness(corpus: dict, catalog: SoftwareCatalog, patched: SoftwareCatalog, seeds) -> dict:
    """Run the sweep across several seeds and report, per chain, the fraction of
    seeds on which the chain drains at baseline and on which each control breaks it.
    A control-break rate of exactly 0 or 1 means the result is structural (seed-
    independent); anything in between is seed-dependent and is flagged."""
    seeds = list(seeds)
    agg: dict[str, dict] = {}
    for seed in seeds:
        for r in sweep_all(corpus, catalog, patched, seed):
            d = agg.setdefault(r["id"], {"name": r["name"], "usd_millions": r["usd_millions"],
                                         "baseline_live": 0, "break": {c: 0 for c in CONTROLS}})
            if r["baseline_success"]:
                d["baseline_live"] += 1
                for c in CONTROLS:
                    if r["broke_chain"][c]:
                        d["break"][c] += 1
    n = len(seeds)
    per_chain = []
    unstable = []
    for cid in sorted(agg):
        d = agg[cid]
        live = d["baseline_live"]
        rates = {c: (round(d["break"][c] / live, 3) if live else None) for c in CONTROLS}
        per_chain.append({"id": cid, "name": d["name"], "usd_millions": d["usd_millions"],
                          "baseline_success_rate": round(live / n, 3), "control_break_rate": rates})
        if live < n:
            unstable.append({"id": cid, "issue": "baseline not always live", "rate": round(live / n, 3)})
        for c in CONTROLS:
            if rates[c] is not None and 0.0 < rates[c] < 1.0:
                unstable.append({"id": cid, "control": c, "break_rate": rates[c]})
    return {"seeds": seeds, "per_chain": per_chain, "unstable": unstable,
            "all_structural": not unstable}


def render_robustness(rob: dict) -> str:
    L = ["# Crypto hacks — control-ROI seed robustness", "",
         f"The single-control sweep run across seeds {rob['seeds']}, reporting per chain the "
         "fraction of seeds on which it drains at baseline and on which each control breaks it. "
         "A rate of 0 or 1 is structural (seed-independent); anything between is seed-dependent.", "",
         "| case | baseline live | " + " | ".join(_LABEL[c] for c in CONTROLS) + " |",
         "|---|---|" + "---|" * len(CONTROLS)]
    for r in sorted(rob["per_chain"], key=lambda r: -r["usd_millions"]):
        cells = " | ".join("—" if r["control_break_rate"][c] is None else f"{r['control_break_rate'][c]:.0%}" for c in CONTROLS)
        L.append(f"| {r['name']} | {r['baseline_success_rate']:.0%} | {cells} |")
    L += ["", ("**All control-break results are structural (0% or 100% across seeds)** and every "
               "chain drains at baseline on every seed, so the ROI table is not an artifact of a "
               "single seed — it is entailed by the model's gating."
               if rob["all_structural"] else
               "**Seed-dependent results flagged** (not all structural):")]
    if not rob["all_structural"]:
        for u in rob["unstable"]:
            L.append(f"- {u}")
    return "\n".join(L) + "\n"


def run(corpus_path: str | Path, catalog_path: str | Path, output_dir: str | Path, seed: int = 1, seeds=None) -> dict:
    corpus = load_corpus(corpus_path)
    catalog = SoftwareCatalog.load(catalog_path)
    patched = patched_catalog(catalog_path)
    rows = sweep_all(corpus, catalog, patched, seed)
    summary = summarize(rows)
    payload = {"schema_version": "1.0", "seed": seed, "summary": summary, "rows": rows,
               "coverage": coverage_sets(rows),
               "safety_boundary": {"synthetic_only": True, "stages_mechanism_not_technique": True}}
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "controls.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "report.md").write_text(render_report(rows, summary), encoding="utf-8")
    if seeds is not None:
        rob = robustness(corpus, catalog, patched, seeds)
        payload["robustness"] = rob
        (out / "robustness.json").write_text(json.dumps(rob, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out / "robustness.md").write_text(render_robustness(rob), encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="configs/crypto_hack_corpus.json")
    parser.add_argument("--catalog", default="configs/software_catalog.json")
    parser.add_argument("--output", default="output/hack_controls")
    parser.add_argument("--seeds", type=int, default=8, help="number of seeds (0..N-1) for the robustness sweep")
    args = parser.parse_args(argv)
    payload = run(args.corpus, args.catalog, args.output, seeds=range(args.seeds))
    for c in CONTROLS:
        e = payload["summary"]["control_effect"][c]
        print(f"  {_LABEL[c]:20s} breaks {e['chains_broken']}/{payload['summary']['chains']} chains, ${e['usd_millions_broken']:.0f}M")
    rob = payload.get("robustness", {})
    print(f"robustness over {len(rob.get('seeds', []))} seeds: all_structural={rob.get('all_structural')}, unstable={len(rob.get('unstable', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
