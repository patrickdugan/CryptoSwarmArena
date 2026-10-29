"""Statistical study of the curated crypto-hack corpus.

Loads ``configs/crypto_hack_corpus.json`` and tabulates the cases by attack
mechanism (primary cause and chain participation), by target type, by year, and
by the signing / multisig / attribution dimensions, then writes a Markdown report
and a JSON of the numbers.  It is a descriptive study of a curated, illustrative
sample — not an exhaustive or dollar-exact census — and it is deterministic (no
timestamps), so the report is reproducible.

The four mechanisms match the RTG eval taxonomy: human_deception,
signer_manipulation, credential_compromise, technical_exploitation.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

MECHANISMS = ("human_deception", "signer_manipulation", "credential_compromise", "technical_exploitation")


def load_corpus(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _is_dprk(attribution: str) -> bool:
    a = attribution.lower()
    return "lazarus" in a or "dprk" in a or "north korea" in a


def compute_stats(corpus: dict) -> dict:
    hacks = corpus["hacks"]
    n = len(hacks)
    total_usd = round(sum(h["usd_millions"] for h in hacks), 2)

    def _bucket(key_fn):
        count: Counter = Counter()
        usd: dict[str, float] = defaultdict(float)
        for h in hacks:
            k = key_fn(h)
            count[k] += 1
            usd[k] += h["usd_millions"]
        return {k: {"count": count[k], "usd_millions": round(usd[k], 2),
                    "count_share": round(count[k] / n, 4),
                    "usd_share": round(usd[k] / total_usd, 4) if total_usd else 0.0}
                for k in sorted(count)}

    # primary cause vs chain participation (a case chains several mechanisms)
    by_primary = _bucket(lambda h: h["primary_mechanism"])
    participation: dict[str, dict] = {}
    for m in MECHANISMS:
        subset = [h for h in hacks if m in h["mechanism_chain"]]
        participation[m] = {
            "count": len(subset),
            "count_share": round(len(subset) / n, 4),
            "usd_millions": round(sum(h["usd_millions"] for h in subset), 2),
            "usd_share": round(sum(h["usd_millions"] for h in subset) / total_usd, 4) if total_usd else 0.0,
        }

    multisig = [h for h in hacks if h.get("multisig")]
    blind = [h for h in hacks if h.get("blind_signing")]
    signer = [h for h in hacks if h["primary_mechanism"] == "signer_manipulation"]
    dprk = [h for h in hacks if _is_dprk(h.get("attribution", ""))]

    return {
        "schema_version": "1.0",
        "evidence_scope": "curated illustrative sample; dollar figures as-reported and mark-to-market at time of theft",
        "n_hacks": n,
        "total_usd_millions": total_usd,
        "by_primary_mechanism": by_primary,
        "mechanism_chain_participation": participation,
        "by_target_type": _bucket(lambda h: h["target_type"]),
        "by_year": _bucket(lambda h: h["date"][:4]),
        "by_surface": _bucket(lambda h: h.get("surface", "n/a")),
        "multisig": {"count": len(multisig), "count_share": round(len(multisig) / n, 4),
                     "usd_millions": round(sum(h["usd_millions"] for h in multisig), 2)},
        "blind_signing": {"count": len(blind), "count_share": round(len(blind) / n, 4),
                          "usd_millions": round(sum(h["usd_millions"] for h in blind), 2),
                          "cases": [h["id"] for h in blind]},
        "signer_manipulation_is_blind_signing": {
            "count": sum(1 for h in signer if h.get("blind_signing")),
            "of_signer_cases": len(signer)},
        "dprk": {"count": len(dprk), "count_share": round(len(dprk) / n, 4),
                 "usd_millions": round(sum(h["usd_millions"] for h in dprk), 2),
                 "usd_share": round(sum(h["usd_millions"] for h in dprk) / total_usd, 4) if total_usd else 0.0},
        "chain_length_distribution": {str(k): v for k, v in sorted(Counter(len(h["mechanism_chain"]) for h in hacks).items())},
        "aggregate_benchmarks": corpus.get("aggregate_benchmarks", {}),
    }


def _pct(x: float) -> str:
    return f"{round(x * 100):d}%"


def render_report(stats: dict, corpus: dict) -> str:
    L = [
        "# Crypto hacks — attack-mechanism study",
        "",
        f"A curated sample of **{stats['n_hacks']}** notable crypto thefts "
        f"(~${stats['total_usd_millions']/1000:.1f}B at time of theft), characterised by the four RTG "
        "attack mechanisms. Illustrative, not an exhaustive or dollar-exact census; figures are "
        "as-reported and mark-to-market. External aggregates are listed at the end for context.",
        "",
        "## Primary cause (dominant mechanism per case)",
        "",
        "| mechanism | cases | case share | $M | $ share |",
        "|---|---|---|---|---|",
    ]
    for m in MECHANISMS:
        a = stats["by_primary_mechanism"].get(m, {"count": 0, "count_share": 0, "usd_millions": 0, "usd_share": 0})
        L.append(f"| {m} | {a['count']} | {_pct(a['count_share'])} | {a['usd_millions']:.1f} | {_pct(a['usd_share'])} |")
    L += [
        "",
        "## Chain participation (mechanism appears anywhere in the kill chain)",
        "",
        "Catastrophic thefts chain mechanisms, so a case counts under every mechanism in its chain. "
        "This is why human deception and credential compromise dominate participation even when the "
        "*terminal* act is a signed transfer.",
        "",
        "| mechanism | cases | case share | $M | $ share |",
        "|---|---|---|---|---|",
    ]
    for m in MECHANISMS:
        a = stats["mechanism_chain_participation"][m]
        L.append(f"| {m} | {a['count']} | {_pct(a['count_share'])} | {a['usd_millions']:.1f} | {_pct(a['usd_share'])} |")

    sb = stats["signer_manipulation_is_blind_signing"]
    bl = stats["blind_signing"]
    L += [
        "",
        "## Signing, multisig, and attribution",
        "",
        f"- **Blind / spoofed signing**: {bl['count']} of {stats['n_hacks']} cases "
        f"(${bl['usd_millions']/1000:.1f}B) — the signer approved a tampered display or payload. "
        f"Cases: {', '.join(bl['cases'])}.",
        f"- **Signer-manipulation cases that are blind-signing**: {sb['count']} of {sb['of_signer_cases']} — "
        "deception of the signer, not coercion, is the modern signer-manipulation pattern.",
        f"- **Multisig involved**: {stats['multisig']['count']} of {stats['n_hacks']} cases "
        f"(${stats['multisig']['usd_millions']/1000:.1f}B). Multisig does **not** stop blind-signing: "
        "WazirX (3-of-6), Radiant (3-of-11), Bybit (Safe cold wallet) were all multisig drains where a "
        "uniform tampered display fooled the quorum.",
        f"- **DPRK-attributed**: {stats['dprk']['count']} of {stats['n_hacks']} cases, "
        f"{_pct(stats['dprk']['usd_share'])} of sampled dollars.",
        "",
        "## By target type",
        "",
        "| target | cases | $M |",
        "|---|---|---|",
    ]
    for t, a in stats["by_target_type"].items():
        L.append(f"| {t} | {a['count']} | {a['usd_millions']:.1f} |")

    L += ["", "## By year", "", "| year | cases | $M |", "|---|---|---|"]
    for y, a in stats["by_year"].items():
        L.append(f"| {y} | {a['count']} | {a['usd_millions']:.1f} |")

    L += ["", "## Relevance to the eval", "",
          "The sample is dominated by **signer manipulation via deception** (blind-signing / spoofed "
          "approval) and **credential compromise**, usually *entered* through **human deception** and "
          "run by a DPRK actor. Technical exploitation is a large share of *bridge/DeFi* cases but a "
          "smaller share of dollars in this sample. This is why the feral-custody family now models a "
          "`deceived_signing` objective distinct from coercion and key theft (and applies it to "
          "threshold signing, which these multisig drains show is not immune), and a remote "
          "software-implant key-exfil channel — see `paper/feral_custody_design.md` and the RTG paper §2.",
          "",
          "## External aggregate benchmarks (as reported; scope varies, not reconciled)", ""]
    for item in stats.get("aggregate_benchmarks", {}).get("items", []):
        L.append(f"- {item['metric']}: **{item['value']}** ({item['source']})")
    return "\n".join(L) + "\n"


def run(corpus_path: str | Path, output_dir: str | Path) -> dict:
    corpus = load_corpus(corpus_path)
    stats = compute_stats(corpus)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "report.md").write_text(render_report(stats, corpus), encoding="utf-8")
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="configs/crypto_hack_corpus.json")
    parser.add_argument("--output", default="output/crypto_hack_study")
    args = parser.parse_args(argv)
    stats = run(args.corpus, args.output)
    print(json.dumps({"n_hacks": stats["n_hacks"], "total_usd_millions": stats["total_usd_millions"],
                      "by_primary": {m: stats["by_primary_mechanism"].get(m, {}).get("count", 0) for m in MECHANISMS}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
