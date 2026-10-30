"""Export the historical hack corpus as game data for the "Heist Desk" browser game.

For every playable corpus hack this runs the staged kill chain under each of the
2^3 subsets of the defensive controls (see ``hack_controls``) across a fixed seed
range, and records per-stage results.  Output is deterministic (byte-identical
across runs) and is inlined into ``ui/play/index.html`` by ``ui/play/build_play.py``.

    python -m spiral_ln.hack_game --out ui/play/scenarios.json
"""

from __future__ import annotations

import argparse
import json
from itertools import combinations
from pathlib import Path

from .hack_controls import CONTROLS, patched_catalog
from .software_surface import SoftwareCatalog
from .staged_hacks import load_corpus, stage_chain

SCHEMA = "heist-desk/1"
NOT_PLAYABLE_REASON = ("Pure code exploits are outside the sim: it stages people, keys and signers, "
                       "not software bugs.")


def control_subsets() -> list[tuple[str, ...]]:
    """All subsets of CONTROLS, in CONTROLS order within each subset, smallest first."""
    return [combo for k in range(len(CONTROLS) + 1) for combo in combinations(CONTROLS, k)]


def subset_key(subset) -> str:
    return "+".join(c for c in CONTROLS if c in subset)


def _stage_status(stage: dict) -> str:
    if stage.get("abstracted"):
        return "abstract"
    flag = stage["landed"] if "landed" in stage else stage.get("exhibited")
    if flag is None:
        return "abstract"
    return "landed" if flag else "blocked"


def _run_chain(record: dict, catalog: SoftwareCatalog, patched: SoftwareCatalog, subset, seed: int) -> dict:
    kwargs: dict = {}
    if "phishing_resistant_entry" in subset:
        kwargs["foothold_override"] = False
    if "clear_signing" in subset:
        kwargs["diligence_override"] = 1.0
    cat = patched if "device_integrity_patch" in subset else catalog
    res = stage_chain(record, cat, seed, **kwargs)
    raw = [_stage_status(st) for st in res["stages"]]
    success = bool(res["chain_success"])
    if success:
        # The chain still drained: a stage the sim marked blocked was routed around (e.g. BitPay's
        # implant link is patched but its terminal is social deception that needs no implant).
        statuses = ["bypassed" if s == "blocked" else s for s in raw]
    else:
        statuses, blocked = [], False
        for s in raw:
            statuses.append("not_reached" if blocked else s)
            blocked = blocked or s == "blocked"
    return {"seed": seed, "success": success, "stages": statuses}


def build_scenarios(corpus_path, catalog_path, content_path, seeds=range(1, 9)) -> dict:
    seeds = list(seeds)
    corpus = load_corpus(corpus_path)
    catalog = SoftwareCatalog.load(catalog_path)
    patched = patched_catalog(catalog_path)
    content = json.loads(Path(content_path).read_text(encoding="utf-8"))
    subsets = control_subsets()

    scenarios = []
    for h in corpus["hacks"]:
        chain = list(h["mechanism_chain"])
        playable = not all(m == "technical_exploitation" for m in chain)
        sc = {"id": h["id"], "name": h["name"], "date": h["date"], "year": int(str(h["date"])[:4]),
              "usd_millions": h["usd_millions"], "native": h["native"], "target_type": h["target_type"],
              "attribution": h["attribution"], "device_or_infra": h["device_or_infra"],
              "root_cause": h["root_cause"], "defense": h["defense"], "confidence": h["confidence"],
              "sources": h["sources"], "surface": h.get("surface", ""),
              "primary_mechanism": h["primary_mechanism"], "chain": chain, "playable": playable}
        if not playable:
            sc["reason"] = NOT_PLAYABLE_REASON
        else:
            outcomes = {}
            for subset in subsets:
                runs = [_run_chain(h, catalog, patched, subset, s) for s in seeds]
                outcomes[subset_key(subset)] = {
                    "success_rate": round(sum(r["success"] for r in runs) / len(runs), 3),
                    "runs": runs}
            sc["outcomes"] = outcomes
        scenarios.append(sc)

    playable = [s for s in scenarios if s["playable"]]
    singles = [c for c in CONTROLS]
    unstoppable = [s["id"] for s in playable
                   if all(s["outcomes"][c]["success_rate"] == 1.0 for c in singles)]
    return {
        "schema": SCHEMA, "generated_by": "spiral_ln.hack_game", "seeds": seeds,
        "control_ids": list(CONTROLS), "content": content, "scenarios": scenarios,
        "summary": {"playable": len(playable), "history_only": len(scenarios) - len(playable),
                    "unstoppable_by_any_single_control": unstoppable,
                    "total_usd_millions_playable": round(sum(s["usd_millions"] for s in playable), 2)},
    }


def dumps(data: dict) -> str:
    return json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="configs/crypto_hack_corpus.json")
    parser.add_argument("--catalog", default="configs/software_catalog.json")
    parser.add_argument("--content", default="configs/heist_content.json")
    parser.add_argument("--out", default="ui/play/scenarios.json")
    parser.add_argument("--seeds", type=int, default=8, help="seeds 1..N")
    args = parser.parse_args(argv)
    data = build_scenarios(args.corpus, args.catalog, args.content, range(1, args.seeds + 1))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dumps(data), encoding="utf-8", newline="\n")
    s = data["summary"]
    print(f"wrote {out} ({out.stat().st_size} bytes): {s['playable']} playable, {s['history_only']} history-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
