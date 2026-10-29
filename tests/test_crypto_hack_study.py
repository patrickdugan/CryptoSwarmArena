import json
from pathlib import Path

from spiral_ln import crypto_hack_study as study

CORPUS = Path(__file__).resolve().parents[1] / "configs" / "crypto_hack_corpus.json"
MECHS = set(study.MECHANISMS)
SURFACES = {"remote", "local", "phishing", "supply_chain", "side_channel", "key_management", "ui_confusion", "physical", "n/a"}


def test_corpus_records_are_well_formed():
    corpus = study.load_corpus(CORPUS)
    assert corpus["hacks"]
    for h in corpus["hacks"]:
        assert h["primary_mechanism"] in MECHS
        assert set(h["mechanism_chain"]) <= MECHS and h["primary_mechanism"] in h["mechanism_chain"]
        assert h.get("surface", "n/a") in SURFACES
        assert isinstance(h["usd_millions"], (int, float)) and h["usd_millions"] >= 0
        assert h["sources"] and h["stage"]["family"] in {"feral_custody", "swarm", "none"}


def test_stats_are_consistent():
    corpus = study.load_corpus(CORPUS)
    stats = study.compute_stats(corpus)
    n = stats["n_hacks"]
    assert n == len(corpus["hacks"])
    assert sum(a["count"] for a in stats["by_primary_mechanism"].values()) == n
    # chain participation is >= primary count for each mechanism
    for m in study.MECHANISMS:
        prim = stats["by_primary_mechanism"].get(m, {"count": 0})["count"]
        assert stats["mechanism_chain_participation"][m]["count"] >= prim
    # the signer-manipulation cluster is dominated by blind-signing
    sb = stats["signer_manipulation_is_blind_signing"]
    assert sb["count"] >= 5 and sb["count"] <= sb["of_signer_cases"]
    assert set(stats["blind_signing"]["cases"]) >= {"bybit", "wazirx", "radiant"}
    assert stats["dprk"]["count"] >= 5


def test_report_and_stats_are_deterministic(tmp_path):
    a = study.run(CORPUS, tmp_path / "a")
    b = study.run(CORPUS, tmp_path / "b")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    for name in ("stats.json", "report.md"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
    report = (tmp_path / "a" / "report.md").read_text(encoding="utf-8")
    assert "attack-mechanism study" in report and "blind" in report.lower()
