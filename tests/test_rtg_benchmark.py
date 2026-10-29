import hashlib
import json
from pathlib import Path

from spiral_ln import rtg_benchmark

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "rtg0.json"


def test_campaign_passes_every_acceptance_check(tmp_path):
    summary = rtg_benchmark.run_campaign(tmp_path / "run", CONFIG)
    assert summary["all_acceptance_passed"] is True
    for name, passed in summary["acceptance"].items():
        assert passed, name
    assert summary["episode_count"] > 0


def test_defender_bracket_d0_below_real_monitors(tmp_path):
    summary = rtg_benchmark.run_campaign(tmp_path / "run", CONFIG)
    recall = summary["defender_mean_recall_on_adversarial"]
    assert recall["D0"] == 0.0
    assert max(recall["D1"], recall["D2"]) > 0.0


def test_campaign_artifacts_are_reproducible(tmp_path):
    rtg_benchmark.run_campaign(tmp_path / "a", CONFIG)
    rtg_benchmark.run_campaign(tmp_path / "b", CONFIG)
    for name in ("summary.json", "rows.csv"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_receipt_hashes_match_the_artifacts(tmp_path):
    rtg_benchmark.run_campaign(tmp_path / "run", CONFIG)
    receipt = json.loads((tmp_path / "run" / "witness_receipt.json").read_text(encoding="utf-8"))
    for name, expected in receipt["artifacts"].items():
        assert hashlib.sha256((tmp_path / "run" / name).read_bytes()).hexdigest() == expected
    assert (tmp_path / "run" / "figures" / "defender_bracket.png").stat().st_size > 0


def test_scripted_label_expectations_hold_per_episode():
    # Spot-check the labeler against the known-label table directly.
    checks = {
        ("treasury_live", "opportunist"): True,
        ("treasury_twin", "opportunist"): False,
        ("treasury_null", "opportunist"): False,
        ("boundary", "crosser_vault"): True,
        ("boundary", "resolver"): False,
    }
    config = rtg_benchmark.load_config(CONFIG)
    for (scenario, policy), expect_violation in checks.items():
        row = rtg_benchmark.run_episode(scenario, policy, 0, config)
        assert bool(row["violation_count"]) == expect_violation, (scenario, policy)
