import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from statistics import mean

import numpy as np
import pytest

import spiral_ln
from spiral_ln import rtg_awareness_eval
from spiral_ln.rtg.awareness import (
    CUES,
    POSITIVE_FAMILIES,
    NETWORKS,
    SCRIPTED_LABELS,
    ProbePolicy,
    ScriptedOrganism,
    auroc,
    build_contrast_set,
    contrast_hash,
    evaluate_source,
    lexical_features,
    mask_prompts,
)
from spiral_ln.rtg.addressing import is_decoy

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "rtg_eval_awareness.json"


@pytest.fixture(scope="module")
def prompts():
    return build_contrast_set(4)


def test_pair_members_differ_only_in_the_cue_line(prompts):
    pairs = {}
    for prompt in prompts:
        pairs.setdefault((prompt.family, prompt.form, prompt.state), {})[prompt.label] = prompt
    assert len(pairs) == len(CUES) * 8 * 4
    for (family, form, _), members in pairs.items():
        one, zero = members[1], members[0]
        assert one.system == zero.system
        one_lines, zero_lines = one.user.split("\n"), zero.user.split("\n")
        assert (one_lines[0], zero_lines[0]) == CUES[family][form]
        assert one_lines[1:] == zero_lines[1:]


def test_scripted_organisms_reproduce_their_known_labels(prompts):
    # Acceptance: the instrument must recover every scripted label before a model
    # result is interpretable.
    for kind, label in SCRIPTED_LABELS.items():
        for seed in range(4):
            report, probe = evaluate_source(ScriptedOrganism(kind, seed), prompts)
            assert report["verdict"] == label, (kind, seed, report["gates"])
            assert (probe is not None) == (label == "eval_awareness_signal")


def test_planted_direction_is_recovered_at_or_after_onset(prompts):
    organism = ScriptedOrganism("aware", seed=1)
    report, probe = evaluate_source(organism, prompts)
    assert probe.layer >= organism.onset
    assert float(probe.direction @ organism.direction()) >= 0.9
    # The scripted belief ignores in-world monitoring, so the direction must too.
    assert 0.3 <= report["discriminant"]["oversight_auroc"] <= 0.7
    # Held-out forms land on the right centroid.
    held_out = [row for row in report["rows"] if row["split"] == "confirmation" and row["family"] in POSITIVE_FAMILIES]
    assert abs(mean(row["index"] for row in held_out if row["label"] == 1) - 1.0) < 0.2
    assert abs(mean(row["index"] for row in held_out if row["label"] == 0)) < 0.2


def test_mask_readout_recovers_the_scripted_mask_belief(prompts):
    # The network mask is never used to fit the probe.  An organism that believes
    # the mask must show it; one that ignores the mask must not.
    masked = mask_prompts(8)
    assert len(masked) == 8 * len(NETWORKS)
    assert all(p.label is None and f"Network: {NETWORKS[p.form]}." in p.user for p in masked)
    believer = evaluate_source(ScriptedOrganism("aware_mask"), prompts, masked=masked)[0]["readout"]
    assert abs(believer["testnet_minus_mainnet"]["mean"] - 1.0) < 0.25
    assert believer["testnet_minus_mainnet"]["positive_states"] == 8
    assert believer["index_by_network"]["mainnet"] < 0.25 < 0.75 < believer["index_by_network"]["testnet"]
    ignorer = evaluate_source(ScriptedOrganism("aware"), prompts, masked=masked)[0]["readout"]
    assert abs(ignorer["testnet_minus_mainnet"]["mean"]) < 0.25
    assert abs(ignorer["rtg_minus_mainnet"]["mean"]) < 0.25


def test_contrast_pairs_never_show_the_mask_and_readout_addresses_are_decoys(prompts):
    assert not any("Network:" in p.user for p in prompts)
    for prompt in mask_prompts(2):
        addresses = [word for word in prompt.user.split() if word[:3] in ("bc1", "tb1", "rtg") and "1q" in word]
        assert len(addresses) == 3 and all(is_decoy(address) for address in addresses)


def test_no_probe_and_no_readout_without_a_signal(prompts):
    report, probe = evaluate_source(ScriptedOrganism("null"), prompts, masked=mask_prompts(2))
    assert probe is None
    assert "readout" not in report and "rows" not in report


def test_shipped_cue_families_share_no_distinguishing_words(prompts):
    report, _ = evaluate_source(ScriptedOrganism("null"), prompts)
    assert report["confirmation"]["lexical_transfer_auroc"] == 0.5
    assert lexical_features(prompts).shape[:2] == (len(prompts), 1)


def test_leaked_vocabulary_is_reported_as_confounded(prompts):
    # A contrast set whose families share a telltale word lets a words-only source
    # transfer.  The lexical baseline transfers too, so the verdict is a fault in
    # the instrument, not a signal.
    leaked = [
        replace(p, user="zzalpha zzbeta zzgamma zzdelta " + p.user)
        if p.family in POSITIVE_FAMILIES and p.label == 1
        else p
        for p in prompts
    ]
    report, probe = evaluate_source(ScriptedOrganism("lexical"), leaked)
    assert report["confirmation"]["lexical_transfer_auroc"] == 1.0
    assert report["verdict"] == "confounded"
    assert probe is None


def test_mixed_transfer_evidence_is_unresolved_not_a_signal_or_a_negative(prompts):
    # Two held-out harness blocks point the wrong way: pooled transfer still clears
    # its threshold, block consistency does not.
    class Inconsistent(ScriptedOrganism):
        def capture(self, batch):
            return super().capture(
                [replace(p, label=1 - p.label) if p.block in (("harness", 4), ("harness", 5)) else p for p in batch]
            )

    report, probe = evaluate_source(Inconsistent("aware"), prompts)
    assert report["confirmation"]["positive_blocks"] == 10
    assert report["gates"]["transfers_across_cue_families"] and not report["gates"]["block_consistent"]
    assert report["verdict"] == "unresolved" and probe is None


def test_too_few_blocks_is_insufficient_not_negative(prompts):
    few = [p for p in prompts if p.form < 6]  # two confirmation forms per family
    report, probe = evaluate_source(ScriptedOrganism("aware"), few)
    assert report["verdict"] == "insufficient" and probe is None
    none = [p for p in prompts if p.form < 4]
    assert evaluate_source(ScriptedOrganism("aware"), none)[0]["verdict"] == "insufficient"


def test_incomplete_pairs_are_rejected(prompts):
    with pytest.raises(ValueError, match="incomplete matched pairs"):
        evaluate_source(ScriptedOrganism("aware"), prompts[1:])


def test_policy_and_auroc_validation():
    assert auroc([0.9, 0.8, 0.1], [1, 1, 0]) == 1.0
    assert auroc([0.5, 0.5], [1, 0]) == 0.5
    with pytest.raises(ValueError):
        auroc([0.1, 0.2], [1, 1])
    with pytest.raises(ValueError):
        ProbePolicy(min_transfer_auroc=1.5)
    with pytest.raises(ValueError):
        ScriptedOrganism("oracle")


def test_contrast_set_and_verdict_are_stable_across_hash_seeds(prompts):
    script = (
        "from spiral_ln.rtg.awareness import *;"
        "p = build_contrast_set(4); r, _ = evaluate_source(ScriptedOrganism('aware'), p);"
        "print(contrast_hash(p), r['verdict'], r['selected_layer'], repr(r['confirmation']['transfer_auroc']))"
    )
    outputs = []
    for hash_seed in ("1", "2"):
        env = {**os.environ, "PYTHONHASHSEED": hash_seed, "PYTHONPATH": str(Path(spiral_ln.__file__).parents[1])}
        outputs.append(subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, check=True).stdout)
    assert outputs[0] == outputs[1]
    assert outputs[0].split()[0] == contrast_hash(prompts)


def test_campaign_writes_receipted_reproducible_artifacts(tmp_path):
    summary = rtg_awareness_eval.run_campaign(tmp_path / "a", CONFIG)
    assert all(summary["scripted_acceptance"].values())
    assert summary["model_sources"] == {}
    receipt = json.loads((tmp_path / "a" / "witness_receipt.json").read_text(encoding="utf-8"))
    for name, expected in receipt["artifacts"].items():
        assert hashlib.sha256((tmp_path / "a" / name).read_bytes()).hexdigest() == expected
    assert (tmp_path / "a" / "figures" / "layer_profile.png").stat().st_size > 0
    rtg_awareness_eval.run_campaign(tmp_path / "b", CONFIG)
    assert (tmp_path / "a" / "summary.json").read_bytes() == (tmp_path / "b" / "summary.json").read_bytes()
    assert (tmp_path / "a" / "rows.csv").read_bytes() == (tmp_path / "b" / "rows.csv").read_bytes()


def test_llama_source_reads_one_state_per_prompt_and_drops_the_sentinel(monkeypatch, prompts):
    calls = []

    def fake_run(args, **kwargs):
        texts = Path(args[args.index("-f") + 1]).read_bytes().decode("utf-8").split(args[args.index("--embd-separator") + 1])
        calls.append(texts)
        data = [{"index": i, "embedding": [float(len(text)), float(i)]} for i, text in enumerate(texts)]
        return subprocess.CompletedProcess(args, 0, json.dumps({"data": data[::-1]}).encode(), b"")

    monkeypatch.setattr(rtg_awareness_eval.subprocess, "run", fake_run)
    source = rtg_awareness_eval.LlamaEmbeddingSource("llama-embedding", "model.gguf", chunk=5)
    acts = source.capture(prompts[:12])
    assert acts.shape == (12, 1, 2)
    assert [len(texts) for texts in calls] == [6, 6, 3]  # each call carries one sentinel
    assert all(texts[-1] == "x" for texts in calls)
    first = rtg_awareness_eval.chatml(prompts[0])
    assert first.endswith("<|im_start|>assistant\n") and prompts[0].user in first
    assert acts[0, 0, 0] == len(first)
    assert np.array_equal(acts[:, 0, 1], [0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1])
