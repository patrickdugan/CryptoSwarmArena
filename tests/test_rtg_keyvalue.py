import json
import re
from pathlib import Path

import numpy as np
import pytest

from spiral_ln import rtg_keyvalue_eval
from spiral_ln.rtg.awareness import ProbePolicy, contrast_hash
from spiral_ln.rtg.keyvalue import (
    BASE58,
    CONCEPTS,
    ITEMS,
    MASKS,
    NOTICE_KINDS,
    NOTICES,
    SCRIPTED_BINDING,
    ScriptedBinder,
    analyze,
    contrast_prompts,
    decoy_key,
    decoy_txid,
    is_decoy_key,
    target_prompts,
)

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "rtg_keyvalue.json"


@pytest.fixture(scope="module")
def prompts():
    return contrast_prompts(4) + target_prompts(8)


def _report(kind, prompts, seed=0):
    binder = ScriptedBinder(kind, seed)
    return analyze(binder.name, binder.capture(prompts), prompts)


def test_every_key_like_string_is_an_invalid_decoy():
    # Canary C1: nothing here can decode to key material on any chain.
    for mask in MASKS:
        for seed in range(16):
            key = decoy_key("treasury", mask, seed)
            assert is_decoy_key(key) and len(key) == 52
            assert key == decoy_key("treasury", mask, seed)
    assert decoy_key("treasury", "mainnet", 1)[0] == "K" and decoy_key("treasury", "testnet", 1)[0] == "c"
    assert not is_decoy_key(BASE58)
    txid = decoy_txid("treasury", 3)
    assert len(txid) == 64
    with pytest.raises(ValueError):
        int(txid, 16)


def test_target_design_is_fully_crossed_and_notices_differ_only_in_one_line():
    targets = target_prompts(8)
    assert len(targets) == 8 * len(MASKS) * len(ITEMS) * len(NOTICE_KINDS) * len(NOTICES)
    cells = {}
    for prompt in targets:
        cells.setdefault((prompt.condition.rsplit("/", 1)[0], prompt.state, prompt.form), {})[prompt.condition.rsplit("/", 1)[1]] = prompt
    for (_, _, form), members in cells.items():
        told, placebo = members["disclosed"].user.split("\n"), members["placebo"].user.split("\n")
        assert (told[-2], placebo[-2]) == NOTICES[form]
        assert told[:-2] + told[-1:] == placebo[:-2] + placebo[-1:]
    keyed = [p for p in targets if "/key/" in p.condition]
    assert all(any(is_decoy_key(word) and len(word) == 52 for word in p.user.split()) for p in keyed)


def test_contrast_cues_never_mention_keys_networks_or_the_disclosure():
    # The probes must not be fit on what they are later read on.
    banned = {"key", "keys", "mainnet", "testnet", "network", "chain", "fake"}
    for cues, families in CONCEPTS.values():
        for family in families:
            for pair in cues[family]:
                for line in pair:
                    assert not banned & set(re.findall(r"[a-z]+", line.lower())), line


def test_scripted_binders_reproduce_planted_geometry_and_binding(prompts):
    for kind, (lift, interaction) in SCRIPTED_BINDING.items():
        report = _report(kind, prompts)
        assert {c: v["verdict"] for c, v in report["concepts"].items()} == {c: f"{c}_signal" for c in CONCEPTS}
        assert abs(report["topology"][-1]["cosine"]["eval~value"] + 0.4) < 0.15
        value = report["targets"]["value"]["contrasts"]
        assert abs(value["key_lift@mainnet"]["mean"] - lift) < 0.25
        assert abs(value["disclosure_on_key_lift@mainnet"]["mean"] - interaction) < 0.2
        # Told that an already-testnet network is fake: nothing left to update.
        assert abs(value["disclosure_on_key_lift@testnet"]["mean"]) < 0.2
        assert abs(report["targets"]["reward"]["contrasts"]["disclosure_on_key_lift@mainnet"]["mean"]) < 0.2


def test_bound_binder_is_told_apart_from_unbound_only_by_the_interaction(prompts):
    bound = _report("bound", prompts)["targets"]["value"]["contrasts"]
    unbound = _report("unbound", prompts)["targets"]["value"]["contrasts"]
    # Disclosure lowers the value index of an inert turn equally in both, because
    # the planted eval and value directions are not orthogonal.
    assert abs(bound["disclosure_on_inert@mainnet"]["mean"] - unbound["disclosure_on_inert@mainnet"]["mean"]) < 0.05
    assert bound["disclosure_on_inert@mainnet"]["mean"] < -0.2
    assert bound["disclosure_on_key_lift@mainnet"]["negative_states"] == 8
    assert bound["disclosure_on_key_lift@mainnet"]["two_sided_sign_p_value"] < 0.01
    assert unbound["disclosure_on_key_lift@mainnet"]["two_sided_sign_p_value"] > 0.05


def test_no_readout_for_a_concept_without_a_signal(prompts):
    report = _report("null", prompts)
    assert all(v["verdict"] == "no_signal" for v in report["concepts"].values())
    assert report["targets"] == {} and report["rows"] == []


def test_a_layer_with_no_direction_reports_no_contrast_instead_of_nan(prompts):
    # Layer 0 of a real model is the embedding of the last token, identical for every prompt.
    acts = ScriptedBinder("bound").capture(prompts)
    acts[:, 0, :] = 1.0
    report = analyze("flat-first-layer", acts, prompts)
    assert report["topology"][0]["contrasts"] == {"eval": None, "value": None, "reward": None}
    assert report["topology"][-1]["contrasts"]["value"] is not None
    json.dumps(report, allow_nan=False)


def test_analysis_rejects_misaligned_activations(prompts):
    with pytest.raises(ValueError, match="expected"):
        analyze("x", np.zeros((3, 2, 4)), prompts, ProbePolicy())


def test_saved_activations_are_refused_for_other_prompts(tmp_path, prompts):
    binder = ScriptedBinder("bound")
    exported = tmp_path / "prompts.json"
    digest = rtg_keyvalue_eval.export_prompts(exported, prompts)
    texts = json.loads(exported.read_text(encoding="utf-8"))["texts"]
    assert digest == contrast_hash(prompts) and len(texts) == len(prompts)
    assert texts[0].endswith("<|im_start|>assistant\n")

    meta = {"model": "scripted/bound", "revision": "0" * 40, "quantization": "none", "prompt_sha256": digest}
    np.savez(tmp_path / "acts.npz", acts=binder.capture(prompts).astype(np.float32), meta=json.dumps(meta))
    source = rtg_keyvalue_eval.SavedActivations(str(tmp_path / "acts.npz"))
    assert source.capture(prompts).shape == (len(prompts), binder.layers, binder.dim)
    with pytest.raises(ValueError, match="captured for prompts"):
        source.capture(prompts[:-1])


def test_campaign_reads_a_model_only_through_a_matching_file(tmp_path, prompts):
    binder = ScriptedBinder("bound", seed=11)
    meta = {"model": "scripted/bound", "revision": "0" * 40, "quantization": "none", "prompt_sha256": contrast_hash(prompts)}
    np.savez(tmp_path / "acts.npz", acts=binder.capture(prompts).astype(np.float32), meta=json.dumps(meta))
    summary = rtg_keyvalue_eval.run_campaign(tmp_path / "out", CONFIG, tmp_path / "acts.npz")
    assert all(summary["scripted_acceptance"].values())
    (name, report), = summary["model_sources"].items()
    assert name == "saved:scripted/bound@000000000000:none"
    assert report["targets"]["value"]["contrasts"]["disclosure_on_key_lift@mainnet"]["mean"] < -0.7
    receipt = json.loads((tmp_path / "out" / "witness_receipt.json").read_text(encoding="utf-8"))
    assert receipt["capture"]["prompt_sha256"] == receipt["prompt_sha256"]
    assert (tmp_path / "out" / "figures" / "topology.png").stat().st_size > 0
