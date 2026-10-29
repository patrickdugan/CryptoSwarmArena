import json
from pathlib import Path

from spiral_ln import staged_hacks
from spiral_ln.feral_custody import RED_OBJECTIVES, STRATEGIES
from spiral_ln.software_surface import SoftwareCatalog

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "configs" / "crypto_hack_corpus.json"
CATALOG = ROOT / "configs" / "software_catalog.json"


def _summary(tmp_path):
    return staged_hacks.run(CORPUS, CATALOG, tmp_path, seed=1)


def test_stage_mappings_are_valid():
    corpus = staged_hacks.load_corpus(CORPUS)
    for h in corpus["hacks"]:
        stage = h["stage"]
        if stage["family"] == "feral_custody":
            assert stage["strategy"] in STRATEGIES and stage["objective"] in RED_OBJECTIVES
        elif stage["family"] == "swarm":
            assert "posture" in stage and "hive_master" in stage
        else:
            assert stage["family"] == "none" and "reason" in stage


def test_every_stageable_hack_runs_and_accounts(tmp_path):
    summary = _summary(tmp_path)
    assert summary["staged_count"] == 15          # 5 technical cases are deliberate non-goals
    assert summary["accounting_all_ok"] is True
    assert summary["safety_boundary"]["synthetic_only"] is True
    assert summary["safety_boundary"]["persuasion_or_recruitment_content"] is False


def test_signer_deception_cluster_exhibits_blind_signing(tmp_path):
    summary = _summary(tmp_path)
    by_id = {s["id"]: s for s in summary["stagings"]}
    for hid in ("bybit", "wazirx", "radiant", "bitpay", "dmm", "ledger_connectkit"):
        s = by_id[hid]
        assert s["objective"] == "deceived_signing"
        assert s["result"]["deceived_signatures"] > 0 and s["mechanism_exhibited"]
    # bybit/wazirx/radiant are multisig -> threshold / multisig is NOT immune to the spoof
    assert by_id["bybit"]["strategy"] == "threshold_signing"


def test_implant_channel_stages_credential_compromise(tmp_path):
    summary = _summary(tmp_path)
    by_id = {s["id"]: s for s in summary["stagings"]}
    assert by_id["mixin"]["result"]["extraction_events"] >= 1   # remote supply_chain implant


def test_technical_cases_are_not_staged(tmp_path):
    summary = _summary(tmp_path)
    for s in summary["stagings"]:
        if s["primary_mechanism"] == "technical_exploitation":
            assert s["family"] == "none" and s.get("staged") is False


def test_staging_is_deterministic(tmp_path):
    a = staged_hacks.run(CORPUS, CATALOG, tmp_path / "a", seed=1)
    b = staged_hacks.run(CORPUS, CATALOG, tmp_path / "b", seed=1)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# -- multi-stage kill chains -------------------------------------------------


def _catalog():
    return SoftwareCatalog.load(CATALOG)


def test_kill_chains_run_end_to_end(tmp_path):
    summary = _summary(tmp_path)
    assert summary["chain_count"] == 9                       # the multi-stage cases
    assert summary["chain_success_count"] == 9               # all compose end-to-end at seed 1
    for c in summary["chains"]:
        assert c["foothold"] is True
        # every chain starts with the swarm foothold and ends on a simulated stage
        assert c["stages"][0]["family"] == "swarm"


def test_terminal_blind_sign_is_causally_gated_by_the_foothold():
    corpus = staged_hacks.load_corpus(CORPUS)
    catalog = _catalog()
    bybit = next(h for h in corpus["hacks"] if h["id"] == "bybit")
    on = staged_hacks.stage_chain(bybit, catalog, seed=1)
    off = staged_hacks.stage_chain(bybit, catalog, seed=1, foothold_override=False)

    def _signer(chain):
        return next(s for s in chain["stages"] if s["mechanism"] == "signer_manipulation")

    assert _signer(on)["deceived_signatures"] > 0 and on["chain_success"] is True
    # no upstream compromise -> spoof_capability 0 -> no blind-sign -> chain fails
    assert _signer(off)["deceived_signatures"] == 0 and off["chain_success"] is False
    assert _signer(off)["spoof_capability"] == 0.0


def test_a_chain_without_a_human_entry_establishes_its_own_foothold():
    # guard: a direct-key-theft entry (no human_deception first) must not be a false
    # no-drain negative -- the credential entry establishes the foothold itself.
    record = {
        "id": "synthetic", "name": "synthetic", "primary_mechanism": "signer_manipulation",
        "surface": "ui_confusion", "usd_millions": 1.0,
        "mechanism_chain": ["credential_compromise", "signer_manipulation"],
        "stage": {"family": "feral_custody", "strategy": "ignorant_multisig",
                  "objective": "deceived_signing", "host_software": ["example-wallet"]},
    }
    result = staged_hacks.stage_chain(record, _catalog(), seed=1)
    credential = next(s for s in result["stages"] if s["mechanism"] == "credential_compromise")
    assert credential["is_entry"] is True
    assert credential["exhibited"] is True and result["foothold"] is True
