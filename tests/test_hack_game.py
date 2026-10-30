"""Heist Desk exporter: deterministic, well-formed, and consistent with the staged-chain sim."""

import importlib.util
import json
from pathlib import Path

import pytest

from spiral_ln import hack_game
from spiral_ln.hack_controls import CONTROLS

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "configs" / "crypto_hack_corpus.json"
CATALOG = REPO / "configs" / "software_catalog.json"
CONTENT = REPO / "configs" / "heist_content.json"
PURE_TECHNICAL = {"polynetwork", "wormhole", "nomad", "euler", "cetus"}
ALL_ON = "+".join(CONTROLS)


@pytest.fixture(scope="module")
def built():
    return hack_game.build_scenarios(CORPUS, CATALOG, CONTENT)


@pytest.fixture(scope="module")
def by_id(built):
    return {s["id"]: s for s in built["scenarios"]}


def _playable(built):
    return [s for s in built["scenarios"] if s["playable"]]


def test_deterministic(built):
    again = hack_game.build_scenarios(CORPUS, CATALOG, CONTENT)
    assert hack_game.dumps(built) == hack_game.dumps(again)


def test_shape_and_non_playable(built):
    assert built["schema"] == "heist-desk/1"
    assert built["seeds"] == list(range(1, 9))
    assert built["control_ids"] == list(CONTROLS)
    assert len(built["scenarios"]) == 20
    assert {s["id"] for s in built["scenarios"] if not s["playable"]} == PURE_TECHNICAL
    for s in built["scenarios"]:
        assert isinstance(s["year"], int) and str(s["year"]) == s["date"][:4]
        if not s["playable"]:
            assert "outcomes" not in s and s["reason"].startswith("Pure code exploits")
        else:
            assert "reason" not in s
    assert built["summary"]["playable"] == 15 and built["summary"]["history_only"] == 5


def test_outcomes_wellformed(built):
    for s in _playable(built):
        assert len(s["outcomes"]) == 8
        assert "" in s["outcomes"] and ALL_ON in s["outcomes"]
        for key, out in s["outcomes"].items():
            parts = key.split("+") if key else []
            assert [c for c in CONTROLS if c in parts] == parts
            assert len(out["runs"]) == 8
            assert [r["seed"] for r in out["runs"]] == list(range(1, 9))
            rate = sum(r["success"] for r in out["runs"]) / 8
            assert out["success_rate"] == round(rate, 3)
            for run in out["runs"]:
                st = run["stages"]
                assert len(st) == len(s["chain"])
                assert set(st) <= {"landed", "blocked", "abstract", "not_reached", "bypassed"}
                if "blocked" in st:
                    first = st.index("blocked")
                    assert all(x == "not_reached" for x in st[first + 1:])
                    assert "blocked" not in st[first + 1:]
                assert "not_reached" not in st[: st.index("blocked")] if "blocked" in st else "not_reached" not in st
                assert run["success"] == ("blocked" not in st)
                if run["success"]:
                    assert "not_reached" not in st
                else:
                    assert "bypassed" not in st
                for mech, res in zip(s["chain"], st):
                    if res == "abstract":
                        assert mech == "technical_exploitation"


def test_bitpay_device_patch_bypasses_implant(by_id):
    out = by_id["bitpay"]["outcomes"]["device_integrity_patch"]
    assert out["success_rate"] == 1.0
    assert all(r["stages"] == ["landed", "bypassed", "landed"] for r in out["runs"])


def test_baseline_always_succeeds(built):
    for s in _playable(built):
        assert s["outcomes"][""]["success_rate"] == 1.0


def test_spot_checks(by_id):
    ronin = by_id["ronin"]["outcomes"]
    assert ronin["phishing_resistant_entry"]["success_rate"] == 0
    assert ronin["clear_signing"]["success_rate"] == 1
    assert ronin["device_integrity_patch"]["success_rate"] == 0
    harmony = by_id["harmony"]["outcomes"]
    stoppers = [k for k in CONTROLS if harmony[k]["success_rate"] < 1.0]
    assert stoppers == ["device_integrity_patch"]
    mtgox = by_id["mtgox"]["outcomes"]
    assert all(o["success_rate"] == 1.0 for o in mtgox.values())


def test_summary(built):
    s = built["summary"]
    assert "mtgox" in s["unstoppable_by_any_single_control"]
    assert "ronin" not in s["unstoppable_by_any_single_control"]
    total = sum(x["usd_millions"] for x in _playable(built))
    assert s["total_usd_millions_playable"] == round(total, 2)


def test_content_passthrough(built):
    content = json.loads(CONTENT.read_text(encoding="utf-8"))
    assert built["content"] == content
    assert len(built["content"]["probes"]) == 8
    assert len(built["content"]["controls"]) == 3


def _build_play():
    spec = importlib.util.spec_from_file_location("build_play", REPO / "ui" / "play" / "build_play.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_play_inlines_and_rejects_script_close(built, tmp_path):
    template = tmp_path / "t.html"
    template.write_text('<html><script id="scenarios-data" type="application/json">__SCENARIOS_JSON__</script></html>',
                        encoding="utf-8")
    scen = tmp_path / "s.json"
    scen.write_text(hack_game.dumps(built), encoding="utf-8")
    out = tmp_path / "index.html"
    mod = _build_play()
    assert mod.main(["--template", str(template), "--scenarios", str(scen), "--out", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    start = html.index('type="application/json">') + len('type="application/json">')
    payload = json.loads(html[start:html.index("</script>", start)])
    assert payload == built
    assert "__SCENARIOS_JSON__" not in html

    bad = dict(built, content=dict(built["content"], description="x </SCRIPT> y"))
    scen.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        mod.main(["--template", str(template), "--scenarios", str(scen), "--out", str(out)])


# --- content and page checks (Heist Desk) -----------------------------------------------

def test_content_matches_the_game():
    from spiral_ln.custody_wars.content import SEATS
    from spiral_ln.hack_controls import CONTROLS as SIM_CONTROLS
    content = json.loads((REPO / "configs/heist_content.json").read_text(encoding="utf-8"))
    corpus = json.loads((REPO / "configs/crypto_hack_corpus.json").read_text(encoding="utf-8"))
    assert [c["id"] for c in content["controls"]] == list(SIM_CONTROLS)
    assert set(content["mechanisms"]) == set(corpus["mechanisms"])
    for p in content["probes"]:
        assert p["to"] in SEATS and p["to"] != "HIVE"            # probes target defender seats
        assert 0 < len(p["message"]) <= 600                       # the message schema's maxLength
        assert set(p["mechanisms"]) <= set(corpus["mechanisms"])
    tut = next(h for h in corpus["hacks"] if h["id"] == content["tutorial"]["scenario"])
    assert any(m != "technical_exploitation" for m in tut["mechanism_chain"])


def test_real_template_builds(tmp_path):
    out = tmp_path / "index.html"
    rc = _build_play().main(["--template", str(REPO / "ui/play/index.template.html"), "--scenarios", str(REPO / "ui/play/scenarios.json"), "--out", str(out)])
    html = out.read_text(encoding="utf-8")
    assert rc == 0 and "__SCENARIOS_JSON__" not in html and '"schema":"heist-desk/1"' in html
