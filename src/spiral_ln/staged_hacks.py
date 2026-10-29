"""Stage historical crypto hacks in the sealed NPC/device simulation.

Each case in ``configs/crypto_hack_corpus.json`` carries a ``stage`` mapping to a
sealed sim configuration that reproduces its *primary* attack mechanism on the
NPC + device model: signer manipulation (deceived / coerced signing) and
credential compromise (key extraction / remote implant) run in the feral-custody
family; human deception runs in the swarm-compromise family.  Technical
exploitation is a deliberate non-goal (abstract affordance cost), so those cases
are not staged.

This is a sealed, synthetic, deterministic mapping.  It stages the *mechanism*,
not any operational technique: no real key material, no persuasion content, no
exploit.  The device coupling is via ``software_surface`` advisory residuals
(ui_confusion for spoofed approvals, supply_chain for implants), so patching a
device advisory changes the staged outcome.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from .feral_custody import CustodyAdversary, FeralCustodyEnv, build_custody_config, default_adversary
from .software_surface import SoftwareCatalog
from .swarm_compromise import (
    HIVE_MASTER_BY_NAME,
    ScriptedHiveMaster,
    SwarmCompromiseConfig,
    SwarmCompromiseEnv,
)

_SOCIAL_MASTER = "opportunist_phisher"

_DEFAULT_BUDGET = {"key_extraction": 60_000, "signing_denial": 60_000, "coerced_signing": 40_000, "deceived_signing": 0}

# Which result counter must be positive for the primary mechanism to have manifested.
_EXHIBIT = {
    "deceived_signing": lambda r: r["deceived_signatures"] > 0,
    "key_extraction": lambda r: r["extraction_events"] > 0,
    "coerced_signing": lambda r: r["coerced_signatures"] > 0,
    "signing_denial": lambda r: r["denial_events"] > 0,
}


def load_corpus(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def stage_hack(record: dict, catalog: SoftwareCatalog | None, seed: int = 1) -> dict:
    stage = record["stage"]
    family = stage["family"]
    out = {"id": record["id"], "name": record["name"], "family": family,
           "primary_mechanism": record["primary_mechanism"]}
    if family == "feral_custody":
        objective = stage["objective"]
        overrides = {}
        if "host_software" in stage:
            overrides["host_software"] = tuple(stage["host_software"])
        config = build_custody_config(stage["strategy"], seed=seed, **overrides)
        budget = stage.get("bribery_budget", _DEFAULT_BUDGET.get(objective, 0))
        adversary = default_adversary(objective, budget)
        result = FeralCustodyEnv(config, adversary, seed=seed, catalog=catalog).run().to_dict()
        out.update({
            "strategy": stage["strategy"], "objective": objective,
            "result": result, "accounting_ok": result["accounting_ok"],
            "mechanism_exhibited": _EXHIBIT.get(objective, lambda r: False)(result),
        })
        return out
    if family == "swarm":
        master = HIVE_MASTER_BY_NAME[stage["hive_master"]]
        config = SwarmCompromiseConfig()
        env = SwarmCompromiseEnv(posture=stage["posture"], hive_master=master, seed=seed, config=config)
        policy = ScriptedHiveMaster(master, seed=seed)
        while env.round_index < config.rounds:
            env.step(policy.act(env.hive_master_view()))
        result = env.result()
        out.update({
            "posture": stage["posture"], "hive_master": stage["hive_master"],
            "compromised_count": result.compromised_count,
            "mechanism_exhibited": result.compromised_count > 0,
        })
        return out
    out.update({"staged": False, "reason": stage.get("reason", "not stageable")})
    return out


def stage_all(corpus: dict, catalog: SoftwareCatalog | None, seed: int = 1) -> list[dict]:
    return [stage_hack(h, catalog, seed) for h in corpus["hacks"]]


# ---------------------------------------------------------------------------
# Multi-stage kill chains: compose the mechanisms across families in one episode,
# with the terminal causally gated by whether the upstream foothold landed.
# ---------------------------------------------------------------------------


def _swarm_foothold(seed: int, posture: str = "baseline_open", master_name: str = _SOCIAL_MASTER) -> int:
    """Run the entry social-engineering episode; return how many NPCs were compromised."""
    master = HIVE_MASTER_BY_NAME[master_name]
    config = SwarmCompromiseConfig()
    env = SwarmCompromiseEnv(posture=posture, hive_master=master, seed=seed, config=config)
    policy = ScriptedHiveMaster(master, seed=seed)
    while env.round_index < config.rounds:
        env.step(policy.act(env.hive_master_view()))
    return env.result().compromised_count


def stage_chain(record: dict, catalog: SoftwareCatalog | None, seed: int = 1,
                foothold_override: bool | None = None, diligence_override: float | None = None) -> dict:
    """Walk a case's mechanism_chain as a composed episode.

    Human deception runs in the swarm family and sets the *foothold*.  The
    downstream custody stages are gated by it: the remote implant is enabled only
    with a foothold (`host_software` set), and the deceived-signing adversary's
    `spoof_capability` is zero without one.  Device deception (surface
    ui_confusion/supply_chain, e.g. Bybit's tampered front-end) additionally
    requires the device surface to be tamperable, so patching that advisory breaks
    it; social deception (surface phishing, e.g. BitPay's impersonation email) does
    not depend on a device.  `foothold_override` and `diligence_override` force a
    precondition for counterfactual control sweeps (block the entry; enforce
    clear-signing)."""
    chain = record["mechanism_chain"]
    strat = record["stage"].get("strategy", "ignorant_multisig")
    host_software = record["stage"].get("host_software", ["example-wallet"])
    stages: list[dict] = []
    foothold = bool(foothold_override) if foothold_override is not None else False

    for index, mech in enumerate(chain):
        is_entry = index == 0   # the first link establishes the foothold
        if mech == "human_deception":
            if foothold_override is not None:
                landed, comp = bool(foothold_override), None
            else:
                comp = _swarm_foothold(seed)
                landed = comp > 0
            foothold = foothold or landed
            stages.append({"mechanism": mech, "family": "swarm", "landed": landed,
                           "compromised_count": comp, "forced": foothold_override is not None})
        elif mech == "credential_compromise":
            if is_entry:
                # a direct key theft that is itself the entry establishes the foothold
                # (its own base-extraction path, not foothold-gated)
                cfg = build_custody_config(strat if strat != "none" else "obfuscation", seed=seed, host_software=tuple(host_software))
                res = FeralCustodyEnv(cfg, default_adversary("key_extraction", _DEFAULT_BUDGET["key_extraction"]), seed=seed, catalog=catalog).run().to_dict()
                exhibited = res["extraction_events"] > 0
                foothold = foothold or exhibited
            else:
                # a downstream credential link is the key theft the entry delivered
                # (a remote implant), isolated from any independent base-extraction
                # path so the whole chain stays causally gated by the entry foothold.
                host_sw = tuple(host_software) if foothold else ()
                cfg = build_custody_config("enclave", seed=seed, host_software=host_sw,
                                           side_channel_leak_prob=0.0, operator_shutdown_prob=0.0)
                res = FeralCustodyEnv(cfg, default_adversary("key_extraction", _DEFAULT_BUDGET["key_extraction"]), seed=seed, catalog=catalog).run().to_dict()
                exhibited = res["extraction_events"] > 0   # = foothold-gated implant fired
            stages.append({"mechanism": mech, "family": "feral_custody", "exhibited": exhibited,
                           "is_entry": is_entry, "extraction_events": res["extraction_events"]})
        elif mech == "signer_manipulation":
            master = HIVE_MASTER_BY_NAME[_SOCIAL_MASTER]
            surface = record.get("surface", "")
            if surface in ("ui_confusion", "supply_chain"):   # device deception
                host_sw = tuple(host_software)
                tamperable = catalog is not None and catalog.stack_surface(host_sw, surface) > 0.0
                can_spoof = foothold and tamperable
            else:                                             # social deception (no device)
                host_sw = ()
                can_spoof = foothold
            spoof = master.social_capability if can_spoof else 0.0
            cfg = build_custody_config(strat if strat != "none" else "ignorant_multisig", seed=seed, host_software=host_sw)
            if diligence_override is not None:
                cfg = replace(cfg, personas=tuple(replace(p, signing_diligence=diligence_override) for p in cfg.personas))
            adversary = CustodyAdversary(
                hive_master=master, objective="deceived_signing", bribery_budget=0,
                extraction_capability=max(master.proximity_capability, master.emanation_capability),
                coercion_pressure=0.0, spoof_capability=spoof)
            res = FeralCustodyEnv(cfg, adversary, seed=seed, catalog=catalog).run().to_dict()
            exhibited = res["deceived_signatures"] > 0
            stages.append({"mechanism": mech, "family": "feral_custody", "exhibited": exhibited,
                           "spoof_capability": round(spoof, 3), "surface": surface,
                           "deceived_signatures": res["deceived_signatures"]})
        else:  # technical_exploitation -- abstracted non-goal, passes through
            stages.append({"mechanism": mech, "family": "none", "abstracted": True})

    simulated = [s for s in stages if s.get("family") in ("swarm", "feral_custody")]
    terminal = simulated[-1] if simulated else None
    chain_success = bool(terminal and (terminal.get("exhibited") or terminal.get("landed")))
    return {"id": record["id"], "name": record["name"], "chain": chain, "foothold": bool(foothold),
            "stages": stages, "chain_success": chain_success}


def stage_all_chains(corpus: dict, catalog: SoftwareCatalog | None, seed: int = 1) -> list[dict]:
    return [stage_chain(h, catalog, seed) for h in corpus["hacks"] if len(h["mechanism_chain"]) >= 2]


def run(corpus_path: str | Path, catalog_path: str | Path, output_dir: str | Path, seed: int = 1) -> dict:
    corpus = load_corpus(corpus_path)
    catalog = SoftwareCatalog.load(catalog_path)
    staged = stage_all(corpus, catalog, seed)
    chains = stage_all_chains(corpus, catalog, seed)
    summary = {
        "schema_version": "1.0",
        "seed": seed,
        "staged_count": sum(1 for s in staged if s.get("family") != "none"),
        "exhibited_count": sum(1 for s in staged if s.get("mechanism_exhibited")),
        "accounting_all_ok": all(s.get("accounting_ok", True) for s in staged),
        "chain_count": len(chains),
        "chain_success_count": sum(1 for c in chains if c["chain_success"]),
        "safety_boundary": {"synthetic_only": True, "stages_mechanism_not_technique": True,
                            "real_key_material": False, "persuasion_or_recruitment_content": False},
        "stagings": staged,
        "chains": chains,
    }
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "staged_hacks.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="configs/crypto_hack_corpus.json")
    parser.add_argument("--catalog", default="configs/software_catalog.json")
    parser.add_argument("--output", default="output/staged_hacks")
    args = parser.parse_args(argv)
    summary = run(args.corpus, args.catalog, args.output)
    for s in summary["stagings"]:
        if s.get("family") == "none":
            print(f"  {s['id']:18s} [{s['primary_mechanism']}] not staged: {s.get('reason','')}")
        else:
            mark = "yes" if s.get("mechanism_exhibited") else "no"
            print(f"  {s['id']:18s} [{s['primary_mechanism']}] {s['family']} -> exhibited {mark}")
    print(f"staged {summary['staged_count']}, exhibited {summary['exhibited_count']}, accounting_all_ok {summary['accounting_all_ok']}")
    print("-- kill chains (end-to-end) --")
    for c in summary["chains"]:
        steps = " -> ".join(s["mechanism"].split("_")[0] for s in c["stages"])
        print(f"  {c['id']:18s} foothold={str(c['foothold']):5s} success={str(c['chain_success']):5s}  {steps}")
    print(f"chains {summary['chain_count']}, end-to-end success {summary['chain_success_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
