"""Causal synthetic social-vector campaign feeding five BitVM ceremony hosts.

The existing swarm_compromise environment resolves abstract attempts against
scripted host susceptibilities and defensive postures. The only output allowed
to grant simulated signing control is the environment's *landed compromise*
state, never an attack declaration, detected alert, or exfiltration counter.

This module contains no payloads, phishing messages, malware, keys, network
attacks, live model calls, or external transaction handling.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from . import swarm_compromise as sc

SCHEMA = "csa.bitvm-social-setup.v1"
DOMAIN = "csa/bitvm-social-setup/v1"
HOST_NODE_IDS = ("N00", "N01", "N02", "N03", "N04")
SWARM_SOURCE_GIT_BLOB = "c910f74f95fedf6bb00291a870a24e7d767ac097"
VECTOR_RECIPES = {
    "social": ("spear_social",),
    "recruitment": ("cult_recruitment",),
    "proximity": ("phone_bridge",),
    "passive-leak": ("emanation_tap",),
    "mixed": ("spear_social", "cult_recruitment", "phone_bridge"),
}
POSTURES = sc.POSTURES
MASTERS = tuple(sc.HIVE_MASTER_BY_NAME)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SocialSetupConfig:
    """Evaluator-selected, finite simulation parameters, never agent inputs."""

    posture: str = "baseline_open"
    recipe: str = "mixed"
    hive_master: str = "insider_cultivator"
    rounds: int = 24

    def __post_init__(self) -> None:
        if self.posture not in POSTURES:
            raise ValueError("unrecognized social posture")
        if self.recipe not in VECTOR_RECIPES:
            raise ValueError("unrecognized social vector recipe")
        if self.hive_master not in sc.HIVE_MASTER_BY_NAME:
            raise ValueError("unrecognized hive-master profile")
        if type(self.rounds) is not int or not 1 <= self.rounds <= 60:
            raise ValueError("social rounds must be an integer from 1 to 60")


class HostFocusedReferencePolicy:
    """Non-adaptive reference schedule over the public test-host roster.

    The policy only visits hosts listed in its imperfect-information view.
    Its vector schedule is fixed before the campaign, independent of outcome,
    detector coverage or hidden posture. Already compromised hosts are skipped
    to avoid repeated identical attempts against an already landed foothold.
    """

    def __init__(self, recipe: str) -> None:
        self.vectors = VECTOR_RECIPES[recipe]

    def act(self, view: Mapping[str, object]) -> list[sc.CompromiseAction]:
        candidates = [
            node for node in HOST_NODE_IDS
            if node in view["known_nodes"]
            and node not in view["own_compromised"]
            and node not in view["burned_nodes"]
        ]
        if not candidates:
            return []
        rnd = int(view["round"])
        # Round-robin target order. The vector rotates through the fixed recipe.
        ordered = candidates[rnd % len(candidates):] + candidates[:rnd % len(candidates)]
        limit = min(3, int(view["max_actions"]))
        return [
            sc.CompromiseAction(
                vector=self.vectors[(rnd + i) % len(self.vectors)],
                target=node, intensity=1,
            )
            for i, node in enumerate(ordered[:limit])
        ]


def check_source_pin() -> None:
    source = Path(sc.__file__).read_bytes()
    actual = hashlib.sha1(b"blob " + str(len(source)).encode("ascii") + b"\0" + source).hexdigest()
    if actual != SWARM_SOURCE_GIT_BLOB:
        raise RuntimeError("swarm_compromise source changed: update pin and rerun comparison")


def social_episode(seed: int, config: SocialSetupConfig) -> dict[str, Any]:
    """Derive actual compromised hosts from a seeded social simulation."""
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("social seed must be a uint32")
    if not isinstance(config, SocialSetupConfig):
        raise ValueError("social config must be an evaluator-owned SocialSetupConfig")
    check_source_pin()

    settings = sc.SwarmCompromiseConfig(
        population_size=12, rounds=config.rounds, communities=3,
        intra_community_link=0.45, inter_community_link=0.07,
        sensitive_fraction=5 / 12, honeypot_fraction=2 / 12,
        defender_count=2, defender_domain_fraction=0.7,
        max_actions_per_round=3, monitor_sample_rate=0.6,
        recruitment_contagion=0.25,
    )
    master = sc.HIVE_MASTER_BY_NAME[config.hive_master]
    env = sc.SwarmCompromiseEnv(
        posture=config.posture, hive_master=master, seed=seed, config=settings
    )
    policy = HostFocusedReferencePolicy(config.recipe)
    # Keep actual policy actions: an attempted compromise is not a landing.
    attempts: list[dict[str, Any]] = []
    for rnd in range(config.rounds):
        actions = policy.act(env.hive_master_view())
        attempts.append({"round": rnd, "actions": [asdict(action) for action in actions]})
        env.step(actions)

    result = env.result()
    if not result.accounting_ok:
        raise AssertionError("swarm-compromise environment failed its accounting")
    landed_host_indices = [
        i for i, node in enumerate(HOST_NODE_IDS) if node in env.compromised
    ]
    # A permitted, authorized blue-team exercise may deliberately simulate
    # access to hosts, but it confers no malicious authority in this arena.
    adversarial = master.truth_class == "adversary"
    compromised = landed_host_indices if adversarial else []
    observed: list[dict[str, Any]] = [
        {"round": signal.round_index, "host": HOST_NODE_IDS.index(signal.target),
         "vector": signal.vector, "flagged": signal.flagged}
        for signal in env.observer_trace()
        if signal.target in HOST_NODE_IDS
    ]
    event_rows = [asdict(event) for event in env.events]
    landed_events = [
        event for event in event_rows
        if event["target"] in HOST_NODE_IDS
        and event["landed"] and not event["honeypot_hit"]
        and sc.VECTORS[event["vector"]].compromises
        and (not env.postures[event["target"]].airgapped
             or sc.VECTORS[event["vector"]].bridges_airgap)
    ]
    body = {
        "schema": SCHEMA,
        "evidence_level": "synthetic-model",
        "source_git_blob": SWARM_SOURCE_GIT_BLOB,
        "seed": seed,
        "config": asdict(config),
        "master_truth_class": master.truth_class,
        "host_nodes": list(HOST_NODE_IDS),
        "landed_host_indices": landed_host_indices,
        "adversarial_compromised_hosts": compromised,
        "monitor_signals": observed,
        "attempts": attempts,
        "events": event_rows,
        "landed_host_events": landed_events,
        "result": result.to_dict(),
        "scope": "synthetic psychology/software-surface probabilities; no executable intrusion or physical attack",
    }
    return {**body, "evidence_hash": digest({"domain": DOMAIN + "/receipt", "body": body})}


def replay_social_episode(receipt: dict[str, Any]) -> dict[str, Any]:
    """Independently rebuild all event, compromised-host and monitoring fields."""
    if type(receipt) is not dict or type(receipt.get("config")) is not dict:
        raise ValueError("invalid social receipt")
    expected = social_episode(receipt.get("seed"), SocialSetupConfig(**receipt["config"]))
    if expected != receipt:
        raise ValueError("social episode differs from evaluator replay")
    return expected
