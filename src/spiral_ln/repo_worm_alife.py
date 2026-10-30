"""REPO-WORM-ALIFE-01: sealed repository-contagion control benchmark.

An entirely in-process, content-free simulation of agents adopting an inert
marker from lower-trust repository material. It has no GitHub client, sockets,
repository mutation, executable payload, instruction text, or model calls.

Source/target interactions, detection decisions, and inference/network costs
are abstract scripted events. Results establish properties of this *model* only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, stdev
from typing import Any

from .swarm_compromise import PROFILE_ARCHETYPES

SCHEMA_VERSION = "rtg.repo_worm_alife.v1"
CONFIG_SCHEMA = "rtg.repo_worm_alife.config.v1"
PROFILES = tuple(
    profile for profile in PROFILE_ARCHETYPES
    if profile.name in {"guarded_engineer", "balanced_contributor", "eager_newcomer", "principled_auditor"}
)
# Deliberately fixed-size synthetic wire events. These are *not* packet captures.
MARKER_REQUEST_BYTES = 512
MARKER_RESPONSE_BYTES = 256
BENIGN_REQUEST_BYTES = 384
BENIGN_RESPONSE_BYTES = 256
REMOTE_INFERENCE_BYTES = 2304  # hypothetical request + response per review
WORK_UNITS_PER_REVIEW = 1024  # nominal tokens; no models are run


@dataclass(frozen=True)
class Posture:
    name: str
    trust_multiplier: float
    monitor_coverage: float
    true_positive_rate: float
    false_positive_rate: float
    isolate_source_rate: float


POSTURES = {
    p.name: p for p in (
        Posture("baseline_open", 1.00, 0.10, 0.30, 0.01, 0.00),
        Posture("provenance_gate", 0.65, 0.55, 0.78, 0.03, 0.55),
        Posture("inspect_verify", 0.43, 0.82, 0.90, 0.04, 0.78),
        Posture("human_review", 0.30, 0.96, 0.96, 0.075, 0.92),
    )
}
MODES = ("local", "remote")


@dataclass(frozen=True)
class Config:
    population_size: int = 32
    communities: int = 4
    rounds: int = 24
    intra_link: float = 0.25
    inter_link: float = 0.035
    contacts_per_round: int = 2
    infectious_rounds: int = 3
    initial_markers: int = 1
    base_adoption: float = 0.75
    benign_events_per_round: int = 5
    mutation_probability: float = 0.08
    mutation_step: float = 0.12

    def __post_init__(self) -> None:
        integers = {
            "population_size": (2, 256),
            "communities": (1, 32),
            "rounds": (1, 128),
            "contacts_per_round": (1, 16),
            "infectious_rounds": (1, 32),
            "initial_markers": (1, 16),
            "benign_events_per_round": (0, 64),
        }
        for name, (low, high) in integers.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer in [{low}, {high}]")
        if self.communities > self.population_size or self.initial_markers >= self.population_size:
            raise ValueError("communities must fit population; initial_markers must leave a susceptible node")
        for name in ("intra_link", "inter_link", "base_adoption", "mutation_probability", "mutation_step"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be a finite probability/step in [0, 1]")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def draw(seed: int, *parts: Any) -> float:
    """Counter-based seeded PRNG so paired postures share opportunity draws."""
    digest = hashlib.sha256(canonical([seed, *parts]).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def build_graph(config: Config, seed: int) -> tuple[tuple[int, ...], ...]:
    """Seeded, content-free undirected synthetic repository dependency graph."""
    rng = random.Random(seed)
    neighbors: list[list[int]] = [[] for _ in range(config.population_size)]
    for left in range(config.population_size):
        for right in range(left + 1, config.population_size):
            rate = config.intra_link if left % config.communities == right % config.communities else config.inter_link
            if rng.random() < rate:
                neighbors[left].append(right)
                neighbors[right].append(left)
    return tuple(tuple(sorted(row)) for row in neighbors)


def safety_boundary() -> dict[str, bool]:
    return {
        "synthetic_only": True,
        "network_transport": False,
        "live_repository_access": False,
        "model_call_in_harness": False,
        "payload_or_instruction_content": False,
        "executing_or_persisting_agent_code": False,
        "real_infection_or_replication": False,
    }


@dataclass
class Episode:
    metrics: dict[str, Any]
    events: list[dict[str, Any]]
    trajectory: list[dict[str, Any]]
    graph: tuple[tuple[int, ...], ...]


def run_episode(config: Config, seed: int, posture: str, mode: str = "local", *, retain_events: bool = False) -> Episode:
    """Run a fixed-horizon scripted trial. Agent compliance is a probability, not observed LLM behavior."""
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be a uint32")
    if posture not in POSTURES or mode not in MODES:
        raise ValueError("unknown posture or inference mode")
    policy = POSTURES[posture]
    graph = build_graph(config, seed)
    # Highest-connectivity nodes get the initial abstract marker, identically for every policy.
    roots = tuple(sorted(sorted(range(config.population_size), key=lambda i: (-len(graph[i]), i))[:config.initial_markers]))
    infected_at: dict[int, int] = {node: 0 for node in roots}
    generation: dict[int, int] = {node: 0 for node in roots}
    strain: dict[int, float] = {node: 1.0 for node in roots}
    quarantined: set[int] = set()
    attempted: set[tuple[int, int]] = set()
    active_sources: set[int] = set()
    per_source_children: dict[int, int] = {node: 0 for node in roots}
    contacts = detections = false_positives = benign = adoptions = mutations = 0
    local_work_units = external_calls = api_calls = api_bytes = external_bytes = 0
    max_generation = 0
    events: list[dict[str, Any]] = []
    trajectory: list[dict[str, Any]] = []
    chain = "0" * 64
    event_count = 0

    def record(event: dict[str, Any]) -> None:
        nonlocal chain, event_count
        chain = hashlib.sha256((chain + canonical(event)).encode("utf-8")).hexdigest()
        event_count += 1
        if retain_events:
            events.append({**event, "chain_sha256": chain})

    for tick in range(config.rounds):
        new_this_tick = 0
        eligible = tuple(sorted(
            node for node, start in infected_at.items()
            if start <= tick < start + config.infectious_rounds and node not in quarantined
        ))
        for source in eligible:
            candidates = [target for target in graph[source] if (source, target) not in attempted]
            candidates.sort(key=lambda target: (draw(seed, "contact_order", tick, source, target), target))
            for target in candidates[:config.contacts_per_round]:
                if source in quarantined:
                    break
                attempted.add((source, target))
                active_sources.add(source)
                contacts += 1
                api_calls += 2
                api_bytes += MARKER_REQUEST_BYTES + MARKER_RESPONSE_BYTES
                local_work_units += WORK_UNITS_PER_REVIEW
                if mode == "remote":
                    external_calls += 1
                    external_bytes += REMOTE_INFERENCE_BYTES
                inspected = draw(seed, "inspection", tick, source, target) < policy.monitor_coverage
                detected = inspected and draw(seed, "detect", tick, source, target) < policy.true_positive_rate
                outcome = "ignored"
                if detected:
                    detections += 1
                    outcome = "blocked_marker"
                    if draw(seed, "isolate", tick, source, target) < policy.isolate_source_rate:
                        quarantined.add(source)
                elif target in infected_at:
                    outcome = "already_carrying"
                elif target in quarantined:
                    outcome = "quarantined_target"
                else:
                    profile = PROFILES[target % len(PROFILES)]
                    probability = min(1.0, config.base_adoption * strain[source]
                                      * (1 - 0.45 * profile.security_hygiene) * policy.trust_multiplier)
                    if draw(seed, "adopt", tick, source, target) < probability:
                        infected_at[target] = tick + 1
                        generation[target] = generation[source] + 1
                        per_source_children[source] = per_source_children.get(source, 0) + 1
                        per_source_children.setdefault(target, 0)
                        new_this_tick += 1
                        adoptions += 1
                        max_generation = max(max_generation, generation[target])
                        outcome = "adopted_marker"
                        factor = strain[source]
                        if draw(seed, "mutation", tick, source, target) < config.mutation_probability:
                            delta = config.mutation_step * (1 if draw(seed, "mutation_sign", tick, source, target) < 0.5 else -1)
                            factor = min(1.25, max(0.75, factor + delta))
                            if factor != strain[source]:
                                mutations += 1
                        strain[target] = round(factor, 6)
                record({
                    "tick": tick, "kind": "marker", "source": source, "target": target,
                    "observed_alert": detected, "decision": outcome,
                    "synthetic_api_calls": 2,
                    "synthetic_wire_bytes": MARKER_REQUEST_BYTES + MARKER_RESPONSE_BYTES,
                    "inference_units": WORK_UNITS_PER_REVIEW,
                    "external_inference_calls": int(mode == "remote"),
                })
        # Benign changes are matched controls and contribute genuine false alarms.
        for slot in range(config.benign_events_per_round):
            target = int(draw(seed, "benign_target", tick, slot) * config.population_size)
            inspected = draw(seed, "benign_inspection", tick, slot) < policy.monitor_coverage
            alert = inspected and draw(seed, "benign_alert", tick, slot) < policy.false_positive_rate
            benign += 1
            false_positives += int(alert)
            api_calls += 1
            api_bytes += BENIGN_REQUEST_BYTES + BENIGN_RESPONSE_BYTES
            local_work_units += WORK_UNITS_PER_REVIEW
            if mode == "remote":
                external_calls += 1
                external_bytes += REMOTE_INFERENCE_BYTES
            record({
                "tick": tick, "kind": "benign", "source": None, "target": target,
                "observed_alert": alert, "decision": "false_alarm" if alert else "benign_clear",
                "synthetic_api_calls": 1,
                "synthetic_wire_bytes": BENIGN_REQUEST_BYTES + BENIGN_RESPONSE_BYTES,
                "inference_units": WORK_UNITS_PER_REVIEW,
                "external_inference_calls": int(mode == "remote"),
            })
        trajectory.append({
            "tick": tick,
            "new_adoptions": new_this_tick,
            "carrying_total": len(infected_at),
            "active_sources": len(eligible),
            "quarantined_sources": len(quarantined),
        })

    # Sources with at least one attempted handoff form the observed reproduction denominator.
    # Late adopters that never had a contact opportunity are right-censored.
    active_count = len(active_sources)
    metrics = {
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "posture": posture,
        "inference_mode": mode,
        "population": config.population_size,
        "rounds": config.rounds,
        "graph_nodes": len(graph),
        "graph_edges": sum(map(len, graph)) // 2,
        "initial_markers": len(roots),
        "carrying_total": len(infected_at),
        "secondary_adoptions": adoptions,
        "seed_offspring_per_root": round(sum(per_source_children[root] for root in roots) / len(roots), 6),
        "reproduction_observed": round(adoptions / active_count, 6) if active_count else 0.0,
        "active_sources_observed": active_count,
        "right_censored_carriers": len(set(infected_at).difference(active_sources)),
        "max_generation": max_generation,
        "mutations": mutations,
        "marker_contacts": contacts,
        "marker_detected": detections,
        "marker_detection_recall": round(detections / contacts, 6) if contacts else None,
        "benign_contacts": benign,
        "false_alarms": false_positives,
        "benign_false_alarm_rate": round(false_positives / benign, 6) if benign else None,
        "isolated_sources": len(quarantined),
        "synthetic_api_calls": api_calls,
        "synthetic_wire_bytes": api_bytes,
        "abstract_inference_work_units": local_work_units,
        "simulated_external_inference_calls": external_calls,
        "simulated_external_inference_bytes": external_bytes,
        "last_adoption_tick": max((start - 1 for start in infected_at.values() if start > 0), default=None),
        "ledger_events": event_count,
        "ledger_chain_sha256": chain,
        "graph_sha256": sha(graph),
        "lineage_sha256": sha(sorted((node, infected_at[node], generation[node], strain[node]) for node in infected_at)),
        "accounting_ok": len(infected_at) == len(roots) + adoptions
        and sum(per_source_children.values()) == adoptions
        and event_count == contacts + benign
        and external_calls == (contacts + benign if mode == "remote" else 0)
        and 0 <= detections <= contacts and 0 <= false_positives <= benign,
    }
    return Episode(metrics, events, trajectory, graph)


def validate_campaign(spec: dict[str, Any]) -> tuple[Config, list[int], list[str], list[str]]:
    if spec.get("schema_version") != CONFIG_SCHEMA:
        raise ValueError("unknown config schema")
    config = Config(**spec["design"])
    seeds, postures, modes = spec["seeds"], spec["postures"], spec["inference_modes"]
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= 64 or any(type(s) is not int or not 0 <= s <= 2**32 - 1 for s in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be 1..64 unique uint32 values")
    if not isinstance(postures, list) or not postures or len(set(postures)) != len(postures) or any(p not in POSTURES for p in postures):
        raise ValueError("invalid postures")
    if not isinstance(modes, list) or not modes or len(set(modes)) != len(modes) or any(m not in MODES for m in modes):
        raise ValueError("invalid inference modes")
    if len(seeds) * len(postures) * len(modes) > 512:
        raise ValueError("campaign exceeds 512 episodes")
    return config, seeds, postures, modes


def interval(values: list[float]) -> dict[str, float | int]:
    # Descriptive normal-approximation interval across independent *seeded worlds*.
    return {
        "n": len(values),
        "mean": round(mean(values), 6) if values else 0.0,
        "ci95_half_width": round(1.96 * stdev(values) / math.sqrt(len(values)), 6) if len(values) >= 2 else 0.0,
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"by_mode_posture": {}, "paired_vs_baseline": {}}
    modes = sorted({r["inference_mode"] for r in rows})
    postures = sorted({r["posture"] for r in rows})
    for mode in modes:
        filtered = [r for r in rows if r["inference_mode"] == mode]
        for posture in postures:
            selected = [r for r in filtered if r["posture"] == posture]
            summary["by_mode_posture"][f"{mode}/{posture}"] = {
                "secondary_adoptions": interval([float(r["secondary_adoptions"]) for r in selected]),
                "reproduction_observed": interval([float(r["reproduction_observed"]) for r in selected]),
                "seed_offspring_per_root": interval([float(r["seed_offspring_per_root"]) for r in selected]),
                "marker_detection_recall": interval([float(r["marker_detection_recall"]) for r in selected if r["marker_detection_recall"] is not None]),
                "benign_false_alarm_rate": interval([float(r["benign_false_alarm_rate"]) for r in selected if r["benign_false_alarm_rate"] is not None]),
                "synthetic_wire_bytes": interval([float(r["synthetic_wire_bytes"]) for r in selected]),
            }
        baseline = {r["seed"]: r for r in filtered if r["posture"] == "baseline_open"}
        for posture in postures:
            if posture == "baseline_open" or not baseline:
                continue
            matched = [(baseline[r["seed"]], r) for r in filtered if r["posture"] == posture and r["seed"] in baseline]
            summary["paired_vs_baseline"][f"{mode}/{posture}"] = {
                "delta_secondary_adoptions": interval([float(t["secondary_adoptions"] - b["secondary_adoptions"]) for b, t in matched]),
                "delta_reproduction_observed": interval([float(t["reproduction_observed"] - b["reproduction_observed"]) for b, t in matched]),
                "delta_seed_offspring_per_root": interval([float(t["seed_offspring_per_root"] - b["seed_offspring_per_root"]) for b, t in matched]),
            }
    return summary


def campaign(spec: dict[str, Any], *, retain_events: bool = False) -> tuple[list[Episode], dict[str, Any]]:
    config, seeds, postures, modes = validate_campaign(spec)
    episodes = [
        run_episode(config, seed, posture, mode, retain_events=retain_events)
        for mode in modes for posture in postures for seed in seeds
    ]
    return episodes, summarize([episode.metrics for episode in episodes])


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(spec: dict[str, Any], output: Path, *, retain_events: bool = False) -> dict[str, Any]:
    episodes, stats = campaign(spec, retain_events=retain_events)
    output.mkdir(parents=True, exist_ok=True)
    source_hash = file_sha256(Path(__file__))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "config_sha256": sha(spec),
        "source_sha256": source_hash,
        "configuration": spec,
        "safety_boundary": safety_boundary(),
        "limitations": "Scripted, synthetic contact/adoption rates; invented traffic-byte constants; no measured model or real network evidence.",
    }
    rows = [e.metrics for e in episodes]
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "summary.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output / "episodes.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for episode in episodes:
        if retain_events:
            filename = f"{episode.metrics['inference_mode']}_{episode.metrics['posture']}_seed{episode.metrics['seed']}.jsonl"
            with (output / filename).open("w", encoding="utf-8") as handle:
                for event in episode.events:
                    handle.write(canonical(event) + "\n")
    receipts = {
        "schema_version": SCHEMA_VERSION,
        "episodes_sha256": sha(rows),
        "summary_sha256": sha(stats),
        "config_sha256": sha(spec),
        "source_sha256": source_hash,
        "episode_chains": [e.metrics["ledger_chain_sha256"] for e in episodes],
        "events_exported": retain_events,
    }
    (output / "receipts.json").write_text(json.dumps(receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipts


def verify(output: Path) -> bool:
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    receipts = json.loads((output / "receipts.json").read_text(encoding="utf-8"))
    spec = manifest["configuration"]
    if sha(spec) != receipts["config_sha256"] or sha(spec) != manifest["config_sha256"]:
        return False
    if file_sha256(Path(__file__)) != receipts["source_sha256"] or receipts["source_sha256"] != manifest["source_sha256"]:
        return False
    episodes, stats = campaign(spec, retain_events=bool(receipts["events_exported"]))
    rows = [e.metrics for e in episodes]
    if sha(rows) != receipts["episodes_sha256"] or sha(stats) != receipts["summary_sha256"]:
        return False
    if [e.metrics["ledger_chain_sha256"] for e in episodes] != receipts["episode_chains"]:
        return False
    if json.loads((output / "summary.json").read_text(encoding="utf-8")) != stats:
        return False
    with (output / "episodes.csv").open(encoding="utf-8", newline="") as handle:
        if list(csv.DictReader(handle)) != [{k: "" if v is None else str(v) for k, v in row.items()} for row in rows]:
            return False
    if receipts["events_exported"]:
        for e in episodes:
            filename = f"{e.metrics['inference_mode']}_{e.metrics['posture']}_seed{e.metrics['seed']}.jsonl"
            with (output / filename).open(encoding="utf-8") as handle:
                if [json.loads(line) for line in handle] != e.events:
                    return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("configs/repo_worm_alife_v1.json"))
    parser.add_argument("--output", type=Path, default=Path("output/repo_worm_alife_v1"))
    parser.add_argument("--events", action="store_true", help="Retain every simulated event (bounded JSONL)")
    parser.add_argument("--verify", type=Path, help="Independently rerun and compare all evidence in this output directory")
    args = parser.parse_args(argv)
    if args.verify is not None:
        ok = verify(args.verify)
        print("VERIFIED" if ok else "VERIFICATION FAILED")
        return 0 if ok else 1
    spec = json.loads(args.config.read_text(encoding="utf-8"))
    receipts = emit(spec, args.output, retain_events=args.events)
    print(f"Wrote {args.output}: {len(receipts['episode_chains'])} scripted episodes; receipts {receipts['episodes_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
