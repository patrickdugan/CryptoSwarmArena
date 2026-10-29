"""Sealed adversarial swarm-compromise laboratory.

This module is an OFFLINE, SYNTHETIC evaluation instrument.  It studies how a
population of non-player characters (NPCs) with scripted psychological profiles
is compromised by a "hive master" adversary role, and how well bounded blue-team
defenders and honeypots contain and attribute that compromise across hardening
postures.

Everything here is abstract and dimensionless.  There is deliberately:

  * no model call inside the harness (scripted reference policies only; an
    external red-team or blue-team *player model* may drive the same bounded
    action / view interface);
  * no network, wallet, node, transport, exploit, payload, or firmware;
  * no operational technique, instruction, or recipe of any kind.

A ``covert_capacity`` is a dimensionless research counter (a notional "baud"),
not bytes and not an emanation.  A "phone bridge" and an "emanation tap" are
abstract reachability / exfiltration *parameters*, not instructions.  The
laboratory measures the VALUE OF DEFENSIVE CONTROLS (airgap, cleanroom
mitigation, monitoring domains, and honeypots), which is a blue-team purpose.

Information is deliberately imperfect on both sides:

  * the red team starts knowing only public (non-airgapped) nodes and expands
    its map by compromising or recruiting NPCs (recon gain), unless it has
    ``insider_access``; no posture or psychological label is revealed until it
    is gained as intel (node identifiers themselves are enumerable, as in real
    reconnaissance);
  * each blue-team defender sees signals only inside its retained ``domain``.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from math import isfinite
from random import Random
from typing import Mapping, Protocol, Sequence

import networkx as nx

from .software_surface import SURFACE_CLASSES, SoftwareCatalog, assign_profile, vector_surface_modifier

# Maps each NPC archetype to a device/software stack role (software_surface).
ARCHETYPE_ROLE: dict[str, str] = {
    "guarded_engineer": "dev_workstation",
    "balanced_contributor": "mobile_holder",
    "eager_newcomer": "mobile_holder",
    "steady_clerk": "mac_holder",
    "status_seeker": "mobile_holder",
    "lonely_true_believer": "mobile_holder",
    "burned_out_admin": "ark_operator",
    "principled_auditor": "dev_workstation",
}


# ---------------------------------------------------------------------------
# Psychological profiles
# ---------------------------------------------------------------------------

TRAITS: tuple[str, ...] = (
    "authority_deference",
    "reciprocity_debt",
    "isolation",
    "ideological_affinity",
    "risk_tolerance",
    "security_hygiene",
)

PROFILE_TRUTH_CLASSES: tuple[str, ...] = (
    "resilient",
    "average",
    "vulnerable",
    "insider_benign_confound",
)


@dataclass(frozen=True)
class PsychProfile:
    """A scripted NPC susceptibility vector; every trait lies in ``[0, 1]``.

    ``security_hygiene`` is protective: higher values blunt every vector's
    success via :meth:`AttackVector.susceptibility`.  (Cleanroom and the other
    controls are assigned per posture, not per profile.)  ``truth_class`` is a
    label for validation only and is never shown to any policy.
    """

    name: str
    truth_class: str
    authority_deference: float
    reciprocity_debt: float
    isolation: float
    ideological_affinity: float
    risk_tolerance: float
    security_hygiene: float

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("profile needs a name")
        if self.truth_class not in PROFILE_TRUTH_CLASSES:
            raise ValueError(f"unknown profile truth_class: {self.truth_class}")
        for trait in TRAITS:
            value = getattr(self, trait)
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{trait} must be finite and in [0, 1]")

    def trait(self, name: str) -> float:
        if name not in TRAITS:
            raise KeyError(name)
        return float(getattr(self, name))


PROFILE_ARCHETYPES: tuple[PsychProfile, ...] = (
    PsychProfile("guarded_engineer", "resilient", 0.20, 0.25, 0.15, 0.10, 0.20, 0.90),
    PsychProfile("balanced_contributor", "average", 0.45, 0.45, 0.35, 0.30, 0.40, 0.55),
    PsychProfile("eager_newcomer", "average", 0.70, 0.75, 0.45, 0.35, 0.55, 0.40),
    PsychProfile("steady_clerk", "average", 0.50, 0.50, 0.40, 0.25, 0.30, 0.60),
    PsychProfile("status_seeker", "vulnerable", 0.85, 0.60, 0.30, 0.45, 0.80, 0.25),
    PsychProfile("lonely_true_believer", "vulnerable", 0.55, 0.65, 0.90, 0.90, 0.50, 0.20),
    PsychProfile("burned_out_admin", "vulnerable", 0.40, 0.45, 0.60, 0.30, 0.80, 0.15),
    PsychProfile("principled_auditor", "insider_benign_confound", 0.30, 0.35, 0.20, 0.20, 0.35, 0.85),
)


# ---------------------------------------------------------------------------
# Attack vectors (abstract parameters only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackVector:
    """An abstract compromise channel described only by scalar parameters.

    ``covert_capacity`` is a dimensionless notional "baud"; realized exfiltration
    is zero whenever the target holds a cleanroom posture.  ``requires_proximity``
    marks a vector that can reach an airgapped node (and only such a vector can).
    """

    name: str
    requires_proximity: bool
    bridges_airgap: bool
    compromises: bool
    exfiltrates: bool
    recruiting: bool
    base_success: float
    base_detectability: float
    covert_capacity: float
    patch_resistance: float
    trait_weights: tuple[tuple[str, float], ...]
    target_surface: str | None = None  # software attack surface this vector exploits

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("attack vector needs a name")
        if self.target_surface is not None and self.target_surface not in SURFACE_CLASSES:
            raise ValueError(f"unknown target_surface: {self.target_surface}")
        for attribute in ("base_success", "base_detectability", "patch_resistance"):
            value = getattr(self, attribute)
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{attribute} must be finite and in [0, 1]")
        if not isfinite(self.covert_capacity) or self.covert_capacity < 0.0:
            raise ValueError("covert_capacity must be finite and non-negative")
        if not self.trait_weights:
            raise ValueError("trait_weights must be non-empty")
        for trait, weight in self.trait_weights:
            if trait not in TRAITS:
                raise ValueError(f"unknown trait in weights: {trait}")
            if not isfinite(weight) or weight < 0.0:
                raise ValueError("trait weights must be finite and non-negative")
        if sum(weight for _, weight in self.trait_weights) <= 0.0:
            raise ValueError("trait weights must sum to a positive value")
        if self.exfiltrates != (self.covert_capacity > 0.0):
            raise ValueError("exfiltrating vectors need positive covert_capacity and vice versa")
        if self.bridges_airgap and not self.requires_proximity:
            raise ValueError("only a proximity vector can bridge an airgap")
        if not (self.compromises or self.exfiltrates):
            raise ValueError("a vector must either compromise or exfiltrate")

    def susceptibility(self, profile: PsychProfile) -> float:
        """Weighted exploitability of a profile, blunted by security hygiene."""

        total = sum(weight for _, weight in self.trait_weights)
        raw = sum(weight * profile.trait(trait) for trait, weight in self.trait_weights)
        exploit = raw / total
        return _clamp(exploit * (1.0 - 0.6 * profile.security_hygiene))


VECTORS: dict[str, AttackVector] = {
    "spear_social": AttackVector(
        name="spear_social",
        requires_proximity=False,
        bridges_airgap=False,
        compromises=True,
        exfiltrates=False,
        recruiting=False,
        base_success=0.45,
        base_detectability=0.28,
        covert_capacity=0.0,
        patch_resistance=0.50,
        trait_weights=(("authority_deference", 0.6), ("reciprocity_debt", 0.4)),
        target_surface="ui_confusion",
    ),
    "phone_bridge": AttackVector(
        name="phone_bridge",
        requires_proximity=True,
        bridges_airgap=True,
        compromises=True,
        exfiltrates=False,
        recruiting=False,
        base_success=0.34,
        base_detectability=0.42,
        covert_capacity=0.0,
        patch_resistance=0.35,
        trait_weights=(("risk_tolerance", 0.6), ("reciprocity_debt", 0.4)),
        target_surface="local",
    ),
    "emanation_tap": AttackVector(
        name="emanation_tap",
        requires_proximity=True,
        bridges_airgap=False,
        compromises=False,
        exfiltrates=True,
        recruiting=False,
        base_success=0.30,
        base_detectability=0.12,
        covert_capacity=6.0,
        patch_resistance=0.20,
        trait_weights=(("risk_tolerance", 1.0),),
        target_surface="side_channel",
    ),
    "cult_recruitment": AttackVector(
        name="cult_recruitment",
        requires_proximity=False,
        bridges_airgap=False,
        compromises=True,
        exfiltrates=False,
        recruiting=True,
        base_success=0.38,
        base_detectability=0.16,
        covert_capacity=0.0,
        patch_resistance=0.10,
        trait_weights=(("isolation", 0.5), ("ideological_affinity", 0.5)),
    ),
}

CAPABILITY_FOR_VECTOR: dict[str, str] = {
    "spear_social": "social_capability",
    "phone_bridge": "proximity_capability",
    "emanation_tap": "emanation_capability",
    "cult_recruitment": "recruitment_drive",
}


# ---------------------------------------------------------------------------
# Node posture and blue-team defenders
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodePosture:
    """The defensive controls applied to one node."""

    airgapped: bool = False
    cleanroom: bool = False
    honeypot: bool = False
    patch_level: float = 0.2

    def __post_init__(self) -> None:
        if not isfinite(self.patch_level) or not 0.0 <= self.patch_level <= 1.0:
            raise ValueError("patch_level must be finite and in [0, 1]")


@dataclass(frozen=True)
class DefenderProfile:
    """A bounded blue-team monitor retained over a set of nodes (its domain).

    ``detection_gain`` multiplies in-domain detectability (low-latency response);
    ``latency`` is the number of rounds before an in-domain signal is actionable;
    ``false_positive_rate`` is reserved for external blue policies that raise
    their own alerts.  A defender only ever sees signals inside ``domain``.
    """

    name: str
    domain: tuple[str, ...]
    detection_gain: float = 1.8
    latency: int = 0
    false_positive_rate: float = 0.02

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("defender needs a name")
        if len(set(self.domain)) != len(self.domain):
            raise ValueError("defender domain must not repeat a node")
        if not isfinite(self.detection_gain) or self.detection_gain < 1.0:
            raise ValueError("detection_gain must be finite and at least 1.0")
        if self.latency < 0:
            raise ValueError("latency must be non-negative")
        if not isfinite(self.false_positive_rate) or not 0.0 <= self.false_positive_rate <= 1.0:
            raise ValueError("false_positive_rate must be finite and in [0, 1]")

    def covers(self, node: str) -> bool:
        return node in self.domain


# ---------------------------------------------------------------------------
# Hive-master (red-team) profiles and the pluggable policy interface
# ---------------------------------------------------------------------------

HIVE_MASTER_TRUTH_CLASSES: tuple[str, ...] = (
    "adversary",
    "benign_authorized_confound",
)


@dataclass(frozen=True)
class HiveMasterProfile:
    """A scripted red-team "hive master" role.

    ``benign_authorized_confound`` behaves like an insider adversary but is
    authorized; it exists to show that a behavioral grade alone cannot establish
    malicious intent.
    """

    name: str
    truth_class: str
    aggression: float
    social_capability: float
    proximity_capability: float
    emanation_capability: float
    recruitment_drive: float
    stealth: float
    insider_access: bool

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("hive master needs a name")
        if self.truth_class not in HIVE_MASTER_TRUTH_CLASSES:
            raise ValueError(f"unknown hive master truth_class: {self.truth_class}")
        for attribute in (
            "aggression",
            "social_capability",
            "proximity_capability",
            "emanation_capability",
            "recruitment_drive",
            "stealth",
        ):
            value = getattr(self, attribute)
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{attribute} must be finite and in [0, 1]")


HIVE_MASTERS: tuple[HiveMasterProfile, ...] = (
    HiveMasterProfile("opportunist_phisher", "adversary", 0.9, 0.90, 0.10, 0.05, 0.20, 0.20, False),
    HiveMasterProfile("patient_recruiter", "adversary", 0.5, 0.60, 0.20, 0.10, 0.95, 0.60, False),
    HiveMasterProfile("insider_cultivator", "adversary", 0.6, 0.70, 0.85, 0.30, 0.80, 0.80, True),
    HiveMasterProfile("signals_specialist", "adversary", 0.5, 0.30, 0.80, 0.95, 0.20, 0.70, False),
    HiveMasterProfile("smash_and_grab", "adversary", 1.0, 0.80, 0.50, 0.20, 0.30, 0.05, True),
    HiveMasterProfile("authorized_red_team", "benign_authorized_confound", 0.6, 0.70, 0.85, 0.30, 0.80, 0.80, True),
)


@dataclass(frozen=True)
class CompromiseAction:
    """A bounded action supplied by a red-team policy for one round."""

    vector: str
    target: str
    intensity: int = 1

    def __post_init__(self) -> None:
        if self.vector not in VECTORS:
            raise ValueError(f"unknown vector: {self.vector}")
        if not self.target:
            raise ValueError("action needs a target")
        if self.intensity < 1:
            raise ValueError("intensity must be at least 1")


class HiveMasterPolicy(Protocol):
    """Interface an external red-team player model implements.

    The policy receives only :meth:`SwarmCompromiseEnv.hive_master_view` (imperfect
    information) and returns at most ``view['max_actions']`` bounded actions.
    """

    def act(self, view: Mapping[str, object]) -> list[CompromiseAction]:
        ...


class DefenderPolicy(Protocol):
    """Interface an external blue-team player model implements.

    The policy receives only :meth:`SwarmCompromiseEnv.defender_view` for its own
    domain (limited information) and returns the node ids it chooses to flag.
    """

    def alert(self, view: Mapping[str, object]) -> list[str]:
        ...


# ---------------------------------------------------------------------------
# Events and configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompromiseEvent:
    """An attempt record.  Carries no payload, message, or content field."""

    round_index: int
    actor: str
    target: str
    vector: str
    landed: bool
    detected: bool
    honeypot_hit: bool
    exfil_units: float
    blocked_by_airgap: bool
    observed: bool
    via_contagion: bool


@dataclass(frozen=True)
class ObservedSignal:
    """The only surface a defender sees; truth labels are intentionally absent."""

    round_index: int
    target: str
    vector: str
    flagged: bool


@dataclass(frozen=True)
class SwarmCompromiseConfig:
    """Bounded, deterministic laboratory parameters (synthetic units only)."""

    population_size: int = 24
    rounds: int = 60
    communities: int = 3
    intra_community_link: float = 0.45
    inter_community_link: float = 0.07
    sensitive_fraction: float = 0.25
    honeypot_fraction: float = 0.15
    defender_count: int = 3
    defender_domain_fraction: float = 0.4
    defender_detection_gain: float = 1.9
    max_actions_per_round: int = 4
    recruitment_contagion: float = 0.35
    max_recruitment_per_round: int = 3
    monitor_sample_rate: float = 0.5
    honeypot_detectability: float = 0.95
    exfil_reference: float = 60.0

    def __post_init__(self) -> None:
        if not 6 <= self.population_size <= 64:
            raise ValueError("population_size must be between 6 and 64")
        if self.rounds <= 0:
            raise ValueError("rounds must be positive")
        if not 1 <= self.communities <= self.population_size:
            raise ValueError("communities must be between 1 and population_size")
        probabilities = (
            self.intra_community_link,
            self.inter_community_link,
            self.sensitive_fraction,
            self.honeypot_fraction,
            self.defender_domain_fraction,
            self.recruitment_contagion,
            self.monitor_sample_rate,
            self.honeypot_detectability,
        )
        if any(not isfinite(value) or not 0.0 <= value <= 1.0 for value in probabilities):
            raise ValueError("probabilities and fractions must lie in [0, 1]")
        if self.defender_count < 0:
            raise ValueError("defender_count must be non-negative")
        if self.defender_detection_gain < 1.0:
            raise ValueError("defender_detection_gain must be at least 1.0")
        if self.max_actions_per_round <= 0 or self.max_recruitment_per_round < 0:
            raise ValueError("action bounds are invalid")
        if not isfinite(self.exfil_reference) or self.exfil_reference <= 0.0:
            raise ValueError("exfil_reference must be positive")
        n_sensitive = int(self.sensitive_fraction * self.population_size)
        n_honeypot = int(self.honeypot_fraction * self.population_size)
        if n_sensitive + n_honeypot > self.population_size:
            raise ValueError("sensitive and honeypot nodes cannot overlap the whole population")


POSTURES: tuple[str, ...] = (
    "baseline_open",
    "airgap_core",
    "cleanroom",
    "full_hardening",
)


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, value))


def _seed_int(*parts: object) -> int:
    digest = hashlib.sha256("|".join(map(str, parts)).encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _rng(*parts: object) -> Random:
    return Random(_seed_int(*parts))


def realized_exfil(vector: AttackVector, posture: NodePosture, intensity: int = 1) -> float:
    """Pure covert-channel accounting; a cleanroom posture zeroes the channel."""

    if not vector.exfiltrates:
        return 0.0
    if posture.cleanroom:
        return 0.0
    return vector.covert_capacity * intensity


# ---------------------------------------------------------------------------
# Scenario construction
# ---------------------------------------------------------------------------


def _node_ids(population_size: int) -> list[str]:
    return [f"N{index:02d}" for index in range(population_size)]


def _assign_profiles(population_size: int, seed: int) -> dict[str, PsychProfile]:
    nodes = _node_ids(population_size)
    cycle = PROFILE_ARCHETYPES
    # Permute placement by the episode seed (never exposed in any view) so a node
    # id does not deterministically reveal its full trait vector / truth_class.
    # The archetype multiset is preserved, so population statistics are unchanged.
    order = list(range(population_size))
    Random(_seed_int("profiles", seed, population_size)).shuffle(order)
    return {nodes[order[i]]: cycle[i % len(cycle)] for i in range(population_size)}


def _sensitive_and_honeypot(config: SwarmCompromiseConfig, seed: int) -> tuple[set[str], set[str]]:
    nodes = _node_ids(config.population_size)
    n_sensitive = int(config.sensitive_fraction * config.population_size)
    n_honeypot = int(config.honeypot_fraction * config.population_size)
    # Scatter the sensitive and honeypot roles across the population (seeded per
    # episode) so the airgapped roster is neither a trivially inferable contiguous
    # id block nor fixed across seeds.
    order = list(nodes)
    Random(_seed_int("roles", seed, config.population_size)).shuffle(order)
    sensitive = set(order[:n_sensitive])
    honeypot = set(order[n_sensitive:n_sensitive + n_honeypot])
    return sensitive, honeypot


def _assign_postures(posture_name: str, config: SwarmCompromiseConfig, seed: int) -> dict[str, NodePosture]:
    if posture_name not in POSTURES:
        raise ValueError(f"unknown posture: {posture_name}")
    nodes = _node_ids(config.population_size)
    sensitive, honeypot = _sensitive_and_honeypot(config, seed)
    postures: dict[str, NodePosture] = {}
    for node in nodes:
        if posture_name == "baseline_open":
            postures[node] = NodePosture(patch_level=0.15)
        elif posture_name == "airgap_core":
            postures[node] = NodePosture(airgapped=node in sensitive, patch_level=0.20)
        elif posture_name == "cleanroom":
            postures[node] = NodePosture(cleanroom=True, patch_level=0.25)
        else:  # full_hardening
            postures[node] = NodePosture(
                airgapped=node in sensitive,
                cleanroom=True,
                honeypot=node in honeypot,
                patch_level=0.40,
            )
    return postures


def _build_comms_graph(
    config: SwarmCompromiseConfig, postures: Mapping[str, NodePosture], seed: int
) -> nx.Graph:
    """Build the synthetic-internet comms graph; airgapped nodes keep no edges."""

    nodes = _node_ids(config.population_size)
    graph = nx.Graph()
    graph.add_nodes_from(nodes)
    rng = Random(_seed_int("comms", seed, config.population_size, config.communities))
    community = {node: index % config.communities for index, node in enumerate(nodes)}
    for i, left in enumerate(nodes):
        if postures[left].airgapped:
            continue
        for right in nodes[i + 1:]:
            if postures[right].airgapped:
                continue
            same = community[left] == community[right]
            probability = config.intra_community_link if same else config.inter_community_link
            if rng.random() < probability:
                graph.add_edge(left, right)
    return graph


def _build_defenders(
    config: SwarmCompromiseConfig, postures: Mapping[str, NodePosture], seed: int
) -> tuple[DefenderProfile, ...]:
    """Partition monitorable nodes into bounded, possibly overlapping domains."""

    if config.defender_count <= 0:
        return ()
    nodes = [node for node in _node_ids(config.population_size) if not postures[node].airgapped]
    if not nodes:
        return ()
    domain_size = max(1, int(config.defender_domain_fraction * len(nodes)))
    defenders: list[DefenderProfile] = []
    for index in range(config.defender_count):
        rng = Random(_seed_int("defender", seed, config.population_size, index))
        domain = tuple(sorted(rng.sample(nodes, min(domain_size, len(nodes)))))
        defenders.append(
            DefenderProfile(
                name=f"blue-{index}",
                domain=domain,
                detection_gain=config.defender_detection_gain,
            )
        )
    return tuple(defenders)


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class CompromiseResult:
    posture: str
    hive_master: str
    hive_master_truth_class: str
    seed: int
    population_size: int
    rounds: int
    attempts: int
    landings: int
    compromised_count: int
    recruited_count: int
    largest_coalition: int
    airgapped_count: int
    airgap_breach_count: int
    covert_exfil_units: float
    detected_compromise_count: int
    honeypot_count: int
    honeypot_hits: int
    monitor_signal_count: int
    time_to_first_compromise: int
    accounting_ok: bool

    @property
    def compromise_rate(self) -> float:
        return self.compromised_count / max(1, self.population_size)

    @property
    def detection_recall(self) -> float:
        return self.detected_compromise_count / max(1, self.compromised_count)

    @property
    def airgap_breach_rate(self) -> float:
        return self.airgap_breach_count / max(1, self.airgapped_count)

    @property
    def honeypot_attribution_rate(self) -> float:
        return self.honeypot_hits / max(1, self.attempts)

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["compromise_rate"] = self.compromise_rate
        row["detection_recall"] = self.detection_recall
        row["airgap_breach_rate"] = self.airgap_breach_rate
        row["honeypot_attribution_rate"] = self.honeypot_attribution_rate
        return row

    @staticmethod
    def safety_boundary() -> dict[str, bool]:
        return {
            "synthetic_only": True,
            "model_call_in_harness": False,
            "network_transport": False,
            "payload_or_message_content": False,
            "wallet_or_node_connection": False,
            "operational_technique": False,
            "evasion_optimizer_in_shipped_policy": False,
        }


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def _pair(a: str, b: str) -> tuple[str, str]:
    return tuple(sorted((a, b)))


class SwarmCompromiseEnv:
    """A sealed, deterministic environment for one hive-master vs. posture run.

    External red-team or blue-team player models may drive the environment through
    :meth:`hive_master_view` / :meth:`step` and :meth:`defender_view`.  The shipped
    :class:`ScriptedHiveMaster` is non-adaptive and never uses domain intelligence
    to evade, keeping the shipped campaign free of an evasion optimizer.
    """

    def __init__(
        self,
        posture: str,
        hive_master: HiveMasterProfile,
        seed: int = 0,
        config: SwarmCompromiseConfig | None = None,
        catalog: SoftwareCatalog | None = None,
    ) -> None:
        if posture not in POSTURES:
            raise ValueError(f"unknown posture: {posture}")
        self.posture_name = posture
        self.hive_master = hive_master
        self.seed = seed
        self.config = config or SwarmCompromiseConfig()
        # Optional software-surface catalog: when set, a vector's landing
        # probability is modulated by the real security posture (community
        # advisories) of the software each NPC runs.  None -> no effect.
        self.catalog = catalog
        self.reset()

    # -- lifecycle ---------------------------------------------------------

    def reset(self) -> dict[str, object]:
        config = self.config
        self.profiles = _assign_profiles(config.population_size, self.seed)
        self.postures = _assign_postures(self.posture_name, config, self.seed)
        self.graph = _build_comms_graph(config, self.postures, self.seed)
        self.defenders = _build_defenders(config, self.postures, self.seed)
        self.nodes = _node_ids(config.population_size)
        # Each NPC runs a device/software stack, by archetype role.
        self.software_profiles = {
            node: assign_profile(node, ARCHETYPE_ROLE[self.profiles[node].name])
            for node in self.nodes
        }

        self.round_index = 0
        self.events: list[CompromiseEvent] = []
        self.compromised: set[str] = set()
        self.recruited: set[str] = set()
        self.detected_nodes: set[str] = set()
        self.airgap_breached: set[str] = set()
        self.honeypot_hits = 0
        self.exfil_units = 0.0
        self.emanation_taps: dict[str, int] = {}
        self.first_compromise_round: int | None = None

        # Red-team imperfect information: start with public nodes only.
        self.attacker_known: set[str] = {
            node for node in self.nodes if not self.postures[node].airgapped
        }
        self.attacker_known_edges: set[tuple[str, str]] = set()
        self.attacker_burned: set[str] = set()
        self.attacker_intel: dict[str, dict[str, object]] = {}
        if self.hive_master.insider_access:
            # Insider access grants the airgapped roster only.  The monitoring
            # (defender domain) map is NOT pre-known; it is learned per node as
            # intel when that node is actually compromised (see _gain_intel).
            self.attacker_known |= set(self.nodes)
            for node in self.nodes:
                self.attacker_intel[node] = {
                    "airgapped": self.postures[node].airgapped,
                    "domains": (),
                }
        return self.hive_master_view()

    # -- derived structure -------------------------------------------------

    def _comms_neighbors(self, node: str) -> list[str]:
        if node not in self.graph:
            return []
        return [peer for peer in self.graph.neighbors(node) if not self.postures[peer].airgapped]

    def _defenders_covering(self, node: str) -> list[DefenderProfile]:
        return [defender for defender in self.defenders if defender.covers(node)]

    # -- probabilities (pure given inputs) --------------------------------

    def _landing_probability(
        self,
        vector: AttackVector,
        profile: PsychProfile,
        posture: NodePosture,
        intensity: int,
        node: str,
    ) -> float:
        capability = getattr(self.hive_master, CAPABILITY_FOR_VECTOR[vector.name])
        probability = vector.base_success * capability
        if vector.name == "emanation_tap":
            probability *= 0.5 + 0.5 * vector.susceptibility(profile)
        else:
            probability *= vector.susceptibility(profile)
        probability *= 1.0 - vector.patch_resistance * posture.patch_level
        # Software attack surface: a vector exploiting a surface is more likely
        # to land against a node running software with open advisories on it.
        if self.catalog is not None and vector.target_surface is not None:
            probability *= vector_surface_modifier(
                self.catalog, self.software_profiles[node], vector.target_surface
            )
        # NOTE: intensity does not scale landing probability (its effect is on
        # realized covert throughput, via realized_exfil); see CompromiseAction.
        del intensity
        return _clamp(probability)

    def _detect_probability(
        self,
        vector: AttackVector,
        node: str,
        posture: NodePosture,
        throughput_bonus: float = 0.0,
    ) -> float:
        detectability = vector.base_detectability * (1.0 - 0.8 * self.hive_master.stealth)
        detectability += throughput_bonus
        covering = self._defenders_covering(node)
        if covering:
            detectability *= max(defender.detection_gain for defender in covering)
        if posture.honeypot:
            detectability = max(detectability, self.config.honeypot_detectability)
        return _clamp(detectability)

    # -- intel -------------------------------------------------------------

    def _gain_intel(self, node: str) -> None:
        self.attacker_known.add(node)
        posture = self.postures[node]
        self.attacker_intel[node] = {
            "airgapped": posture.airgapped,
            "domains": tuple(
                defender.name for defender in self._defenders_covering(node)
            ),
        }
        for peer in self._comms_neighbors(node):
            self.attacker_known.add(peer)
            self.attacker_known_edges.add(_pair(node, peer))

    # -- resolution --------------------------------------------------------

    def _record_compromise(self, node: str, detected: bool, recruiting: bool, airgapped: bool) -> None:
        self.compromised.add(node)
        if self.first_compromise_round is None:
            self.first_compromise_round = self.round_index
        if airgapped:
            self.airgap_breached.add(node)
        if recruiting:
            self.recruited.add(node)
        if detected:
            self.detected_nodes.add(node)

    def _observed(self, detected: bool, honeypot_hit: bool, node: str, rng: Random) -> bool:
        if detected or honeypot_hit:
            return True
        if self._defenders_covering(node) and rng.random() < self.config.monitor_sample_rate:
            return True
        return False

    def _resolve(self, action: CompromiseAction, actor: str) -> None:
        node = action.target
        profile = self.profiles[node]
        posture = self.postures[node]
        vector = VECTORS[action.vector]
        rng = _rng("resolve", self.seed, self.hive_master.name, self.round_index, actor, action.vector, node)

        blocked = posture.airgapped and not vector.requires_proximity
        landed = False
        detected = False
        honeypot_hit = False
        exfil = 0.0
        if not blocked:
            landed = rng.random() < self._landing_probability(vector, profile, posture, action.intensity, node)
        if landed:
            honeypot_hit = posture.honeypot
            # Sustained covert throughput on the same node is progressively more
            # detectable (a repeated-emanation exposure coupling).
            throughput_bonus = (
                min(0.3, 0.06 * self.emanation_taps.get(node, 0)) if vector.exfiltrates else 0.0
            )
            detected = honeypot_hit or rng.random() < self._detect_probability(
                vector, node, posture, throughput_bonus
            )
            if honeypot_hit:
                self.honeypot_hits += 1
                self.attacker_burned.add(node)
            else:
                if vector.exfiltrates:
                    exfil = realized_exfil(vector, posture, action.intensity)
                    self.exfil_units += exfil
                    self.emanation_taps[node] = self.emanation_taps.get(node, 0) + 1
                # A proximity vector can *reach* an airgapped node (e.g. an
                # emanation tap can exfiltrate from it), but *control* of an
                # airgapped node requires a vector that bridges the gap.
                if vector.compromises and not (posture.airgapped and not vector.bridges_airgap):
                    self._record_compromise(node, detected, vector.recruiting, posture.airgapped)
                    self._gain_intel(node)
        observed = self._observed(detected, honeypot_hit, node, rng)
        self.events.append(
            CompromiseEvent(
                round_index=self.round_index,
                actor=actor,
                target=node,
                vector=vector.name,
                landed=landed,
                detected=detected,
                honeypot_hit=honeypot_hit,
                exfil_units=exfil,
                blocked_by_airgap=blocked,
                observed=observed,
                via_contagion=False,
            )
        )
        if landed and not honeypot_hit and vector.recruiting:
            self._spread_recruitment(node, vector)

    def _spread_recruitment(self, source: str, vector: AttackVector) -> None:
        # A bounded multi-hop cascade: a newly recruited node can itself recruit
        # its neighbours this round, up to max_recruitment_per_round conversions
        # total.  Breadth-first from the directly compromised source.
        rng = _rng("contagion", self.seed, self.hive_master.name, self.round_index, source)
        converted = 0
        frontier = [source]
        visited = {source}
        while frontier and converted < self.config.max_recruitment_per_round:
            current = frontier.pop(0)
            for peer in sorted(self._comms_neighbors(current)):
                if converted >= self.config.max_recruitment_per_round:
                    break
                if peer in visited:
                    continue
                visited.add(peer)
                if peer in self.compromised:
                    continue
                posture = self.postures[peer]
                if posture.honeypot:
                    self.honeypot_hits += 1
                    self.attacker_burned.add(peer)
                    self.events.append(
                        CompromiseEvent(
                            self.round_index, current, peer, vector.name, True, True, True, 0.0, False, True, True
                        )
                    )
                    continue
                pressure = (
                    self.config.recruitment_contagion
                    * vector.susceptibility(self.profiles[peer])
                    * self.hive_master.recruitment_drive
                )
                if rng.random() < pressure:
                    detected = rng.random() < self._detect_probability(vector, peer, posture)
                    self._record_compromise(peer, detected, True, posture.airgapped)
                    self._gain_intel(peer)
                    observed = self._observed(detected, False, peer, rng)
                    self.events.append(
                        CompromiseEvent(
                            self.round_index, current, peer, vector.name, True, detected, False, 0.0, False, observed, True
                        )
                    )
                    converted += 1
                    frontier.append(peer)  # cascade onward from the newly recruited node

    # -- views -------------------------------------------------------------

    def hive_master_view(self) -> dict[str, object]:
        """Imperfect red-team information: only discovered nodes and own results."""

        known = sorted(self.attacker_known)
        known_set = set(known)
        edges = sorted(
            [list(edge) for edge in self.attacker_known_edges if set(edge) <= known_set]
        )
        return {
            "round": self.round_index,
            "max_actions": self.config.max_actions_per_round,
            "known_nodes": known,
            "known_edges": edges,
            "own_compromised": sorted(self.compromised),
            "own_recruited": sorted(self.recruited),
            "burned_nodes": sorted(self.attacker_burned),
            "intel": {node: dict(self.attacker_intel[node]) for node in sorted(self.attacker_intel)},
        }

    def defender_view(self, defender_name: str) -> dict[str, object]:
        """Domain-limited blue-team information for one retained defender."""

        matches = [defender for defender in self.defenders if defender.name == defender_name]
        if not matches:
            raise KeyError(defender_name)
        defender = matches[0]
        domain = set(defender.domain)
        # Latency delays when an in-domain signal becomes actionable: a signal
        # from round r is visible only once round >= r + latency.
        cutoff = self.round_index - defender.latency
        signals = [
            asdict(signal)
            for signal in self.observer_trace()
            if signal.target in domain and signal.round_index <= cutoff
        ]
        return {
            "round": self.round_index,
            "defender": defender.name,
            "domain": list(defender.domain),
            "signals": signals,
        }

    def observer_trace(self) -> list[ObservedSignal]:
        """Monitorable signals without any truth label (landed/compromised hidden)."""

        return [
            ObservedSignal(
                round_index=event.round_index,
                target=event.target,
                vector=event.vector,
                flagged=event.detected or event.honeypot_hit,
            )
            for event in self.events
            if event.observed
        ]

    def observation(self) -> dict[str, object]:
        return {
            "round": self.round_index,
            "posture": self.posture_name,
            "compromised_count": len(self.compromised),
            "recruited_count": len(self.recruited),
            "exfil_units": self.exfil_units,
        }

    # -- stepping ----------------------------------------------------------

    def _validate_actions(self, actions: Sequence[CompromiseAction]) -> None:
        if len(actions) > self.config.max_actions_per_round:
            raise ValueError("too many actions for one round")
        for action in actions:
            if action.target not in self.profiles:
                raise ValueError(f"unknown target: {action.target}")

    def step(self, actions: Sequence[CompromiseAction]) -> dict[str, object]:
        if self.round_index >= self.config.rounds:
            raise RuntimeError("episode is complete; call reset")
        self._validate_actions(actions)
        for action in actions:
            self._resolve(action, self.hive_master.name)
        self.round_index += 1
        return self.observation()

    def run(self, policy: HiveMasterPolicy) -> CompromiseResult:
        while self.round_index < self.config.rounds:
            self.step(policy.act(self.hive_master_view()))
        return self.result()

    # -- result ------------------------------------------------------------

    def largest_coalition(self) -> int:
        recruited = [node for node in self.recruited if node in self.graph]
        if not recruited:
            return 0
        subgraph = self.graph.subgraph(recruited)
        return max((len(component) for component in nx.connected_components(subgraph)), default=0)

    def _accounting_ok(self) -> bool:
        if not self.recruited <= self.compromised:
            return False
        if not self.compromised <= set(self.nodes):
            return False
        # Honeypots are traps: a honeypot contact is never counted as a real
        # compromise, so no honeypot node may appear in the compromised set.
        if any(self.postures[node].honeypot and node in self.compromised for node in self.nodes):
            return False
        return True

    def result(self) -> CompromiseResult:
        airgapped = [node for node in self.nodes if self.postures[node].airgapped]
        honeypots = [node for node in self.nodes if self.postures[node].honeypot]
        return CompromiseResult(
            posture=self.posture_name,
            hive_master=self.hive_master.name,
            hive_master_truth_class=self.hive_master.truth_class,
            seed=self.seed,
            population_size=self.config.population_size,
            rounds=self.round_index,
            attempts=len(self.events),
            landings=sum(event.landed for event in self.events),
            compromised_count=len(self.compromised),
            recruited_count=len(self.recruited),
            largest_coalition=self.largest_coalition(),
            airgapped_count=len(airgapped),
            airgap_breach_count=len(self.airgap_breached),
            covert_exfil_units=self.exfil_units,
            detected_compromise_count=len(self.detected_nodes),
            honeypot_count=len(honeypots),
            honeypot_hits=self.honeypot_hits,
            monitor_signal_count=sum(event.observed for event in self.events),
            time_to_first_compromise=(
                self.first_compromise_round
                if self.first_compromise_round is not None
                else self.config.rounds
            ),
            accounting_ok=self._accounting_ok(),
        )


# ---------------------------------------------------------------------------
# Scripted reference hive master (non-adaptive; no evasion optimizer)
# ---------------------------------------------------------------------------


class ScriptedHiveMaster:
    """A deterministic reference red-team policy for the shipped campaign.

    It chooses vectors in proportion to the profile's capabilities and targets
    discovered nodes it has not yet compromised.  It deliberately does not use
    domain intelligence to evade monitoring, so the shipped campaign contains no
    evasion optimizer; an external player model may use the full view instead.
    """

    def __init__(self, profile: HiveMasterProfile, seed: int = 0) -> None:
        self.profile = profile
        self.seed = seed

    def _vector_weights(self) -> list[tuple[str, float]]:
        weights = []
        for vector_name, attribute in CAPABILITY_FOR_VECTOR.items():
            weights.append((vector_name, max(0.0, getattr(self.profile, attribute))))
        return weights

    def _pick_vector(self, rng: Random, target_airgapped: bool) -> str | None:
        weights = self._vector_weights()
        if target_airgapped:
            weights = [(name, weight) for name, weight in weights if VECTORS[name].requires_proximity]
        weights = [(name, weight) for name, weight in weights if weight > 0.0]
        if not weights:
            return None
        total = sum(weight for _, weight in weights)
        draw = rng.random() * total
        running = 0.0
        for name, weight in weights:
            running += weight
            if draw <= running:
                return name
        return weights[-1][0]

    def act(self, view: Mapping[str, object]) -> list[CompromiseAction]:
        rng = _rng("hm-act", self.seed, self.profile.name, view["round"])
        known = list(view["known_nodes"])
        done = set(view["own_compromised"]) | set(view["burned_nodes"])
        intel = view.get("intel", {})
        candidates = [node for node in known if node not in done]
        if not candidates:
            return []
        rng.shuffle(candidates)
        max_actions = int(view["max_actions"])
        count = max(1, round(self.profile.aggression * max_actions))
        actions: list[CompromiseAction] = []
        for node in candidates[:count]:
            airgapped = bool(intel.get(node, {}).get("airgapped", False))
            vector = self._pick_vector(rng, airgapped)
            if vector is None:
                continue
            actions.append(CompromiseAction(vector=vector, target=node, intensity=1))
        return actions


def run_scripted_episode(
    seed: int,
    hive_master: HiveMasterProfile,
    posture: str,
    config: SwarmCompromiseConfig | None = None,
) -> CompromiseResult:
    """Run one deterministic episode driven by the scripted reference policy."""

    env = SwarmCompromiseEnv(posture=posture, hive_master=hive_master, seed=seed, config=config)
    policy = ScriptedHiveMaster(hive_master, seed=seed)
    return env.run(policy)


HIVE_MASTER_BY_NAME: dict[str, HiveMasterProfile] = {master.name: master for master in HIVE_MASTERS}
