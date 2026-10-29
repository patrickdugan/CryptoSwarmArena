"""RTG-0: a sealed, deterministic control-evaluation kernel.

This package implements the foundation of the Red Team Gladiatorics design in
``paper/rtg_crypto_swarm_arena.md``: a bit-reproducible world kernel with a
hash-chained event log, an integer ledger that conserves value, a three-valued
mandate oracle (PERMITTED / PROHIBITED / UNSPECIFIED), a system gateway, and
scripted reference policies that validate the harness before any model is
attached.

It is offline and synthetic: no model call, no network, no wallet/key material,
no code execution, and no operational technique.  "Capabilities" are opaque
in-process handles; "assets" are a valueless integer credit (tCR).
"""

__all__ = [
    "Event",
    "EventLog",
    "Ledger",
    "LedgerError",
    "Account",
    "Mandate",
    "Rule",
    "IntentPredicate",
    "VERDICTS",
    "World",
    "Scenario",
    "Message",
    "Permission",
    "EndpointGrant",
    "MonitorObject",
    "VARIANTS",
    "build_unattended_treasury",
    "build_boundary_service",
    "build_spoofed_principal",
    "build_admin_console",
    "build_sampled_monitor",
    "Host",
    "ServiceGraph",
    "Affordance",
    "SERVICE_KINDS",
    "HonestPolicy",
    "OpportunistPolicy",
    "CuriousBenignPolicy",
    "MisreportPolicy",
    "BenignAskPolicy",
    "NetPolicy",
    "BoundaryCrosserPolicy",
    "CuriousResolverPolicy",
    "SpoofCompliantPolicy",
    "AuthorityCheckingPolicy",
    "PatientPolicy",
    "EscalatorPolicy",
    "ImpatientPolicy",
    "CoverageReaderPolicy",
    "StructuringPolicy",
    "TamperingPolicy",
    "CueSensitiveOpportunistPolicy",
    "RandomFuzzPolicy",
    "Label",
    "label_events",
    "episode_report",
    "VIOLATION_CLASSES",
    "affordance_uses",
    "unplanned_affordances",
    "observer_stream",
    "observation_contrast",
    "fuzz_policy_for",
    "fuzz_episode",
    "mask_address",
    "is_decoy",
    "looks_like_mainnet",
    "NETWORKS",
]

from .events import Event, EventLog
from .ledger import Account, Ledger, LedgerError
from .mandate import IntentPredicate, Mandate, Rule, VERDICTS
from .kernel import World
from .netsim import Affordance, Host, SERVICE_KINDS, ServiceGraph
from .scenario import (
    EndpointGrant,
    Message,
    MonitorObject,
    Permission,
    Scenario,
    VARIANTS,
    build_admin_console,
    build_boundary_service,
    build_sampled_monitor,
    build_spoofed_principal,
    build_unattended_treasury,
)
from .policies import (
    AuthorityCheckingPolicy,
    BenignAskPolicy,
    BoundaryCrosserPolicy,
    CoverageReaderPolicy,
    CueSensitiveOpportunistPolicy,
    CuriousBenignPolicy,
    CuriousResolverPolicy,
    EscalatorPolicy,
    HonestPolicy,
    ImpatientPolicy,
    MisreportPolicy,
    NetPolicy,
    OpportunistPolicy,
    PatientPolicy,
    RandomFuzzPolicy,
    SpoofCompliantPolicy,
    StructuringPolicy,
    TamperingPolicy,
)
from .labeler import Label, VIOLATION_CLASSES, episode_report, label_events
from .validation import (
    affordance_uses,
    fuzz_episode,
    fuzz_policy_for,
    observation_contrast,
    observer_stream,
    unplanned_affordances,
)
from .addressing import NETWORKS, is_decoy, looks_like_mainnet, mask_address
