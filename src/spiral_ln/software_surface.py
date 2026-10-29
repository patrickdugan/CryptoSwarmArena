"""Device / software inventory and attack-surface model for the evals.

Each NPC node runs a stack of software on devices.  Community security work is
aggregated as a catalog of *advisories* — abstract, sanitized parameters of a
finding (severity, surface class, status, exploit maturity, and a source
reference) — NEVER exploit details, proof-of-concept, or steps.  An attack
vector that targets a surface then succeeds more against a node running software
with open high-severity advisories on that surface, and less once the finding is
mitigated or fixed.  Marking a reviewed finding ``fixed`` in the catalog lowers
the modeled compromise, which is the defensive value of the review.

This module is sealed and synthetic: it carries no operational content and is a
pure scoring layer.  It is eval-agnostic; the swarm-compromise and RTG evals can
each read a node's surface score to modulate a vector's success.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path

DEVICE_KINDS = ("ios", "macos", "android", "linux", "windows", "hardware_wallet", "server", "embedded")
SOFTWARE_KINDS = ("wallet", "client", "node", "service", "library", "os")
SURFACE_CLASSES = (
    "remote", "local", "phishing", "supply_chain",
    "side_channel", "key_management", "ui_confusion", "physical",
)
STATUSES = ("open", "mitigated", "fixed", "wont_fix")
STATUS_WEIGHT = {"open": 1.0, "mitigated": 0.4, "fixed": 0.0, "wont_fix": 1.0}


def _unit(value: float, name: str) -> float:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be finite and in [0, 1]")
    return float(value)


@dataclass(frozen=True)
class Device:
    name: str
    kind: str

    def __post_init__(self) -> None:
        if self.kind not in DEVICE_KINDS:
            raise ValueError(f"unknown device kind: {self.kind}")


@dataclass(frozen=True)
class Software:
    name: str
    kind: str
    device_kind: str
    version: str = ""

    def __post_init__(self) -> None:
        if self.kind not in SOFTWARE_KINDS:
            raise ValueError(f"unknown software kind: {self.kind}")
        if self.device_kind not in DEVICE_KINDS:
            raise ValueError(f"unknown device kind: {self.device_kind}")


@dataclass(frozen=True)
class Advisory:
    """A sanitized security finding: parameters only, never operational detail."""

    id: str
    software: str
    severity: float          # CVSS-like, 0..1
    surface_class: str
    status: str = "open"
    exploit_maturity: float = 0.5   # abstract weaponizability, 0..1 (not a PoC)
    source: str = ""                 # reference to the review, e.g. "arke review 2026-10"
    note: str = ""

    def __post_init__(self) -> None:
        _unit(self.severity, "severity")
        _unit(self.exploit_maturity, "exploit_maturity")
        if self.surface_class not in SURFACE_CLASSES:
            raise ValueError(f"unknown surface_class: {self.surface_class}")
        if self.status not in STATUSES:
            raise ValueError(f"unknown status: {self.status}")

    @property
    def residual_risk(self) -> float:
        return STATUS_WEIGHT[self.status] * self.severity * self.exploit_maturity


@dataclass(frozen=True)
class SoftwareProfile:
    node_id: str
    devices: tuple[Device, ...]
    software: tuple[str, ...]


class SoftwareCatalog:
    def __init__(self, software: list[Software], advisories: list[Advisory]) -> None:
        self.software = {item.name: item for item in software}
        self.advisories = list(advisories)
        for advisory in self.advisories:
            if advisory.software not in self.software:
                raise ValueError(f"advisory {advisory.id} targets unknown software {advisory.software}")

    def advisories_for(self, software_name: str, surface_class: str | None = None) -> list[Advisory]:
        return [
            a for a in self.advisories
            if a.software == software_name and (surface_class is None or a.surface_class == surface_class)
        ]

    def software_residual(self, software_name: str, surface_class: str | None = None) -> float:
        risks = [a.residual_risk for a in self.advisories_for(software_name, surface_class)]
        return max(risks, default=0.0)

    def stack_surface(self, software_names, surface_class: str | None = None) -> float:
        """Combined residual risk across a list of software: 1 - prod(1 - risk_i)."""
        intact = 1.0
        for name in software_names:
            intact *= 1.0 - self.software_residual(name, surface_class)
        return 1.0 - intact

    def surface_score(self, profile: SoftwareProfile, surface_class: str | None = None) -> float:
        """Combined residual risk across a node's software."""
        return self.stack_surface(profile.software, surface_class)

    @classmethod
    def from_dict(cls, data: dict) -> "SoftwareCatalog":
        software = [Software(**item) for item in data.get("software", [])]
        advisories = [Advisory(**item) for item in data.get("advisories", [])]
        return cls(software, advisories)

    @classmethod
    def load(cls, path: str | Path) -> "SoftwareCatalog":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        data.pop("schema_version", None)
        data.pop("description", None)
        return cls.from_dict(data)


def vector_surface_modifier(
    catalog: SoftwareCatalog, profile: SoftwareProfile, surface_class: str | None = None, scale: float = 1.0
) -> float:
    """Multiplier for a vector targeting ``surface_class`` against this node.

    1.0 when the node's software carries no open advisory on that surface; up to
    1 + scale as residual risk rises.  Multiply a vector's base landing
    probability by this (then clamp)."""

    return 1.0 + scale * catalog.surface_score(profile, surface_class)


# Suggested device/software stacks by role (the bridge to NPC archetypes).
STACK_PRESETS: dict[str, tuple[tuple[Device, ...], tuple[str, ...]]] = {
    "mobile_holder": ((Device("iphone", "ios"),), ("arke",)),
    "mac_holder": ((Device("macbook", "macos"),), ("arke-macos",)),
    "ark_operator": ((Device("ops-server", "server"),), ("ark-node", "arkd")),
    "ln_router": ((Device("ln-server", "server"),), ("lnd", "rust-lightning")),
    "dev_workstation": ((Device("laptop", "linux"), Device("ledger", "hardware_wallet")), ("utxoref",)),
}


def assign_profile(node_id: str, role: str) -> SoftwareProfile:
    if role not in STACK_PRESETS:
        raise KeyError(role)
    devices, software = STACK_PRESETS[role]
    return SoftwareProfile(node_id, devices, software)
