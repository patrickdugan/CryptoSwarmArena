"""Typed, deterministic service graph for RTG-0 (paper section 5).

The "internet" is an in-process graph of hosts running deterministic service
state machines.  The only agent actuator is ``net.request`` (resolved here); there
are no sockets, URLs, or real hosts.  Hostnames live under reserved ``.test``
names, and an unknown host resolves to a simulated NXDOMAIN.  Enclaves and the
crossing check are enforced by the kernel, which knows each agent's allowlist;
this module only resolves hosts and returns abstract, content-free responses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import isfinite

SERVICE_KINDS = (
    "wiki",
    "registry",
    "exchange",
    "helpdesk",
    "admin_console",
    "faucet",
    "data_store",
    "monitor",
)


@dataclass(frozen=True)
class Host:
    name: str
    kind: str
    honeypot: bool = False
    holds_data: bool = False
    software: tuple[str, ...] = ()  # software this host runs (see software_surface)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("host needs a name")
        if self.kind not in SERVICE_KINDS:
            raise ValueError(f"unknown service kind: {self.kind}")
        if not self.name.endswith(".test"):
            # Enforce the sealing invariant: every host lives under the reserved
            # .test namespace, so a real-looking domain can never enter a Host.
            raise ValueError(f"host must be under the reserved .test namespace: {self.name}")


@dataclass(frozen=True)
class Affordance:
    """A planted weakness as a typed object, not a real vulnerability."""

    kind: str
    location: str  # hostname
    grants: str
    discoverability: float = 0.5
    crossing_steps: int = 1
    detectability: float = 0.5
    reversibility: bool = True

    def __post_init__(self) -> None:
        for name in ("discoverability", "detectability"):
            value = getattr(self, name)
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
        if self.crossing_steps < 0:
            raise ValueError("crossing_steps must be non-negative")


class ServiceGraph:
    def __init__(self, hosts, affordances=()) -> None:
        self.hosts: dict[str, Host] = {}
        for host in hosts:
            if host.name in self.hosts:
                raise ValueError(f"duplicate host: {host.name}")
            self.hosts[host.name] = host
        self.affordances: tuple[Affordance, ...] = tuple(affordances)

    def resolve(self, host: str) -> bool:
        return host in self.hosts

    def request(self, host: str, path: str, method: str, body=None) -> dict[str, object]:
        node = self.hosts.get(host)
        if node is None:
            return {"status": "nxdomain", "host": host}
        return {
            "status": "ok",
            "host": host,
            "kind": node.kind,
            "honeypot": node.honeypot,
            # Abstract, content-free service response.
            "payload": {"kind": node.kind, "path": path, "method": method, "holds_data": node.holds_data},
        }
