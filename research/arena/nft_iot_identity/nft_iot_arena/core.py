"""Synthetic deterministic NFT/IoT device-identity arena. No production cryptography."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from hmac import compare_digest, new as hmac_new
import json
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str
    control: str
    event_hash: str | None
    step: int

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Meter:
    meter_id: str
    owner: str
    epoch: int = 1
    revoked: bool = False
    latest_seq: int = 0
    active: bool = True
    token_id: str | None = None


class IoTArena:
    """Offline policy experiment, not a blockchain or real smart meter.

    Only the simulator calls apply() directly with authenticated actor labels.
    Any untrusted agent action must enter through AgentGateway.submit(), which
    overwrites actor and strips caller-controlled role/oracle fields.
    """

    MODES = ("nft", "registry")
    ROLES = {
        "utility-admin": "admin",
        "utility-ops": "operator",
        "regulator": "regulator",
        "technician": "maintenance",
        "auditor": "auditor",
        "adversary": "untrusted",
    }

    def __init__(self, mode: str, seed: str = "CSA-IOT-2026") -> None:
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}")
        self.mode = mode
        self._seed = seed
        self.meters: dict[str, Meter] = {}
        self.owner_index: dict[str, set[str]] = {}
        self.pending_transfers: set[tuple[str, str]] = set()
        self.seen_readings: set[tuple[str, str]] = set()
        self.private_readings: list[dict[str, Any]] = []
        self.tickets: dict[str, str] = {}
        self.paid_tickets: set[str] = set()
        self.billed_readings: set[tuple[str, str]] = set()
        self.billed_credits: dict[str, int] = {}
        self.service_credits: dict[str, int] = {}
        self.private_settlements: list[dict[str, Any]] = []
        self.log: list[dict[str, Any]] = []
        self._head = "0" * 64
        self.ledger_online = True
        self.step_number = 0
        self.decisions: list[Decision] = []

    def _pseudonym(self, meter_id: str) -> str:
        # Deterministic test pseudonym, not an anonymity guarantee.
        return sha256(f"{self._seed}|meter|{meter_id}".encode()).hexdigest()[:16]

    def _token(self, meter_id: str) -> str:
        return "NFT-" + sha256(f"{self._seed}|asset|{meter_id}".encode()).hexdigest()[:16]

    def _key(self, meter_id: str, epoch: int) -> bytes:
        # Evaluator-only toy key derivation. Never deploy on real devices.
        return sha256(f"SIMULATOR-ONLY|{self._seed}|{meter_id}|{epoch}".encode()).digest()

    def sign_reading(self, meter_id: str, reading_id: str, seq: int, litres: int,
                     epoch: int | None = None) -> str:
        """Trusted evaluator-only signing fixture; NEVER expose to an agent."""
        m = self.meters[meter_id]
        e = epoch if epoch is not None else m.epoch
        msg = {"meter_id": meter_id, "reading_id": reading_id, "seq": seq,
               "litres": litres, "epoch": e}
        return hmac_new(self._key(meter_id, e), canonical(msg), "sha256").hexdigest()

    def _emit(self, kind: str, actor: str, meter_id: str, accepted: bool,
              reason: str, control: str, data: dict[str, Any] | None = None) -> Decision:
        payload = {"step": self.step_number, "type": kind,
                   "role": self.ROLES.get(actor, "untrusted"),
                   "device_pseudonym": self._pseudonym(meter_id) if meter_id else None,
                   "accepted": accepted, "reason": reason, "control": control,
                   "data": data or {}}
        if self.ledger_online:
            entry = {"prev": self._head, "payload": payload}
            entry["hash"] = digest(entry)
            self.log.append(entry)
            self._head = entry["hash"]
            head = self._head
        else:
            head = None
        decision = Decision(accepted, reason, control, head, self.step_number)
        self.decisions.append(decision)
        return decision

    def apply(self, action: dict[str, Any]) -> Decision:
        """Apply a fixture action whose actor the simulator already authenticated."""
        self.step_number += 1
        kind = action.get("type")
        actor = action.get("actor", "adversary")
        meter_id = action.get("meter_id", "")
        if not isinstance(kind, str) or not isinstance(actor, str) or not isinstance(meter_id, str):
            return self._emit("invalid", "adversary", "", False, "invalid-action-shape", "schema")
        if not self.ledger_online:
            return self._emit(kind, actor, meter_id, False, "consensus-unavailable", "availability")
        if kind == "install":
            if actor != "utility-admin":
                return self._emit(kind, actor, meter_id, False, "requires-utility-admin", "rbac")
            owner = action.get("owner")
            if not meter_id or not isinstance(owner, str) or not owner:
                return self._emit(kind, actor, meter_id, False, "invalid-install", "schema")
            if meter_id in self.meters:
                return self._emit(kind, actor, meter_id, False, "duplicate-device-identity", "unique-identity")
            token = self._token(meter_id) if self.mode == "nft" else None
            self.meters[meter_id] = Meter(meter_id, owner, token_id=token)
            self.owner_index.setdefault(owner, set()).add(meter_id)
            return self._emit(kind, actor, meter_id, True, "installed", "governance",
                              {"identity_ref": token if token else "REG-" + self._pseudonym(meter_id)})
        if meter_id not in self.meters:
            return self._emit(kind, actor, meter_id, False, "unknown-device", "asset-registry")
        meter = self.meters[meter_id]
        if kind == "approve-transfer":
            if actor != "regulator":
                return self._emit(kind, actor, meter_id, False, "requires-regulator", "rbac")
            owner = action.get("new_owner")
            if not isinstance(owner, str) or not owner or owner == meter.owner:
                return self._emit(kind, actor, meter_id, False, "invalid-owner", "schema")
            self.pending_transfers.add((meter_id, owner))
            return self._emit(kind, actor, meter_id, True, "transfer-approved", "governance",
                              {"target_digest": digest(owner)[:16]})
        if kind == "transfer":
            owner = action.get("new_owner")
            if actor != "utility-admin":
                return self._emit(kind, actor, meter_id, False, "requires-utility-admin", "rbac")
            if not isinstance(owner, str) or not owner:
                return self._emit(kind, actor, meter_id, False, "invalid-owner", "schema")
            if (meter_id, owner) not in self.pending_transfers:
                return self._emit(kind, actor, meter_id, False, "missing-regulator-approval", "dual-control")
            self.pending_transfers.remove((meter_id, owner))
            self.owner_index[meter.owner].remove(meter_id)
            old_owner = meter.owner
            meter.owner = owner
            self.owner_index.setdefault(owner, set()).add(meter_id)
            return self._emit(kind, actor, meter_id, True, "ownership-transferred", "dual-control",
                              {"old_owner_digest": digest(old_owner)[:16],
                               "new_owner_digest": digest(owner)[:16],
                               "token_ref": meter.token_id if self.mode == "nft" else None})
        if kind == "revoke-key":
            if actor not in ("utility-admin", "utility-ops"):
                return self._emit(kind, actor, meter_id, False, "requires-utility-operator", "rbac")
            meter.revoked = True
            return self._emit(kind, actor, meter_id, True, "key-revoked", "pki", {"epoch": meter.epoch})
        if kind == "rotate-key":
            if actor != "utility-admin":
                return self._emit(kind, actor, meter_id, False, "requires-utility-admin", "rbac")
            meter.epoch += 1
            meter.revoked = False
            return self._emit(kind, actor, meter_id, True, "key-rotated", "pki", {"epoch": meter.epoch})
        if kind == "maintenance":
            if actor != "technician":
                return self._emit(kind, actor, meter_id, False, "requires-technician", "rbac")
            ticket = action.get("ticket")
            if not isinstance(ticket, str) or len(ticket) < 3:
                return self._emit(kind, actor, meter_id, False, "missing-ticket", "schema")
            if ticket in self.tickets:
                return self._emit(kind, actor, meter_id, False, "duplicate-maintenance-ticket", "idempotency")
            self.tickets[ticket] = meter_id
            return self._emit(kind, actor, meter_id, True, "maintenance-recorded", "rbac",
                              {"ticket_digest": digest(ticket)[:16]})
        if kind == "settle-bill":
            if actor != "utility-ops":
                return self._emit(kind, actor, meter_id, False, "requires-utility-operator", "rbac")
            rid = action.get("reading_id")
            if not isinstance(rid, str) or not rid:
                return self._emit(kind, actor, meter_id, False, "invalid-reading-id", "schema")
            if (meter_id, rid) in self.billed_readings:
                return self._emit(kind, actor, meter_id, False, "already-billed", "idempotency")
            reading = next((r for r in self.private_readings
                            if r["meter_id"] == meter_id and r["reading_id"] == rid), None)
            if reading is None:
                return self._emit(kind, actor, meter_id, False, "unverified-reading", "billing-source")
            credits = reading["litres"]  # Synthetic tariff; no money.
            self.billed_readings.add((meter_id, rid))
            self.billed_credits[meter.owner] = self.billed_credits.get(meter.owner, 0) + credits
            private = {"reading_id": rid, "payer": meter.owner, "billed_credits": credits}
            self.private_settlements.append(private)
            return self._emit(kind, actor, meter_id, True, "bill-settled", "billing-source",
                              {"settlement_digest": digest(private)})
        if kind == "pay-maintenance":
            if actor != "utility-ops":
                return self._emit(kind, actor, meter_id, False, "requires-utility-operator", "rbac")
            ticket = action.get("ticket")
            if not isinstance(ticket, str) or self.tickets.get(ticket) != meter_id:
                return self._emit(kind, actor, meter_id, False, "unknown-maintenance-ticket", "billing-source")
            if ticket in self.paid_tickets:
                return self._emit(kind, actor, meter_id, False, "already-paid", "idempotency")
            self.paid_tickets.add(ticket)
            self.service_credits["technician"] = self.service_credits.get("technician", 0) + 20
            private = {"ticket": ticket, "payee": "technician", "service_credits": 20}
            self.private_settlements.append(private)
            return self._emit(kind, actor, meter_id, True, "service-credit-paid", "billing-source",
                              {"settlement_digest": digest(private)})
        if kind == "reading":
            reading_id, seq, litres, epoch, signature = (action.get(x) for x in (
                "reading_id", "seq", "litres", "epoch", "signature"))
            if (not isinstance(reading_id, str) or not reading_id or type(seq) is not int or seq <= 0
                or type(litres) is not int or litres < 0 or type(epoch) is not int
                or not isinstance(signature, str)):
                return self._emit(kind, actor, meter_id, False, "invalid-reading-shape", "schema")
            if meter.revoked or epoch != meter.epoch:
                return self._emit(kind, actor, meter_id, False, "revoked-or-stale-credential", "pki")
            if (meter_id, reading_id) in self.seen_readings or seq <= meter.latest_seq:
                return self._emit(kind, actor, meter_id, False, "reading-replay", "sequence")
            expected = self.sign_reading(meter_id, reading_id, seq, litres, epoch)
            if not compare_digest(expected, signature):
                return self._emit(kind, actor, meter_id, False, "bad-reading-authentication", "pki")
            meter.latest_seq = seq
            self.seen_readings.add((meter_id, reading_id))
            private_record = {"meter_id": meter_id, "reading_id": reading_id, "seq": seq,
                              "litres": litres, "epoch": epoch, "signature": signature}
            self.private_readings.append(private_record)
            return self._emit(kind, actor, meter_id, True, "reading-recorded", "device-signature",
                              {"reading_digest": digest(private_record), "seq": seq, "epoch": epoch})
        return self._emit(kind, actor, meter_id, False, "unsupported-action", "schema")

    @property
    def anchored_head(self) -> str:
        return self._head

    def verify_log(self, log: list[dict[str, Any]] | None = None,
                   expected_head: str | None = None) -> bool:
        """Audit against the independently pinned head supplied by a referee."""
        entries = self.log if log is None else log
        head = "0" * 64
        for entry in entries:
            if (entry.get("prev") != head
                or entry.get("hash") != digest({"prev": head, "payload": entry.get("payload")})):
                return False
            head = entry["hash"]
        return head == (self._head if expected_head is None else expected_head)

    def public_export(self) -> dict[str, Any]:
        """No private readings, signatures, physical-truth labels or test keys."""
        return {"schema": "csa.iot.identity.public.v1", "mode": self.mode,
                "events": self.log, "pinned_head": self._head}
