"""Account-based integer ledger for a valueless credit (tCR).

No key material exists: spending presents an opaque capability handle issued by
the harness, meaningless outside the process.  Value is conserved every tick
(sum of balances == genesis supply + mints).  Ownership and access are distinct:
the gateway decides whether a transfer *can* happen; the mandate oracle decides
whether it *may* (see mandate.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field


class LedgerError(Exception):
    pass


@dataclass
class Account:
    account_id: str
    owner: str
    balance: int
    authorized_spenders: tuple[str, ...] = ()


class Ledger:
    def __init__(self) -> None:
        self.accounts: dict[str, Account] = {}
        self.capabilities: dict[str, str] = {}  # handle -> account_id
        self.capability_provenance: dict[str, str] = {}  # handle -> provenance
        self.genesis_supply = 0
        self.minted = 0

    def open_account(self, account_id: str, owner: str, balance: int, spenders: tuple[str, ...] = ()) -> None:
        if account_id in self.accounts:
            raise LedgerError(f"account already exists: {account_id}")
        if int(balance) < 0:
            raise LedgerError("initial balance must be non-negative")
        self.accounts[account_id] = Account(account_id, owner, int(balance), tuple(spenders))
        self.genesis_supply += int(balance)

    def issue_capability(self, handle: str, account_id: str, provenance: str = "granted") -> None:
        if account_id not in self.accounts:
            raise LedgerError(f"capability for unknown account: {account_id}")
        self.capabilities[handle] = account_id
        self.capability_provenance[handle] = provenance

    def balance(self, account_id: str) -> int:
        return self.accounts[account_id].balance

    def owner(self, account_id: str) -> str | None:
        acct = self.accounts.get(account_id)
        return acct.owner if acct else None

    def transfer(self, capability: str | None, src: str, dst: str, amount: int) -> bool:
        """System-level (gateway) rules only: a valid capability over ``src``, a
        positive integer amount, both accounts present, and sufficient funds.
        Authorization (the mandate) is decided elsewhere."""

        if not isinstance(amount, int) or amount <= 0:
            return False
        if capability is not None and not isinstance(capability, str):
            return False  # a non-string handle can never match an issued capability
        if self.capabilities.get(capability) != src:
            return False
        if src not in self.accounts or dst not in self.accounts or src == dst:
            return False
        if self.accounts[src].balance < amount:
            return False
        self.accounts[src].balance -= amount
        self.accounts[dst].balance += amount
        return True

    def total(self) -> int:
        return sum(acct.balance for acct in self.accounts.values())

    def assert_conservation(self) -> None:
        if self.total() != self.genesis_supply + self.minted:
            raise LedgerError("value conservation violated")
