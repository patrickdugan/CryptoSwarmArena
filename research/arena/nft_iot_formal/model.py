"""Offline finite-state NFT versus signed-registry identity equivalence experiment.

This models policy outcomes only: authenticated action labels stand in for real
cryptographic verification. Physical readings, keys, payments and identities
are synthetic. Permissioned consensus and deployment performance are out of scope.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import product
from json import dumps
from typing import Iterable

ARMS = ('registry', 'nft', 'nft_owner_only_ablation')


def digest(obj: object) -> str:
    return sha256(dumps(obj, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class State:
    owner: str = 'utility-a'
    epoch: int = 1
    sequence: int = 0
    last_tick: int = 0
    active: bool = True
    online: bool = True
    token: str | None = None
    ledger_head: str = '0' * 64
    event_count: int = 0


@dataclass(frozen=True)
class Action:
    kind: str
    actor: str = 'attacker'
    approved_by_utility: bool = False
    approved_by_regulator: bool = False
    approved_by_owner: bool = False
    next_owner: str = 'attacker'
    signed: bool = False
    epoch: int = 1
    sequence: int = 1
    tick: int = 1
    claimed_volume: int = 100
    physical_volume: int = 100


@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: str
    oracle_violation: bool = False


def genesis(arm: str) -> State:
    if arm not in ARMS:
        raise ValueError('unknown identity arm')
    token = 'NFT-' + digest({'meter': 'M-1', 'salt': 'fixture'})[:16] if arm.startswith('nft') else None
    return State(token=token)


def projection(state: State) -> tuple:
    """Equivalence relation erases *only* the asset's token identifier."""
    return (state.owner, state.epoch, state.sequence, state.last_tick,
            state.active, state.online, state.ledger_head,
            state.event_count)


def step(state: State, action: Action, arm: str) -> tuple[State, Verdict]:
    """Matched policy with an intentional owner-only-transfer ablation.

    Only accepted lifecycle transitions append to the synthetic anchored log.
    A valid signature is an explicit fixture capability, not a real signature.
    """
    if arm not in ARMS:
        raise ValueError('unknown identity arm')
    if action.kind == 'outage':
        return replace(state, online=False), Verdict(True, 'service-offline')
    if action.kind == 'restore':
        return replace(state, online=True), Verdict(True, 'service-restored')
    if not state.online:
        return state, Verdict(False, 'service-unavailable')
    accepted = False
    reason = 'unknown-action'
    violation = False
    updated = state
    if action.kind == 'transfer':
        owner_ok = action.approved_by_owner
        governed = action.approved_by_utility and action.approved_by_regulator
        approved = owner_ok and (governed or arm == 'nft_owner_only_ablation')
        if not action.next_owner or action.next_owner == state.owner:
            reason = 'invalid-owner'
        elif approved:
            updated = replace(state, owner=action.next_owner)
            accepted, reason = True, 'owner-transferred'
            violation = not governed
        else:
            reason = 'transfer-requires-owner-utility-regulator'
    elif action.kind == 'rotate':
        if action.approved_by_utility and action.approved_by_regulator:
            updated = replace(state, epoch=state.epoch + 1)
            accepted, reason = True, 'key-rotated'
        else:
            reason = 'rotation-requires-quorum'
    elif action.kind == 'retire':
        if action.approved_by_utility and action.approved_by_regulator:
            updated = replace(state, active=False)
            accepted, reason = True, 'device-retired'
        else:
            reason = 'retirement-requires-quorum'
    elif action.kind == 'reading':
        if not state.active:
            reason = 'retired-device'
        elif not action.signed or action.epoch != state.epoch:
            reason = 'invalid-or-stale-signature'
        elif action.sequence <= state.sequence or action.tick <= state.last_tick:
            reason = 'replay-or-nonmonotone-tick'
        elif action.claimed_volume < 0:
            reason = 'invalid-volume'
        else:
            updated = replace(state, sequence=action.sequence, last_tick=action.tick)
            accepted, reason = True, 'reading-accepted'
            violation = action.physical_volume != action.claimed_volume
    elif action.kind == 'audit':
        return state, Verdict(True, 'audit-readable')
    if accepted:
        # A normalized event excludes asset-ref decoration in both arms.
        event = dict(index=state.event_count, action=action.kind,
                     owner=updated.owner, epoch=updated.epoch,
                     sequence=updated.sequence, tick=updated.last_tick,
                     prior=state.ledger_head)
        updated = replace(updated, ledger_head=digest(event),
                          event_count=state.event_count + 1)
    return updated, Verdict(accepted, reason, violation)


def history(arm: str, actions: Iterable[Action]) -> tuple[State, tuple[Verdict, ...]]:
    state = genesis(arm)
    verdicts = []
    for action in actions:
        state, verdict = step(state, action, arm)
        verdicts.append(verdict)
    return state, tuple(verdicts)


def alphabet() -> tuple[Action, ...]:
    """Eight bounded test actions include positive and negative policy cases."""
    return (
        Action('audit'),
        Action('transfer', approved_by_owner=True),
        Action('transfer', approved_by_owner=True, approved_by_utility=True, approved_by_regulator=True),
        Action('rotate', approved_by_utility=True, approved_by_regulator=True),
        Action('reading', signed=True, sequence=1, tick=1),
        Action('reading', signed=False, sequence=1, tick=1),
        Action('outage'),
        Action('restore'),
    )


def bounded_check(depth: int = 4) -> dict:
    """Enumerate every ordered trace up to depth, including the empty trace."""
    if not isinstance(depth, int) or depth < 0 or depth > 5:
        raise ValueError('depth must be 0..5')
    ops = alphabet()
    histories = decisions = 0
    for size in range(depth + 1):
        for trace in product(ops, repeat=size):
            left, lv = history('registry', trace)
            right, rv = history('nft', trace)
            if projection(left) != projection(right) or lv != rv:
                raise AssertionError({'trace': [a.kind for a in trace], 'registry': lv, 'nft': rv})
            histories += 1
            decisions += size
    return {'equivalent': True, 'max_depth': depth,
            'histories': histories, 'decisions_compared': decisions,
            'alphabet_size': len(ops)}


def examples() -> dict:
    scenarios = {
        'unauthorized_transfer': [Action('transfer', approved_by_owner=True)],
        'authorized_transfer': [Action('transfer', approved_by_owner=True,
            approved_by_utility=True, approved_by_regulator=True)],
        'replay': [Action('reading', signed=True), Action('reading', signed=True)],
        'revoked_epoch': [Action('rotate', approved_by_utility=True,
            approved_by_regulator=True), Action('reading', signed=True)],
        'compromised_sensor_false_data': [Action('reading', signed=True, physical_volume=900)],
        'service_outage': [Action('outage'), Action('reading', signed=True)],
        'restored_service': [Action('outage'), Action('restore'), Action('reading', signed=True)],
    }
    rows = {}
    for name, actions in scenarios.items():
        rows[name] = {}
        for arm in ARMS:
            state, verdicts = history(arm, actions)
            rows[name][arm] = {'accepted': [v.accepted for v in verdicts],
                'reasons': [v.reason for v in verdicts],
                'oracle_violations': [v.oracle_violation for v in verdicts],
                'projection_digest': digest(projection(state))}
    return rows


def main() -> None:
    print(dumps({'schema': 'csa.nft_iot_formal.v1', 'bounded': bounded_check(),
                 'scenarios': examples()}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
