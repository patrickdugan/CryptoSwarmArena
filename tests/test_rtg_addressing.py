from spiral_ln.rtg import (
    HonestPolicy,
    NETWORKS,
    World,
    build_unattended_treasury,
    is_decoy,
    looks_like_mainnet,
    mask_address,
)
from spiral_ln.rtg.scenario import AGENT, CAP_OPS, OPS, OWN


def test_masks_are_deterministic_and_network_shaped():
    a = mask_address("A0.own", "mainnet", seed=7)
    assert a == mask_address("A0.own", "mainnet", seed=7)
    assert a.startswith("bc1") and looks_like_mainnet(a)
    assert mask_address("A0.own", "testnet", 7).startswith("tb1")
    assert not looks_like_mainnet(mask_address("A0.own", "testnet", 7))


def test_every_mask_is_an_invalid_decoy():
    # Canary C1: masked addresses can never be a valid real-chain encoding.
    for network in NETWORKS:
        for account in ("P0.ops", "treasury", "A0.own"):
            assert is_decoy(mask_address(account, network, seed=3))


def test_decoy_predicate_is_not_vacuous():
    # is_decoy must return False on a genuinely valid bech32-charset body, else
    # the C1 canary would pass even if is_decoy returned True unconditionally.
    valid_body = "qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzr"  # all in-charset, one '1' separator
    assert not is_decoy(f"bc1{valid_body}")
    assert not is_decoy(f"tb1{valid_body}")
    # a stray intermediate '1' must not fool the separator logic
    assert not is_decoy("bc1qxy1z")


def test_framing_does_not_change_scripted_behavior():
    # The mainnet/testnet mask changes the view, but a scripted policy is
    # invariant to it (the H10 situational-awareness baseline).
    def run(mask):
        world = World(build_unattended_treasury("live", network_mask=mask), seed=9)
        world.run({AGENT: HonestPolicy(AGENT, CAP_OPS, OPS, OWN, 100)})
        return world

    assert run("mainnet").log.hashes == run("testnet").log.hashes


def test_view_exposes_network_and_masked_addresses():
    world = World(build_unattended_treasury("live", network_mask="mainnet"), seed=2)
    view = world.agent_view(AGENT)
    assert view["network"] == "mainnet"
    assert set(view["addresses"]) == set(view["balances"])
    assert all(addr.startswith("bc1") for addr in view["addresses"].values())
