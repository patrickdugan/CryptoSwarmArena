"""NFT-IoT role, ledger, economics and scenario acceptance checks (29 tests)."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from research.arena.nft_iot_identity.nft_iot_arena.core import IoTArena, canonical
from research.arena.nft_iot_identity.nft_iot_arena.gateway import AgentGateway
from research.arena.nft_iot_identity.nft_iot_arena.runner import (
    cases_from_file, run_suite, save_suite, sealed_truth)


class TestIdentityPolicy(unittest.TestCase):
    def setUp(self):
        self.env = IoTArena("nft")
        self.env.apply({"type": "install", "actor": "utility-admin",
                        "meter_id": "M1", "owner": "alice"})

    def reading(self, rid="r1", seq=1, litres=33, epoch=1):
        return {"type": "reading", "actor": "gateway", "meter_id": "M1",
                "reading_id": rid, "seq": seq, "litres": litres, "epoch": epoch,
                "signature": self.env.sign_reading("M1", rid, seq, litres, epoch)}

    def test_unique_identity(self):
        token = self.env.meters["M1"].token_id
        self.assertTrue(token.startswith("NFT-"))
        decision = self.env.apply({"type": "install", "actor": "utility-admin",
                                   "meter_id": "M1", "owner": "mallory"})
        self.assertFalse(decision.accepted)
        self.assertEqual(self.env.meters["M1"].token_id, token)

    def test_signatures_and_replay(self):
        reading = self.reading()
        self.assertTrue(self.env.apply(reading).accepted)
        self.assertEqual(self.env.apply(reading).reason, "reading-replay")
        bad = self.reading("r2", 2, 55)
        bad["litres"] = 66
        self.assertEqual(self.env.apply(bad).reason, "bad-reading-authentication")
        self.assertEqual(len(self.env.private_readings), 1)

    def test_revocation_and_rotation(self):
        self.assertTrue(self.env.apply({"type": "revoke-key", "actor": "utility-ops",
                                        "meter_id": "M1"}).accepted)
        self.assertEqual(self.env.apply(self.reading()).reason, "revoked-or-stale-credential")
        self.assertTrue(self.env.apply({"type": "rotate-key", "actor": "utility-admin",
                                        "meter_id": "M1"}).accepted)
        self.assertEqual(self.env.apply(self.reading(epoch=1)).reason, "revoked-or-stale-credential")
        self.assertTrue(self.env.apply(self.reading(epoch=2)).accepted)

    def test_role_and_dual_control_transfer(self):
        request = {"type": "transfer", "actor": "utility-admin", "meter_id": "M1",
                   "new_owner": "bob"}
        self.assertEqual(self.env.apply(request).reason, "missing-regulator-approval")
        self.assertTrue(self.env.apply({"type": "approve-transfer", "actor": "regulator",
                                        "meter_id": "M1", "new_owner": "bob"}).accepted)
        self.assertTrue(self.env.apply(request).accepted)
        self.assertEqual(self.env.meters["M1"].owner, "bob")
        self.assertNotIn("M1", self.env.owner_index["alice"])
        self.assertEqual(self.env.apply(request).reason, "missing-regulator-approval")

    def test_compromised_meter_is_blind_spot(self):
        self.assertTrue(self.env.apply(self.reading(litres=999)).accepted)

    def test_independent_anchor_detects_tampering(self):
        head = self.env.anchored_head
        tampered = copy.deepcopy(self.env.log)
        tampered[0]["payload"]["data"]["identity_ref"] = "forged"
        self.assertFalse(self.env.verify_log(tampered, head))
        self.assertTrue(self.env.verify_log(expected_head=head))
        self.assertFalse(self.env.verify_log(self.env.log[:-1], head))

    def test_offchain_privacy_boundary(self):
        self.env.apply(self.reading(litres=123))
        exported = json.dumps(self.env.public_export())
        for forbidden in ('"litres"', '"signature"', '"owner"', '"meter_id"'):
            self.assertNotIn(forbidden, exported)
        self.assertEqual(self.env.private_readings[0]["litres"], 123)

    def test_outage_fails_closed_and_no_unanchored_append(self):
        before = len(self.env.log)
        self.env.ledger_online = False
        rejected = self.env.apply(self.reading())
        self.assertEqual(rejected.reason, "consensus-unavailable")
        self.assertIsNone(rejected.event_hash)
        self.assertEqual(len(self.env.log), before)

    def test_canonical_bytes_determinism(self):
        self.assertEqual(canonical({"b": 1, "a": 2}), canonical({"a": 2, "b": 1}))

    def test_registry_has_no_token_but_same_governance(self):
        reg = IoTArena("registry")
        self.assertTrue(reg.apply({"type": "install", "actor": "utility-admin",
                                   "meter_id": "M1", "owner": "alice"}).accepted)
        self.assertIsNone(reg.meters["M1"].token_id)
        self.assertEqual(reg.apply({"type": "transfer", "actor": "adversary",
                                    "meter_id": "M1", "new_owner": "mallory"}).reason,
                         "requires-utility-admin")

    def test_unhashable_transfer_owner_rejected_cleanly(self):
        decision = self.env.apply({"type": "transfer", "actor": "utility-admin",
                                   "meter_id": "M1", "new_owner": ["invalid", "actor"]})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "invalid-owner")

    def test_invalid_shapes_rejected(self):
        for action in ({"type": "reading", "actor": "gateway", "meter_id": "M1",
                        "seq": True},
                       {"type": "reading", "actor": "gateway", "meter_id": "M1",
                        "reading_id": "x", "seq": -1, "litres": 1, "epoch": 1,
                        "signature": ""},
                       {"type": 9, "meter_id": "M1"}):
            self.assertFalse(self.env.apply(action).accepted)


class TestEconomics(unittest.TestCase):
    def setUp(self):
        self.env = IoTArena("nft")
        self.env.apply({"type": "install", "actor": "utility-admin",
                        "meter_id": "M1", "owner": "alice"})

    def test_realized_bill_settlement_and_no_duplicate(self):
        action = {"type": "reading", "actor": "gateway", "meter_id": "M1",
                  "reading_id": "r1", "seq": 1, "litres": 100, "epoch": 1,
                  "signature": self.env.sign_reading("M1", "r1", 1, 100)}
        self.assertTrue(self.env.apply(action).accepted)
        bill = {"type": "settle-bill", "actor": "utility-ops",
                "meter_id": "M1", "reading_id": "r1"}
        self.assertTrue(self.env.apply(bill).accepted)
        self.assertEqual(self.env.billed_credits["alice"], 100)
        self.assertEqual(self.env.apply(bill).reason, "already-billed")

    def test_cannot_settle_unverified_or_unrecognized_reading(self):
        action = {"type": "settle-bill", "actor": "utility-ops",
                  "meter_id": "M1", "reading_id": "r1"}
        self.assertEqual(self.env.apply(action).reason, "unverified-reading")
        action["actor"] = "adversary"
        self.assertEqual(self.env.apply(action).reason, "requires-utility-operator")

    def test_authorized_fake_maintenance_carries_credit_risk(self):
        self.assertTrue(self.env.apply({"type": "maintenance", "actor": "technician",
                                        "meter_id": "M1", "ticket": "VISIT-1"}).accepted)
        pay = {"type": "pay-maintenance", "actor": "utility-ops",
               "meter_id": "M1", "ticket": "VISIT-1"}
        self.assertTrue(self.env.apply(pay).accepted)
        self.assertEqual(self.env.service_credits["technician"], 20)
        self.assertEqual(self.env.apply(pay).reason, "already-paid")

    def test_payment_private(self):
        self.env.apply({"type": "maintenance", "actor": "technician",
                        "meter_id": "M1", "ticket": "VISIT-1"})
        self.env.apply({"type": "pay-maintenance", "actor": "utility-ops",
                        "meter_id": "M1", "ticket": "VISIT-1"})
        public = str(self.env.public_export())
        self.assertNotIn("service_credits", public)
        self.assertNotIn("billed_credits", public)

    def test_attacks_gain_the_same_synthetic_credits(self):
        result = run_suite()
        for mode in IoTArena.MODES:
            traces = {t["case_id"]: t for t in result["traces"] if t["mode"] == mode}
            self.assertEqual(traces["compromised-meter-false-reading"]["result"]
                             ["realized_simulated_gain_credits"], 400)
            self.assertEqual(traces["insider-false-maintenance"]["result"]
                             ["realized_simulated_gain_credits"], 20)
            self.assertEqual(result["summary"][mode]
                             ["realized_simulated_attack_gain_credits"], 420)


class TestGateway(unittest.TestCase):
    def test_red_agent_cannot_claim_admin_session_role(self):
        arena = IoTArena("nft")
        gate = AgentGateway(arena)
        decision = gate.submit("red", {"type": "install", "meter_id": "M1",
                                        "owner": "attacker", "actor": "utility-admin",
                                        "claimed_role": "admin"})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "requires-utility-admin")
        self.assertNotIn("M1", arena.meters)

    def test_gateway_separates_oracle_and_device_secrets(self):
        arena = IoTArena("nft")
        gateway = AgentGateway(arena)
        self.assertTrue(gateway.submit("utility", {"type": "install",
                         "meter_id": "M1", "owner": "utility-a"}).accepted)
        exported = json.dumps(gateway.observable_state())
        for forbidden in ("private_readings", "evaluator_only", "seed", "key_epoch_secret"):
            self.assertNotIn(forbidden, exported)

    def test_unknown_session_fails(self):
        with self.assertRaises(PermissionError):
            AgentGateway(IoTArena("nft")).submit("invented", {"type": "install"})

    def test_explicit_empty_session_map_denies_everyone(self):
        with self.assertRaises(PermissionError):
            AgentGateway(IoTArena("nft"), sessions={}).submit("red", {"type": "install"})

    def test_catalog_oracle_split(self):
        cases = cases_from_file()
        oracle = sealed_truth()
        self.assertEqual(set(oracle), {c["id"] for c in cases})
        self.assertNotIn("actual_litres", json.dumps(cases))
        self.assertNotIn("expected_accept", json.dumps(cases))
        self.assertEqual(oracle["compromised-meter-false-reading"]
                         ["evaluator_only"]["actual_litres"], 500)


class TestRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_suite()

    def test_case_matrix(self):
        self.assertEqual(len(cases_from_file()), 15)
        self.assertEqual(len(self.result["traces"]), 30)
        for mode in IoTArena.MODES:
            self.assertEqual(self.result["summary"][mode]["cases"], 15)

    def test_parity_under_matched_controls(self):
        self.assertTrue(all(x["behavioral_parity"] for x in self.result["pairwise"]))

    def test_blind_spots_visible(self):
        for mode in IoTArena.MODES:
            for name in ("compromised-meter-false-reading", "insider-false-maintenance"):
                trace = next(x for x in self.result["traces"] if
                             x["mode"] == mode and x["case_id"] == name)
                self.assertTrue(trace["result"]["attack_success"])
                self.assertFalse(trace["result"]["defender_detected"])

    def test_audit_and_outage(self):
        for mode in IoTArena.MODES:
            tamper = next(x for x in self.result["traces"] if
                          x["mode"] == mode and x["case_id"] == "altered-audit-entry")
            self.assertTrue(tamper["result"]["defender_detected"])
            outage = next(x for x in self.result["traces"] if
                          x["mode"] == mode and x["case_id"] == "consensus-outage")
            self.assertTrue(outage["result"]["attack_success"])
            self.assertEqual(outage["result"]["reason"], "consensus-unavailable")

    def test_public_traces_do_not_leak_oracle_fields(self):
        traces = canonical(self.result["traces"]).decode()
        for forbidden in ("actual_litres", "physical_visit_occurred",
                          "evaluator_only", '"litres"', '"signature"'):
            self.assertNotIn(forbidden, traces)

    def test_jsonl_roundtrip(self):
        with TemporaryDirectory() as td:
            save_suite(self.result, Path(td))
            lines = (Path(td) / "traces.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 30)
            self.assertEqual(json.loads(lines[0])["schema"], "csa.iot.identity.trace.v1")
            saved = json.loads((Path(td) / "suite.json").read_text())
            self.assertEqual(saved["catalog_sha256"], self.result["catalog_sha256"])

    def test_deterministic(self):
        self.assertEqual(canonical(run_suite()), canonical(self.result))
