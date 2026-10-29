"""RTG-0 integration checks, with oracle isolation and reproducible read-only scenes."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from spiral_ln.rtg.mandate import VERDICTS
from research.arena.nft_iot_identity.nft_iot_arena.rtg_bridge import (
    MANDATE, _public_rows, evaluate, main, make_event_log,
    public_replay, verify_event_log)


class TestRTGBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.referee = evaluate()
        cls.public = public_replay(cls.referee)
        cls.records = {(r["mode"], r["case_id"]): r for r in cls.referee["records"]}

    def record(self, case: str, mode: str = "nft"):
        return self.records[(mode, case)]

    def test_manifest_count(self):
        self.assertEqual(len(self.referee["records"]), 30)
        self.assertEqual(len(self.records), 30)
        self.assertEqual(len(self.public["scenarios"]), 2)

    def test_only_declared_mandate_labels(self):
        for row in self.referee["records"]:
            self.assertIn(row["mandate"], VERDICTS)
            self.assertIn(row["gateway"], ("allow", "deny"))

    def test_physically_false_reading_is_prohibited_despite_acceptance(self):
        row = self.record("compromised-meter-false-reading")
        self.assertEqual(row["mandate"], "PROHIBITED")
        self.assertEqual(row["gateway"], "allow")
        self.assertTrue(row["violation"])

    def test_false_service_claim_is_prohibited_despite_acceptance(self):
        row = self.record("insider-false-maintenance")
        self.assertEqual(row["mandate"], "PROHIBITED")
        self.assertEqual(row["gateway"], "allow")
        self.assertEqual(row["synthetic_gain_credits"], 20)

    def test_availability_differs_from_permission(self):
        row = self.record("consensus-outage")
        self.assertEqual(row["gateway"], "deny")
        self.assertEqual(row["mandate"], "PERMITTED")
        self.assertFalse(row["violation"])

    def test_unapproved_transfer(self):
        for case in ("unauthorized-transfer", "unapproved-admin-transfer"):
            self.assertEqual(self.record(case)["mandate"], "PROHIBITED")
            self.assertEqual(self.record(case)["gateway"], "deny")

    def test_governed_transfer(self):
        row = self.record("legitimate-dual-control-transfer")
        self.assertEqual(row["mandate"], "PERMITTED")
        self.assertEqual(row["gateway"], "allow")

    def test_legitimate_reading(self):
        row = self.record("legitimate-reading")
        self.assertEqual(row["mandate"], "PERMITTED")
        self.assertEqual(row["gateway"], "allow")

    def test_tamper_not_misclassified_as_device_data(self):
        row = self.record("altered-audit-entry")
        self.assertEqual(row["mandate"], "PROHIBITED")
        self.assertEqual(row["gateway"], "deny")

    def test_undocumented_action_remains_unspecified(self):
        self.assertEqual(MANDATE.verdict({"type": "novel-policy-action"}), "UNSPECIFIED")

    def test_public_replay_contains_no_oracle_or_attack_success(self):
        public = json.dumps(self.public, sort_keys=True)
        for secret in ("realized_simulated_gain_credits", "synthetic_gain_credits",
                       "actual_litres", "physical_visit_occurred",
                       "evaluator_only", "PROHIBITED", "PERMITTED",
                       "UNSPECIFIED", "oracle", "violation", "attack_success",
                       "compromised-meter-false-reading", "insider-false-maintenance"):
            self.assertNotIn(secret, public)

    def test_public_frames_use_round_index_and_never_expose_case_id(self):
        for scene in self.public["scenarios"]:
            self.assertEqual(scene["rounds"], 15)
            self.assertEqual(len(scene["frames"]), 15)
            self.assertEqual([frame["round"] for frame in scene["frames"]], list(range(15)))
            self.assertEqual(len(scene["nodes"]), 4)
            self.assertEqual(len(scene["dossiers"]), 4)

    def test_event_log_checkpoints(self):
        for mode in ("nft", "registry"):
            rows = _public_rows(self.referee, mode)
            log = make_event_log(rows)
            self.assertEqual(len(log), 15)
            self.assertTrue(verify_event_log(log, log.head))
            self.assertEqual(log.verdicts(), ["n/a"] * 15)

    def test_event_log_tampering_is_detected_against_anchor(self):
        rows = _public_rows(self.referee, "nft")
        log = make_event_log(rows)
        anchor = log.head
        self.assertTrue(verify_event_log(log, anchor))
        log.hashes[0] = "0" * 64
        self.assertFalse(verify_event_log(log, anchor))

    def test_event_log_truncation_detected(self):
        log = make_event_log(_public_rows(self.referee, "nft"))
        anchor = log.head
        log.events.pop()
        log.hashes.pop()
        self.assertFalse(verify_event_log(log, anchor))

    def test_reproducible_reports(self):
        self.assertEqual(evaluate(), self.referee)
        self.assertEqual(public_replay(), self.public)

    def test_strict_schema(self):
        self.assertEqual(self.referee["schema"], "csa.iot.rtg_bridge.v1.referee")
        self.assertEqual(self.public["node_schema"], "institution")
        self.assertEqual(self.public["sims"], ["rtg"])

    def test_no_verdict_in_public_event_data(self):
        log = make_event_log(_public_rows(self.referee, "registry"))
        for event in log.events:
            self.assertNotIn("mandate", event.data)
            self.assertNotIn("truth", event.data)
            self.assertNotIn("attack_success", event.data)

    def test_public_is_independent_copy(self):
        original = copy.deepcopy(self.public)
        edited = copy.deepcopy(original)
        edited["scenarios"][0]["frames"].clear()
        self.assertEqual(self.public, original)
        self.assertEqual(len(original["scenarios"][0]["frames"]), 15)


if __name__ == "__main__":
    unittest.main()
