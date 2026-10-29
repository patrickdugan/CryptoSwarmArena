"""Acceptance tests for the sealed forensic blue-team entry."""
import unittest
from spiral_ln.forensic_blue import Observation, evidence_digest, investigate, score


class ForensicBlueTests(unittest.TestCase):
    def test_two_independent_origins_support(self):
        events = [
            Observation("e1", "npc_a", "npc_b", "synthetic_transfer", "monitor_1", 1, True),
            Observation("e2", "npc_a", "npc_b", "synthetic_contact", "audit_2", 2),
        ]
        findings = investigate(events, evidence_digest(events))["findings"]
        self.assertEqual(findings[0]["decision"], "supported")
        self.assertEqual(score(findings, [("npc_a", "npc_b")])["recall"], 1.0)

    def test_copied_allegations_not_independent(self):
        events = [
            Observation("e1", "npc_a", "npc_b", "rumor", "same_source", 1),
            Observation("e2", "npc_a", "npc_b", "rumor_copy", "same_source", 2),
        ]
        self.assertEqual(investigate(events)["findings"][0]["decision"], "unresolved")

    def test_shared_host_is_not_attribution(self):
        events = [
            Observation("e1", "npc_a", "shared_host", "shared_infra", "inventory", 3),
            Observation("e2", "npc_b", "shared_host", "shared_infra", "inventory", 3),
        ]
        findings = investigate(events)["findings"]
        self.assertTrue(all(x["decision"] == "unresolved" for x in findings))

    def test_snapshot_integrity(self):
        events = [Observation("e1", "a", "b", "synthetic", "sensor", 0, True)]
        with self.assertRaises(ValueError):
            investigate(events, "bad_digest")

    def test_duplicate_evidence_rejected(self):
        events = [Observation("same", "a", "b", "synthetic", "sensor", 0),
                  Observation("same", "a", "c", "synthetic", "sensor", 1)]
        with self.assertRaises(ValueError):
            evidence_digest(events)

    def test_order_invariance(self):
        e = [Observation("e1", "a", "b", "x", "x", 0, True),
             Observation("e2", "a", "b", "y", "y", 1)]
        self.assertEqual(investigate(e), investigate(list(reversed(e))))

    def test_referee_kept_separate(self):
        e = [Observation("e1", "a", "b", "x", "x", 0, True)]
        self.assertNotIn("truth", str(investigate(e)))


if __name__ == "__main__":
    unittest.main()
