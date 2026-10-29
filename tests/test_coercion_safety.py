"""Regression tests for synthetic, metadata-only safety swarm."""
import unittest
from spiral_ln.coercion_safety import Evidence, SafetySwarm, simulate, evaluate, verify_audit, demo


def event(i, step, source, signal, verified=True, consented=True):
    return {"event_id": i, "step": step, "source_token": source,
            "signal": signal, "verified": verified, "consented": consented}


class SafetySwarmTest(unittest.TestCase):
    def test_two_independent_sources_escalate(self):
        output = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "isolation_concern"),
            event("2", 2, "b", "coercion_concern")]})
        self.assertEqual([a["action"] for a in output["actions"]],
                         ["offer_support", "request_human_review"])
        self.assertTrue(output["audit_valid"])

    def test_one_source_cannot_self_corroborate(self):
        output = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "isolation_concern"),
            event("2", 2, "a", "coercion_concern")]})
        self.assertEqual(output["actions"], [])

    def test_no_consent_quarantines(self):
        output = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "coercion_concern", consented=False)]})
        self.assertEqual(output["quarantined"], 1)
        self.assertEqual(output["actions"], [])

    def test_unverified_quarantines(self):
        output = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "immediate_danger", verified=False)]})
        self.assertEqual(output["actions"], [])

    def test_emergency_restricted(self):
        output = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "immediate_danger", consented=False)]})
        self.assertEqual([a["action"] for a in output["actions"]], ["request_human_review"])
        self.assertEqual(output["audit"][0]["reason"], "emergency_metadata_only")

    def test_replays(self):
        e = event("1", 1, "a", "neutral")
        output = simulate({"case_id": "x", "events": [e, e,
            {**e, "signal": "coercion_concern"}]})
        self.assertEqual(output["duplicates"], 1)
        self.assertEqual(output["conflicts"], 1)

    def test_bad_schema(self):
        for raw in (event("1", -1, "a", "neutral"),
                    {**event("1", 1, "a", "neutral"), "message": "private"},
                    event("1", 1, "a", "invented"),
                    {**event("1", 1, "a", "neutral"), "verified": 1}):
            with self.assertRaises(ValueError):
                Evidence.parse(raw)

    def test_audit_tamper(self):
        result = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "neutral")]})
        result["audit"][0]["reason"] = "modified"
        self.assertFalse(verify_audit(result["audit"]))

    def test_observe_only(self):
        result = simulate({"case_id": "x", "events": [
            event("1", 1, "a", "immediate_danger")]}, policy="observe_only")
        self.assertEqual([a["action"] for a in result["actions"]], ["offer_support"])

    def test_reproducibility(self):
        case = {"case_id": "x", "events": [event("1", 1, "a", "neutral")]}
        self.assertEqual(simulate(case), simulate(case))

    def test_oracle_is_sealed(self):
        c = {"case_id": "x", "events": [event("1", 1, "a", "neutral")],
             "oracle": {"review_required": False, "review_deadline": 2}}
        self.assertEqual(evaluate([c])["counts"]["tn"], 1)

    def test_demo(self):
        self.assertEqual(demo()["counts"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})


if __name__ == "__main__":
    unittest.main()
