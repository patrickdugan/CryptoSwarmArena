"""Regression and metamorphic tests for native forensic blue team."""
from dataclasses import replace
import unittest

from spiral_ln.forensic_blue import Observation, evidence_digest, investigate, score
from spiral_ln.forensic_casebook import EvidenceBroker, evaluate, fixtures, run_investigation, swarm_monitor_leads

class ForensicBlueTests(unittest.TestCase):
    def test_two_independent_origins_support(self):
        events = [Observation('e1','npc_a','npc_b','synthetic_transfer','monitor_1',1,True),
                  Observation('e2','npc_a','npc_b','synthetic_contact','audit_2',2)]
        findings = investigate(events,evidence_digest(events))['findings']
        self.assertEqual(findings[0]['decision'],'supported')
        self.assertEqual(score(findings,[('npc_a','npc_b')])['recall'],1.0)

    def test_copied_allegations_not_independent(self):
        events = [Observation('e1','npc_a','npc_b','rumor','same_source',1),
                  Observation('e2','npc_a','npc_b','rumor_copy','same_source',2)]
        self.assertEqual(investigate(events)['findings'][0]['decision'],'unresolved')

    def test_shared_host_is_not_attribution(self):
        events = [Observation('e1','npc_a','shared_host','shared_infra','inventory',3),
                  Observation('e2','npc_b','shared_host','shared_infra','inventory',3)]
        self.assertTrue(all(x['decision']=='unresolved' for x in investigate(events)['findings']))

    def test_snapshot_integrity(self):
        events = [Observation('e1','a','b','synthetic','sensor',0,True)]
        with self.assertRaises(ValueError): investigate(events,'bad_digest')

    def test_duplicate_evidence_rejected(self):
        events=[Observation('same','a','b','synthetic','sensor',0),
                Observation('same','a','c','synthetic','sensor',1)]
        with self.assertRaises(ValueError): evidence_digest(events)

    def test_order_invariance(self):
        events=[Observation('e1','a','b','x','x',0,True),
                Observation('e2','a','b','y','y',1)]
        self.assertEqual(investigate(events),investigate(events[::-1]))

    def test_referee_separation(self):
        e=[Observation('e1','a','b','x','x',0,True)]
        self.assertNotIn('truth',str(investigate(e)))

    def test_eighteen_cases(self):
        report=evaluate()
        self.assertEqual(report['cases'],18)
        self.assertEqual(report['contract_passes'],18)
        self.assertEqual(report['totals']['reviewed']['fp'],0)

    def test_cases_reproducible(self):
        self.assertEqual(evaluate(),evaluate())

    def test_copied_origin_registry(self):
        case,_=fixtures()[5]
        findings=run_investigation(case)['findings']
        self.assertEqual(findings[0]['independent_origins'],1)

    def test_temporal_separation(self):
        case,_=fixtures()[10]
        findings=run_investigation(case)['findings']
        self.assertEqual(len(findings),2)
        self.assertTrue(all(f['decision']=='unresolved' for f in findings))

    def test_revoked_source(self):
        case,_=fixtures()[16]
        result=run_investigation(case)
        self.assertEqual(result['findings'][0]['decision'],'unresolved')
        self.assertTrue(any(x.get('reason')=='revoked' for x in result['audit']))

    def test_query_budget(self):
        case,_=fixtures()[17]
        broker=EvidenceBroker(case)
        self.assertEqual(broker.query('unknown'),())
        self.assertEqual(broker.remaining,0)
        self.assertEqual(broker.query('s01'),())
        self.assertEqual(broker.audit[-1],{'status':'denied','reason':'budget_exhausted'})

    def test_synthetically_inert_annotations(self):
        case,_=fixtures()[11]
        original=run_investigation(case)['findings']
        changed=replace(case, observations=tuple(replace(o, kind='message_assertion') if o.kind=='message_assertion' else o for o in case.observations))
        self.assertEqual(original,run_investigation(changed)['findings'])

    def test_future_and_scope_cutoff(self):
        for case,_ in (fixtures()[8],fixtures()[9]):
            self.assertEqual(run_investigation(case)['findings'],[])

    def test_local_alert_is_weak(self):
        case,_=fixtures()[12]
        self.assertEqual(run_investigation(case)['findings'][0]['decision'],'unresolved')

    def test_unqualified_denial_does_not_veto(self):
        case,_=fixtures()[14]
        self.assertEqual(run_investigation(case)['findings'][0]['decision'],'supported')

    def test_qualified_conflict_blocks_support(self):
        case,_=fixtures()[6]
        self.assertEqual(run_investigation(case)['findings'][0]['decision'],'unresolved')

    def test_native_swarm_signal_adapter(self):
        from dataclasses import dataclass
        @dataclass(frozen=True)
        class ObservedSignal:
            round_index: int
            target: str
            vector: str
            flagged: bool
        signals = [ObservedSignal(4, "npc_02", "abstract", True),
                   ObservedSignal(3, "npc_01", "abstract", False)]
        self.assertEqual(swarm_monitor_leads(signals), [
            {"node":"npc_02","round":4,"kind":"local_alert","sensor":"arena_monitor"}
        ])

    def test_invalid_ticks(self):
        with self.assertRaises(ValueError): Observation('e','a','b','x','src',-1)
        with self.assertRaises(ValueError): Observation('e','a','b','x','src',True)
        with self.assertRaises(ValueError): Observation('e','a','b','x','src',10,False,at_tick=12,collected_tick=11)

if __name__=='__main__': unittest.main()
