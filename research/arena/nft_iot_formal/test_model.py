"""Offline policy model tests; stdlib only."""
import unittest
from research.arena.nft_iot_formal.model import Action, ARMS, alphabet, bounded_check, examples, genesis, history, projection, step


class NFTFormalTests(unittest.TestCase):
    def test_bounded_equivalence(self):
        result = bounded_check(4)
        self.assertEqual(result['histories'], 4681)
        self.assertEqual(result['decisions_compared'], 18056)
        self.assertTrue(result['equivalent'])

    def test_alphabet_size(self):
        self.assertEqual(len(alphabet()), 8)

    def test_invalid_arm(self):
        with self.assertRaises(ValueError):
            genesis('unknown')

    def test_invalid_depth(self):
        for d in (-1, 6, 0.1):
            with self.subTest(d=d), self.assertRaises(ValueError):
                bounded_check(d)

    def test_token_is_stable_and_distinct(self):
        self.assertEqual(genesis('nft').token, genesis('nft').token)
        self.assertIsNone(genesis('registry').token)
        self.assertTrue(genesis('nft').token.startswith('NFT-'))

    def test_initial_projection_parity(self):
        self.assertEqual(projection(genesis('registry')), projection(genesis('nft')))

    def test_strong_transfer_policy(self):
        attack = Action('transfer', approved_by_owner=True)
        for arm in ARMS[:2]:
            state, verdicts = history(arm, [attack])
            self.assertEqual(state.owner, 'utility-a')
            self.assertFalse(verdicts[-1].accepted)

    def test_ablation_has_counterexample(self):
        attack = Action('transfer', approved_by_owner=True)
        state, verdicts = history('nft_owner_only_ablation', [attack])
        self.assertEqual(state.owner, 'attacker')
        self.assertTrue(verdicts[-1].oracle_violation)

    def test_valid_transfer(self):
        action = Action('transfer', approved_by_owner=True,
            approved_by_utility=True, approved_by_regulator=True)
        for arm in ARMS:
            state, verdicts = history(arm, [action])
            self.assertTrue(verdicts[-1].accepted)
            self.assertEqual(state.owner, 'attacker')

    def test_replay_rejected(self):
        state, verdicts = history('nft', [Action('reading', signed=True), Action('reading', signed=True)])
        self.assertEqual([v.accepted for v in verdicts], [True, False])
        self.assertEqual(state.event_count, 1)

    def test_stale_epoch_after_rotation(self):
        state, verdicts = history('registry', [Action('rotate', approved_by_utility=True,
            approved_by_regulator=True), Action('reading', signed=True, epoch=1)])
        self.assertEqual([v.accepted for v in verdicts], [True, False])
        self.assertEqual(state.epoch, 2)

    def test_compromised_sensor_blindspot(self):
        _, verdicts = history('nft', [Action('reading', signed=True, physical_volume=500)])
        self.assertTrue(verdicts[0].accepted)
        self.assertTrue(verdicts[0].oracle_violation)

    def test_outage_fails_closed(self):
        state, verdicts = history('registry', [Action('outage'), Action('reading', signed=True)])
        self.assertEqual([v.accepted for v in verdicts], [True, False])
        self.assertEqual(state.event_count, 0)

    def test_restoration(self):
        state, verdicts = history('nft', [Action('outage'), Action('restore'), Action('reading', signed=True)])
        self.assertTrue(verdicts[-1].accepted)
        self.assertTrue(state.online)

    def test_retire_and_rotate_need_quorum(self):
        for kind in ('retire', 'rotate'):
            for arm in ARMS[:2]:
                state, verdicts = history(arm, [Action(kind)])
                self.assertFalse(verdicts[-1].accepted)
                self.assertEqual(state.event_count, 0)

    def test_hashes_match_under_matched_policy(self):
        trace = list(alphabet())
        reg, rv = history('registry', trace)
        nft, nv = history('nft', trace)
        self.assertEqual(projection(reg), projection(nft))
        self.assertEqual(rv, nv)

    def test_reproducible_examples(self):
        self.assertEqual(examples(), examples())

    def test_negative_reading_rejected(self):
        _, verdicts = history('nft', [Action('reading', signed=True, claimed_volume=-1)])
        self.assertFalse(verdicts[0].accepted)

    def test_unknown_action_fails(self):
        _, verdicts = history('registry', [Action('fork-world')])
        self.assertFalse(verdicts[0].accepted)

    def test_projected_history_parity(self):
        for name, row in examples().items():
            with self.subTest(name=name):
                self.assertEqual(row['registry'], row['nft'])


if __name__ == '__main__':
    unittest.main()
