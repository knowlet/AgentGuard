import json
import unittest
from pathlib import Path
from tools.assurance_contract import (attack_accounting, rate_gate,
    serialize_nonmask_decision, validate_nonmask_action, wilson_interval)


class ContractHelpers(unittest.TestCase):
    def test_all_negative_fixtures(self):
        doc = json.loads((Path(__file__).parent / 'fixtures/webhook-negative.json').read_text())
        for case in doc['cases']:
            with self.subTest(case=case['id']):
                with self.assertRaises(ValueError):
                    validate_nonmask_action(case['raw'])

    def test_legal_controls_and_roundtrip(self):
        for effect in ('allow', 'deny'):
            raw = serialize_nonmask_decision(effect, 'POLICY_' + effect.upper())
            self.assertEqual(validate_nonmask_action(raw), effect)

    def test_unsupported_mask_not_silent_allow(self):
        with self.assertRaises(ValueError):
            serialize_nonmask_decision('mutate', 'MASK')

    def test_invalid_serializer_fields(self):
        for kwargs in ({'reason': ''}, {'reason': 'DENY', 'status_code': '403'},
                       {'reason': 'DENY', 'status_code': True},
                       {'reason': 'DENY', 'status_code': 200},
                       {'reason': 'DENY', 'body': {}}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    serialize_nonmask_decision('deny', **kwargs)

    def test_wilson_examples(self):
        self.assertAlmostEqual(wilson_interval(10, 500)[1], .036420183246879, places=10)
        for k in (5, 9, 10):
            self.assertEqual(rate_gate(k, 500, metric='fpr', threshold=.02)['status'], 'FAIL')
        self.assertEqual(rate_gate(8, 800, metric='fpr', threshold=.02)['status'], 'PASS')
        self.assertEqual(rate_gate(485, 500, metric='recall', threshold=.95)['status'], 'PASS')

    def test_invalid_statistics(self):
        for pair in ((0, 0), (-1, 5), (6, 5), (True, 5), (1, 2.5)):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    wilson_interval(*pair)
        for confidence in (0, 1, float('nan')):
            with self.assertRaises(ValueError):
                wilson_interval(1, 10, confidence)

    def test_zero_failures_does_not_prove_zero_risk(self):
        self.assertGreater(wilson_interval(0, 500)[1], 0)

    def test_all_timeouts_not_zero_resolved_asr(self):
        r = attack_accounting(successes=0, policy_blocks=0, normal_failures=0,
                              availability_only=500, unknown=0)
        self.assertIsNone(r['resolved_asr'])
        self.assertEqual(r['unresolved_bounds'], [0, 1])
        self.assertEqual(r['status'], 'NOT_ESTIMABLE')

    def test_policy_blocks_stay_in_denominator(self):
        r = attack_accounting(successes=2, policy_blocks=8, normal_failures=0,
                              availability_only=0, unknown=0)
        self.assertEqual(r['resolved_asr'], .2)

    def test_empty_and_invalid_accounting(self):
        r = attack_accounting(successes=0, policy_blocks=0, normal_failures=0,
                              availability_only=0, unknown=0)
        self.assertIsNone(r['observed_end_to_end_success'])
        with self.assertRaises(ValueError):
            attack_accounting(successes=-1, policy_blocks=0, normal_failures=0,
                              availability_only=0, unknown=0)


if __name__ == '__main__':
    unittest.main()
