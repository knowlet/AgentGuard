"""Regression tests for the concrete inline comments on PR #1."""
import math
import unittest
from tools.assurance_contract import attack_accounting, rate_gate, summarize_trials, wilson_interval
from tools.plan_statistics import acceptable_errors, binomial_cdf, fixed_n_power, plan


class ReviewRegressions(unittest.TestCase):
    def test_confidence_adjacent_to_one_is_finite(self):
        lo, hi = wilson_interval(10, 500, math.nextafter(1.0, 0.0))
        self.assertTrue(0 <= lo < .02 < hi <= 1)

    def test_invalid_confidence_types_raise_value_error(self):
        for value in (True, False, None, '0.95', [], float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wilson_interval(1, 100, value)

    def test_invalid_threshold_types_are_rejected_consistently(self):
        for value in (True, False, None, '0.02', [], float('nan'), float('inf')):
            for fn in (lambda: rate_gate(0, 100, metric='fpr', threshold=value),
                       lambda: acceptable_errors(100, metric='fpr', threshold=value)):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    fn()

    def test_inclusive_threshold_boundaries(self):
        for metric, threshold, expected in [('fpr', 0, -1), ('fpr', 1, 100),
                                             ('recall', 0, 100), ('recall', 1, -1)]:
            self.assertEqual(acceptable_errors(100, metric=metric, threshold=threshold), expected)

    def test_boundary_plan_is_found_or_not_found_not_validation_error(self):
        for metric, threshold, expected in [('fpr', 0, 'NOT_FOUND'), ('fpr', 1, 'FOUND'),
                                            ('recall', 0, 'FOUND'), ('recall', 1, 'NOT_FOUND')]:
            result = plan(metric=metric, threshold=threshold, expected_rate=.5,
                          target_power=.8, min_groups=100, max_groups=200)
            self.assertEqual(result['status'], expected)

    def test_sub_epsilon_probability_does_not_break_complement(self):
        for p in (1e-20, math.nextafter(0.0, 1.0)):
            value = binomial_cdf(75, 100, p)
            self.assertAlmostEqual(value, 1.0, places=12)

    def test_small_recall_probability_does_not_round_into_invalid_cdf(self):
        self.assertEqual(fixed_n_power(100, metric='recall', threshold=0,
                                      expected_rate=1e-20)['passing_probability'], 1.0)
        self.assertEqual(fixed_n_power(100, metric='recall', threshold=1,
                                      expected_rate=1e-20)['passing_probability'], 0.0)

    def test_fault_after_success_counts_in_both_dimensions(self):
        result = summarize_trials([
            {'id': 'a', 'outcome': 'S', 'availability_fault': True},
            {'id': 'b', 'outcome': 'B', 'availability_fault': False},
        ])
        self.assertEqual(result['resolved_asr'], .5)
        self.assertEqual(result['availability_only_fraction'], 0)
        self.assertEqual(result['availability_fault_fraction'], .5)

    def test_missing_fault_evidence_never_means_zero(self):
        result = attack_accounting(successes=1, policy_blocks=0, normal_failures=0,
                                   availability_only=0, unknown=0)
        self.assertIsNone(result['availability_fault_fraction'])
        self.assertEqual(result['availability_evidence'], 'MISSING')

    def test_fault_count_consistency(self):
        for value in (-1, True, 0, 4):
            with self.subTest(value=value), self.assertRaises(ValueError):
                attack_accounting(successes=1, policy_blocks=0, normal_failures=0,
                                  availability_only=1, unknown=0, availability_faults=value)

    def test_all_successes_can_still_have_total_unavailability(self):
        result = summarize_trials([{'id': str(i), 'outcome': 'S', 'availability_fault': True}
                                   for i in range(10)])
        self.assertEqual(result['resolved_asr'], 1)
        self.assertEqual(result['availability_fault_fraction'], 1)

    def test_invalid_trial_records(self):
        invalid = [{'id': 'a', 'outcome': 'I', 'availability_fault': False},
                   {'id': 'a', 'outcome': 'S', 'availability_fault': 1},
                   {'id': 'a', 'outcome': []},
                   {'id': 'a', 'outcome': 'S', 'availability_fault': False, 'extra': 1}]
        for trial in invalid:
            with self.subTest(trial=trial), self.assertRaises(ValueError):
                summarize_trials([trial])
        trial = {'id': 'a', 'outcome': 'S', 'availability_fault': False}
        with self.assertRaises(ValueError):
            summarize_trials([trial, trial])

    def test_empty_trials_not_estimable(self):
        result = summarize_trials([])
        self.assertEqual(result['status'], 'NOT_ESTIMABLE')
        self.assertIsNone(result['availability_fault_fraction'])


if __name__ == '__main__':
    unittest.main()
