import copy
import unittest
from tools.apply_gateway_patch import patched_source
from tools.gateway_acceptance import EXTRA_ACTIONS, EXTRA_ENVELOPES, FAULTS, acceptance_status, negative_cases


class GatewayPatchTests(unittest.TestCase):
    def test_wrong_source_refuses_fuzzy_patch(self):
        with self.assertRaisesRegex(ValueError, 'UPSTREAM_WEBHOOK_MISMATCH'):
            patched_source(b'not pinned upstream code')

    def test_all_original_and_extra_fixtures_are_retained(self):
        cases = negative_cases()
        self.assertEqual(len(cases), 22 + len(EXTRA_ACTIONS) + len(EXTRA_ENVELOPES))
        self.assertEqual(len({c['id'] for c in cases}), len(cases))
        self.assertEqual(sum(len(c['phases']) for c in cases), 74)

    def test_empty_or_partial_results_never_pass(self):
        self.assertEqual(acceptance_status([], [], [], 74), 'FAIL')
        self.assertEqual(acceptance_status([{'assertion_passed': True}] * 6, [], [], 74), 'FAIL')

    def test_failure_or_unknown_is_not_pass(self):
        controls = [{'assertion_passed': True} for _ in range(6)]
        rows = [{'id': str(i), 'phase': 'request', 'assertion_passed': True} for i in range(74)]
        faults = [{'assertion_passed': True} for _ in range(len(FAULTS) * 2)]
        self.assertEqual(acceptance_status(controls, rows, faults, 74), 'PASS')
        for v in (False, None, 1, 'PASS'):
            with self.subTest(value=v):
                changed = copy.deepcopy(rows)
                changed[0]['assertion_passed'] = v
                self.assertEqual(acceptance_status(controls, changed, faults, 74), 'FAIL')

    def test_duplicate_case_rows_do_not_supply_coverage(self):
        rows = [{'id': 'same', 'phase': 'request', 'assertion_passed': True}] * 74
        self.assertEqual(acceptance_status([{'assertion_passed': True}] * 6, rows,
                         [{'assertion_passed': True}] * 8, 74), 'FAIL')
