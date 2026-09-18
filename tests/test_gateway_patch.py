import copy
import unittest
from tools.apply_gateway_patch import patched_source
from tools.gateway_acceptance import EXTRA_ACTIONS, EXTRA_ENVELOPES, FAULTS, acceptance_status, negative_cases, strict_rejection


def rejection(phase):
    return {'phase': phase, 'process_listener_owned': True, 'gateway_error_code': 'AG_WIRE_INVALID_RESPONSE', 'http_status': 503, 'client_marker_visible': False,
            'counts': {'request': 1, 'response': 0 if phase == 'request' else 1,
                       'upstream': 0 if phase == 'request' else 1}, 'assertion_passed': True}


def passing_observations():
    controls = []
    for phase in ('request', 'response'):
        for action in ('allow', 'deny', 'mask'):
            row = rejection(phase)
            row['id'] = phase + '_' + action
            row['http_status'] = 403 if action == 'deny' else 200
            if action != 'deny':
                row.update(counts={'request': 1, 'response': 1, 'upstream': 1},
                           request_structure_preserved=True, response_structure_preserved=True,
                           upstream_received_marker=not (phase == 'request' and action == 'mask'),
                           client_marker_visible=phase == 'response' and action == 'allow')
            controls.append(row)
    rows = [dict(rejection(phase), id=c['id']) for c in negative_cases() for phase in c['phases']]
    faults = [dict(rejection(phase), id=fault) for phase in ('request', 'response') for fault in FAULTS]
    for fault in faults:
        fault['recovery'] = next(copy.deepcopy(c) for c in controls if c['id'] == fault['phase'] + '_allow')
        if fault['id'] == 'http_error':
            fault['gateway_error_code'] = 'AG_WIRE_HTTP_STATUS'
        if fault['id'] == 'timeout':
            fault['elapsed_ms'] = 10001
    return controls, rows, faults


class GatewayPatchTests(unittest.TestCase):
    def test_wrong_source_refuses_fuzzy_patch(self):
        with self.assertRaisesRegex(ValueError, 'UPSTREAM_WEBHOOK_MISMATCH'):
            patched_source(b'not pinned upstream code')

    def test_all_original_and_extra_fixtures_are_retained(self):
        cases = negative_cases()
        self.assertEqual(len(cases), 22 + len(EXTRA_ACTIONS) + len(EXTRA_ENVELOPES))
        self.assertEqual(len({c['id'] for c in cases}), len(cases))
        self.assertEqual(sum(len(c['phases']) for c in cases), 84)

    def test_empty_or_partial_results_never_pass(self):
        self.assertEqual(acceptance_status([], [], []), 'FAIL')
        c, r, f = passing_observations()
        self.assertEqual(acceptance_status(c[:-1], r, f), 'FAIL')
        self.assertEqual(acceptance_status(c, r[:-1], f), 'FAIL')
        self.assertEqual(acceptance_status(c, r, f[:-1]), 'FAIL')

    def test_failure_or_unknown_is_not_pass(self):
        controls, rows, faults = passing_observations()
        self.assertEqual(acceptance_status(controls, rows, faults), 'PASS')
        for v in (False, None, 1, 'PASS'):
            with self.subTest(value=v):
                changed = copy.deepcopy(rows)
                changed[0]['assertion_passed'] = v
                self.assertEqual(acceptance_status(controls, changed, faults), 'FAIL')

    def test_duplicate_or_substituted_case_cannot_supply_coverage(self):
        for group_index in range(3):
            for substitution in ('duplicate', 'new'):
                groups = list(passing_observations())
                group = groups[group_index]
                group[0] = copy.deepcopy(group[1]) if substitution == 'duplicate' else dict(group[0], id='wrong')
                self.assertEqual(acceptance_status(*groups), 'FAIL')

    def test_truthy_pass_flags_do_not_override_raw_upstream_observations(self):
        controls, rows, faults = passing_observations()
        rows[0]['counts']['upstream'] = 1
        self.assertEqual(acceptance_status(controls, rows, faults), 'FAIL')

    def test_mask_dropping_payload_still_fails_with_true_flag(self):
        controls, rows, faults = passing_observations()
        controls[2]['request_structure_preserved'] = False
        self.assertEqual(acceptance_status(controls, rows, faults), 'FAIL')

    def test_every_expected_phase_hook_must_be_observed(self):
        r = rejection('response')
        r['counts']['request'] = 0
        self.assertFalse(strict_rejection(r))

    def test_pipeline_exit_codes_are_not_hidden_by_tee(self):
        from test_workflow_shell import WORKFLOW, assert_shell_contract
        # Validate the real workflow; executable failure injection is in
        # test_workflow_shell, using this workflow's actual Python test step.
        self.assertTrue(assert_shell_contract(WORKFLOW.read_text()))
