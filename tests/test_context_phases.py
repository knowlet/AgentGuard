"""Synthetic evaluator controls plus real HTTP adapter tests; not Gateway E2E."""
import copy
import json
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen
from tools import context_probe as probe
from tools.context_probe import cases, case_passes, context_status, context_fixture, EXPECTED_CONTEXT


def observation(case):
    request_allowed = case['allow'] or case.get('mapping_phase') == 'response'
    decisions = []
    for phase in (('request', 'response') if request_allowed else ('request',)):
        allowed = request_allowed if phase == 'request' else case['allow']
        decisions.append({'phase': phase, 'allow': allowed,
                          'reason': 'CONTEXT_ALLOW' if allowed else case['reason'],
                          'context': dict(EXPECTED_CONTEXT) if allowed else {}})
    return {'id': case['id'], 'counts': {'request': 1, 'response': int(request_allowed), 'upstream': int(request_allowed)},
            'http_status': 200 if case['allow'] else 403, 'process_listener_owned': True,
            'preflight_rejected': bool(case.get('mapping_failure')), 'observations': decisions,
            'client_marker_visible': case['allow'], 'request_structure_preserved': request_allowed,
            'response_structure_preserved': case['allow'], 'assertion_passed': True}


class ContextPhases(unittest.TestCase):
    def test_both_phases_and_each_mapping_failure_are_registered(self):
        registered = cases()
        self.assertEqual(len(registered), 37)
        self.assertEqual(len({c['id'] for c in registered}), 37)
        for phase in ('request', 'response'):
            self.assertEqual(sum(c.get('mapping_phase') == phase for c in registered), 16)
        self.assertEqual(context_status([observation(c) for c in registered]), 'PASS')

    def test_phase_fault_config_does_not_alias_the_other_phase(self):
        from tools.context_probe import context_config
        from agentguard.context import HEADER_EXPRESSIONS
        for phase in ('request', 'response'):
            case = next(c for c in cases() if c.get('mapping_phase') == phase
                        and c.get('mapping_failure') == 'missing')
            hooks = context_config(1234, 4321, case)['binds'][0]['listeners'][0]['routes'][0]['policies']['ai']['promptGuard']
            other = 'response' if phase == 'request' else 'request'
            self.assertEqual(hooks[other][0]['webhook']['headers'], HEADER_EXPRESSIONS)
            self.assertNotIn(case['header'], hooks[phase][0]['webhook']['headers'])

    def test_reduced_suite_cannot_be_its_own_oracle(self):
        rows = [observation(c) for c in cases()]
        self.assertEqual(context_status(rows), 'PASS')
        # Even if the generator is shortened to match the rows it produced, the
        # gate stays bound to the frozen registry and must report FAIL.
        with patch.object(probe, 'cases', return_value=cases()[:-1]):
            self.assertEqual(probe.context_status(rows[:-1]), 'FAIL')
            self.assertEqual(probe.context_status(rows), 'FAIL')

    def test_mapping_contract_change_is_rejected_before_running(self):
        with patch.object(probe, 'EXPECTED_MAPPING_HEADERS', probe.EXPECTED_MAPPING_HEADERS[:-1]):
            with self.assertRaisesRegex(ValueError, 'CONTEXT_MAPPING_CHANGED'):
                probe.cases()
        dropped = {k: v for k, v in probe.HEADER_EXPRESSIONS.items() if k != 'x-ag-requested-model'}
        with patch.object(probe, 'HEADER_EXPRESSIONS', dropped):
            with self.assertRaisesRegex(ValueError, 'CONTEXT_MAPPING_CHANGED'):
                probe.cases()

    def test_omitted_response_hook_never_passes_allowed_request(self):
        case = cases()[0]; row = observation(case)
        row['observations'].pop(); row['counts']['response'] = 0
        self.assertFalse(case_passes(row, case))

    def test_response_context_must_match_even_when_request_is_correct(self):
        case = cases()[0]
        for key in EXPECTED_CONTEXT:
            row = observation(case); del row['observations'][1]['context'][key]
            self.assertFalse(case_passes(row, case))
            row = observation(case); row['observations'][1]['context'][key] = 'spoofed'
            self.assertFalse(case_passes(row, case))

    def test_fault_in_response_requires_request_allow_and_response_deny(self):
        case = next(c for c in cases() if c.get('mapping_phase') == 'response')
        row = observation(case)
        self.assertTrue(case_passes(row, case))
        row['observations'][1]['allow'] = True
        self.assertFalse(case_passes(row, case))
        row = observation(case); row['counts']['upstream'] = 0
        self.assertFalse(case_passes(row, case))
        row = observation(case); row['client_marker_visible'] = True
        self.assertFalse(case_passes(row, case))

    def test_missing_duplicate_and_truthy_rows_rejected(self):
        rows = [observation(c) for c in cases()]
        self.assertEqual(context_status(rows[:-1]), 'FAIL')
        bad = copy.deepcopy(rows); bad[-1] = bad[0]
        self.assertEqual(context_status(bad), 'FAIL')
        bad = copy.deepcopy(rows); bad[0]['process_listener_owned'] = 1
        self.assertEqual(context_status(bad), 'FAIL')
        bad = copy.deepcopy(rows); bad[0]['observations'][1]['allow'] = 1
        self.assertEqual(context_status(bad), 'FAIL')

    def test_response_adapter_actually_denies_missing_context_over_http(self):
        with context_fixture() as (state, port):
            for phase in ('request', 'response'):
                req = Request(f'http://127.0.0.1:{port}/{phase}', data=b'{"body":{}}',
                              headers={'Content-Type': 'application/json'})
                with urlopen(req, timeout=3) as response:
                    doc = json.load(response)
                self.assertEqual(doc['action']['status_code'], 403)
                self.assertEqual(doc['action']['reason'], 'CONTEXT_UNAVAILABLE')
            self.assertEqual([r['phase'] for r in state.context_decisions], ['request', 'response'])

    def test_both_adapters_allow_valid_context(self):
        with context_fixture() as (state, port):
            for phase in ('request', 'response'):
                req = Request(f'http://127.0.0.1:{port}/{phase}', data=b'{"body":{}}',
                              headers=dict(EXPECTED_CONTEXT, **{'Content-Type': 'application/json'}))
                with urlopen(req, timeout=3) as response:
                    self.assertEqual(json.load(response), {'action': {'reason': 'CONTEXT_ALLOW'}})
            self.assertEqual(state.counts, {'request': 1, 'response': 1, 'upstream': 0})
