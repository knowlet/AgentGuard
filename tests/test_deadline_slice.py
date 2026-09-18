"""Budget declaration checks, frozen contract and the real loopback fixture.

Synthetic rows are evaluator unit tests; the HTTP tests exercise the fixture
itself. Neither is Gateway E2E.
"""
import copy
import json
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

from agentguard import deadline as budget
from tools import deadline_probe as probe

MARKERS = {'allow': [], 'guard_deadline_decision': ['guardrail_reject'],
           'gateway_timeout': ['timeout'], 'upstream_transport_fault': ['transport']}
WRITES = {'gateway_timeout': 'failed', 'upstream_transport_fault': 'not_attempted'}


def observation(case):
    """Rows that must PASS, built from the case's registered expectation."""
    expected_class = case.get('expected_class') or probe.EXPECTED_CLASS[case['outcome']]
    counts = probe.expected_counts(case)
    exceeded = budget.over_budget(case['stage_ms'])
    decisions = []
    for phase in ('request', 'response'):
        if counts[phase] == 0:
            continue
        slow = phase == case['phase']
        denied = slow and exceeded
        delivered = not (slow and expected_class in probe.AVAILABILITY_FAULTS)
        decisions.append({'phase': phase, 'stage_ms': case['stage_ms'] if slow else 0,
                          'allowed': not denied,
                          'reason': budget.GUARD_DEADLINE_EXCEEDED if denied else 'FIXTURE_ALLOW',
                          'delivered': delivered,
                          'decision_write': WRITES.get(expected_class, 'ok') if slow else 'ok'})
    fault = expected_class in probe.AVAILABILITY_FAULTS
    return {'id': case['id'], 'phase': case['phase'],
            'http_status': 200 if expected_class == 'allow' else 503,
            'counts': counts, 'elapsed_ms': 10000.0 if fault else 1000.0,
            'process_listener_owned': True,
            'client_marker_visible': expected_class == 'allow' and case['phase'] == 'response',
            'client_body_is_guard_denial': expected_class == 'guard_deadline_decision',
            'upstream_received_marker': counts['upstream'] == 1,
            'request_structure_preserved': counts['upstream'] == 1,
            'response_structure_preserved': expected_class == 'allow',
            'guard_decisions': decisions, 'assertion_passed': True,
            'gateway_markers': [m + ':' + case['phase'] for m in MARKERS[expected_class]],
            'gateway_http_status': 200 if expected_class == 'allow' else 503,
            'gateway_log_bytes': 512}


class BudgetDeclaration(unittest.TestCase):
    def test_declared_budget_fits_inside_the_effective_gateway_timeout(self):
        self.assertEqual(budget.DECLARED_GUARD_BUDGET_MS, 1500)
        total = budget.guard_budget_ms(budget.DECLARED_BUDGET_MS) + budget.TRANSPORT_RESERVE_MS + budget.SAFETY_MARGIN_MS
        self.assertLess(total, budget.GATEWAY_WEBHOOK_TIMEOUT_MS)
        self.assertEqual(budget.validate_budget(budget.DECLARED_BUDGET_MS, budget.TRANSPORT_RESERVE_MS,
                                                budget.SAFETY_MARGIN_MS), 1500)

    def test_over_budget_or_undersized_margin_is_rejected(self):
        over = dict(budget.DECLARED_BUDGET_MS)
        over['detector'] = budget.GATEWAY_WEBHOOK_TIMEOUT_MS
        for name, call, code in (
            ('over_budget', (over, budget.TRANSPORT_RESERVE_MS, budget.SAFETY_MARGIN_MS), 'BUDGET_EXCEEDED'),
            ('no_margin', (budget.DECLARED_BUDGET_MS, budget.TRANSPORT_RESERVE_MS, 0), 'MARGIN_TOO_SMALL'),
            ('no_reserve', (budget.DECLARED_BUDGET_MS, 0, budget.SAFETY_MARGIN_MS), 'RESERVE_INVALID'),
            ('stage_drift', ({'queue': 1, 'detector': 2}, budget.TRANSPORT_RESERVE_MS, budget.SAFETY_MARGIN_MS), 'STAGES_UNVERIFIED'),
            ('bool_stage', (dict(budget.DECLARED_BUDGET_MS, audit=True), budget.TRANSPORT_RESERVE_MS, budget.SAFETY_MARGIN_MS), 'STAGE_INVALID'),
            ('negative_stage', (dict(budget.DECLARED_BUDGET_MS, audit=-1), budget.TRANSPORT_RESERVE_MS, budget.SAFETY_MARGIN_MS), 'STAGE_INVALID'),
            ('no_timeout', (budget.DECLARED_BUDGET_MS, budget.TRANSPORT_RESERVE_MS, budget.SAFETY_MARGIN_MS, 2000), 'BUDGET_EXCEEDED'),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, code):
                    budget.validate_budget(*call)

    def test_boundary_is_strict_about_spending_the_budget(self):
        self.assertFalse(budget.over_budget(budget.DECLARED_GUARD_BUDGET_MS))
        self.assertTrue(budget.over_budget(budget.DECLARED_GUARD_BUDGET_MS + 1))
        with self.assertRaisesRegex(ValueError, 'STAGE_INVALID'):
            budget.over_budget(True)


class DeadlineEvidence(unittest.TestCase):
    def rows(self):
        return [observation(c) for c in probe.cases()]

    def index(self, rows):
        return {r['id']: i for i, r in enumerate(rows)}

    def test_registry_is_frozen_and_matches_the_boundary_contract(self):
        rows = probe.cases()
        self.assertEqual(len(rows), probe.EXPECTED_CASE_COUNT)
        self.assertEqual({c['id'] for c in rows}, probe.registered_ids())
        self.assertTrue(probe.contract_matches_pin())
        self.assertTrue(probe.registries_agree())
        classes = [c['expected_class'] for c in rows]
        self.assertEqual(classes.count('allow'), 3)
        self.assertEqual(classes.count('guard_deadline_decision'), 3)
        self.assertEqual(classes.count('gateway_timeout'), 2)
        self.assertEqual(classes.count('upstream_transport_fault'), 1)

    def test_contradictory_registered_case_is_rejected(self):
        broken = list(probe.REGISTERED_CASES)
        broken[3] = ('just_over_budget_request', 'request', 10, 'guard_deny')
        with patch.object(probe, 'REGISTERED_CASES', tuple(broken)):
            with self.assertRaisesRegex(ValueError, 'DEADLINE_CASE_INVALID'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.registered_cases()]), 'FAIL')

    def test_runner_registry_drift_is_refused(self):
        drifted = [list(case) for case in probe.REGISTERED_CASES]
        drifted[0][2] = 1300
        with patch.object(probe, 'REGISTERED_CASES', tuple(tuple(c) for c in drifted)):
            with self.assertRaisesRegex(ValueError, 'RUNNER_REGISTRY_MISMATCH'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.registered_cases()]), 'FAIL')

    def test_contract_digest_and_boundary_are_both_pinned(self):
        # Editing the gate's expectation without its digest is refused outright.
        broken = tuple(list(probe.EXPECTED_CONTRACT)[:3]
                       + [('just_over_budget_request', 'request', 10, 'guard_deadline_decision')]
                       + list(probe.EXPECTED_CONTRACT)[4:])
        with patch.object(probe, 'EXPECTED_CONTRACT', broken):
            with self.assertRaisesRegex(ValueError, 'CONTRACT_CHANGED'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.runner_cases()]), 'FAIL')
        # A contract whose boundary contradicts its expectation is refused even
        # when its digest is pinned correctly, so this reaches _validate_contract.
        with patch.object(probe, 'EXPECTED_CONTRACT', broken), \
             patch.object(probe, 'EXPECTED_CONTRACT_SHA256', probe.contract_digest(broken)):
            with self.assertRaisesRegex(ValueError, 'DEADLINE_CASE_INVALID'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.runner_cases()]), 'FAIL')

    def test_shrunk_or_replaced_suite_cannot_pass(self):
        rows = self.rows()
        self.assertEqual(probe.deadline_status(rows), 'PASS')
        self.assertEqual(probe.deadline_status(rows[:-1]), 'FAIL')
        duplicated = copy.deepcopy(rows)
        duplicated[-1] = duplicated[0]
        self.assertEqual(probe.deadline_status(duplicated), 'FAIL')
        with patch.object(probe, 'cases', return_value=probe.cases()[:-1]):
            self.assertEqual(probe.deadline_status(rows[:-1]), 'FAIL')

    def test_phase_contract_rejects_contradictory_decisions(self):
        """The three verifier false positives reported on head 3d7a5e8."""
        rows = self.rows()
        index = self.index(rows)
        # A response timeout whose preceding request allow was never delivered.
        bad = copy.deepcopy(rows)
        bad[index['unbounded_stage_timeout_response']]['guard_decisions'][0]['delivered'] = False
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # A response guard denial whose request hook already rejected.
        bad = copy.deepcopy(rows)
        bad[index['just_over_budget_response']]['guard_decisions'][0].update(
            allowed=False, reason='CONTEXT_UNAVAILABLE', delivered=True)
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # A request-only case that lost its response decision to a duplicate request.
        bad = copy.deepcopy(rows)
        bad[index['inside_budget_request']]['guard_decisions'][1]['phase'] = 'request'
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # Swapped phases, wrong slow phase, and a wrong write outcome.
        bad = copy.deepcopy(rows)
        bad[index['inside_budget_response']]['guard_decisions'] = list(reversed(
            bad[index['inside_budget_response']]['guard_decisions']))
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        bad = copy.deepcopy(rows)
        bad[index['over_budget_request']]['guard_decisions'][0]['stage_ms'] = 4001
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        bad = copy.deepcopy(rows)
        bad[index['unbounded_stage_timeout_request']]['guard_decisions'][0]['decision_write'] = 'ok'
        self.assertEqual(probe.deadline_status(bad), 'FAIL')

    def test_row_metadata_is_bound_to_the_case(self):
        rows = self.rows()
        index = self.index(rows)
        for case_id in ('inside_budget_response', 'just_over_budget_response',
                        'unbounded_stage_timeout_response'):
            with self.subTest(case_id=case_id):
                bad = copy.deepcopy(rows)
                bad[index[case_id]]['phase'] = 'request'
                self.assertEqual(probe.deadline_status(bad), 'FAIL')
        bad = copy.deepcopy(rows)
        bad[index['over_budget_request']]['id'] = 'inside_budget_request'
        self.assertEqual(probe.deadline_status(bad), 'FAIL')

    def test_gateway_evidence_decides_the_failure_mode(self):
        rows = self.rows()
        index = self.index(rows)
        # A premature disconnect relabelled as a Gateway timeout must fail.
        bad = copy.deepcopy(rows)
        row = bad[index['early_disconnect_request']]
        row['gateway_markers'] = ['timeout:request']
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # A Gateway timeout whose log only shows a transport error must fail.
        bad = copy.deepcopy(rows)
        bad[index['unbounded_stage_timeout_request']]['gateway_markers'] = ['transport:request']
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # Evidence for the wrong phase must fail.
        bad = copy.deepcopy(rows)
        bad[index['unbounded_stage_timeout_response']]['gateway_markers'] = ['timeout:request']
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # Extra or missing evidence must fail.
        for markers in (['timeout:request', 'transport:request'], [], ['guardrail_reject:request']):
            with self.subTest(markers=markers):
                bad = copy.deepcopy(rows)
                bad[index['unbounded_stage_timeout_request']]['gateway_markers'] = markers
                self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # The Gateway access log has to agree with the client-visible status.
        bad = copy.deepcopy(rows)
        bad[index['inside_budget_request']]['gateway_http_status'] = 503
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # A guard denial without its guardrail_reject marker must fail.
        bad = copy.deepcopy(rows)
        bad[index['over_budget_request']]['gateway_markers'] = []
        self.assertEqual(probe.deadline_status(bad), 'FAIL')

    def test_truthy_flags_do_not_override_the_observations(self):
        rows = self.rows()
        index = self.index(rows)
        for name, mutate in (
            ('deny_as_200', lambda r: r.update(http_status=200, gateway_http_status=200, client_marker_visible=True)),
            ('deny_without_body', lambda r: r.update(client_body_is_guard_denial=False)),
            ('fast_timeout', lambda r: r.update(elapsed_ms=500.0)),
            ('missing_log', lambda r: r.update(gateway_log_bytes=0)),
        ):
            with self.subTest(name=name):
                bad = copy.deepcopy(rows)
                target = 'unbounded_stage_timeout_request' if name in ('fast_timeout', 'missing_log') else 'over_budget_request'
                mutate(bad[index[target]])
                self.assertEqual(probe.deadline_status(bad), 'FAIL')
        bad = copy.deepcopy(rows)
        bad[index['inside_budget_request']].update(http_status=503, assertion_passed=True)
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        bad = copy.deepcopy(rows)
        bad[index['over_budget_request']]['guard_decisions'].append(
            {'phase': 'response', 'allowed': True, 'reason': 'FIXTURE_ALLOW', 'stage_ms': 0,
             'delivered': True, 'decision_write': 'ok'})
        self.assertEqual(probe.deadline_status(bad), 'FAIL')

    def test_fixture_writes_and_aborts_its_decision_as_registered(self):
        for stage_ms, budget_ms, expected_reason, expected_status, expected_write in (
            (50, 10, budget.GUARD_DEADLINE_EXCEEDED, 503, 'ok'),
            (5, 10, 'FIXTURE_ALLOW', None, 'ok'),
        ):
            with self.subTest(stage_ms=stage_ms):
                # Small explicit budget keeps the fixture-logic test fast; the
                # registered suite exercises the declared 1500 ms budget.
                with probe.deadline_fixture('request', stage_ms, budget_ms=budget_ms) as (state, port):
                    request = Request(f'http://127.0.0.1:{port}/request', data=b'{"body":{}}',
                                      headers={'Content-Type': 'application/json'})
                    with urlopen(request, timeout=5) as response:
                        doc = json.load(response)
                    self.assertEqual(doc['action']['reason'], expected_reason)
                    self.assertEqual(doc['action'].get('status_code'), expected_status)
                decision = state.guard_decisions[0]
                self.assertEqual(decision['decision_write'], expected_write)
                self.assertTrue(decision['delivered'])

    def test_disconnect_fixture_never_writes_a_decision(self):
        with probe.deadline_fixture('request', 100, budget_ms=10, disconnect=True) as (state, port):
            request = Request(f'http://127.0.0.1:{port}/request', data=b'{"body":{}}',
                              headers={'Content-Type': 'application/json'})
            with self.assertRaises(OSError):
                urlopen(request, timeout=3).read()
            self.assertTrue(probe.wait_idle(state, 5))
        decision = state.guard_decisions[0]
        self.assertEqual(decision['decision_write'], 'not_attempted')
        self.assertFalse(decision['delivered'])


if __name__ == '__main__':
    unittest.main()
