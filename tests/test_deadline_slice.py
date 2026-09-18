"""Budget declaration checks, frozen registry and the real loopback fixture.

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


def observation(case):
    """Rows that must PASS, built from the case's registered expectation."""
    expected_class = case.get('expected_class') or probe.EXPECTED_CLASS[case['outcome']]
    timeout = expected_class == 'availability_fault'
    exceeded = budget.over_budget(case['stage_ms'])
    decisions = []
    counts = probe.expected_counts(case)
    for phase in ('request', 'response'):
        if counts[phase] == 0:
            continue  # the Gateway never reached this phase
        slow = phase == case['phase']
        stage = case['stage_ms'] if slow else 0
        # Only a Gateway-side stop leaves the decision undelivered; a guard
        # denial is a normal, delivered response.
        denied = slow and exceeded
        decisions.append({'phase': phase, 'allowed': not denied,
                          'reason': budget.GUARD_DEADLINE_EXCEEDED if denied else 'FIXTURE_ALLOW',
                          'stage_ms': stage, 'delivered': not (timeout and slow)})
    elapsed = 10000.0 if timeout else 1000.0
    return {'id': case['id'], 'phase': case['phase'],
            'http_status': 200 if expected_class == 'allow' else 503,
            'counts': counts, 'elapsed_ms': elapsed, 'process_listener_owned': True,
            'client_marker_visible': expected_class == 'allow' and case['phase'] == 'response',
            'client_body_is_guard_denial': expected_class == 'guard_deadline_decision',
            'upstream_received_marker': counts['upstream'] == 1,
            'request_structure_preserved': counts['upstream'] == 1,
            'response_structure_preserved': expected_class == 'allow',
            'guard_decisions': decisions, 'assertion_passed': True}


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
    def test_registry_is_frozen_and_matches_the_boundary_contract(self):
        rows = probe.cases()
        self.assertEqual(len(rows), probe.EXPECTED_CASE_COUNT)
        self.assertEqual({c['id'] for c in rows}, probe.registered_ids())
        for case in rows:
            with self.subTest(case=case['id']):
                self.assertIn(case['outcome'], probe.EXPECTED_CLASS)
        self.assertEqual(sum(c['outcome'] == 'allow' for c in rows), 3)
        self.assertEqual(sum(c['outcome'] == 'guard_deny' for c in rows), 3)
        self.assertEqual(sum(c['outcome'] == 'gateway_timeout' for c in rows), 2)

    def test_contradictory_registered_case_is_rejected(self):
        broken = list(probe.REGISTERED_CASES)
        broken[3] = ('just_over_budget_request', 'request', 10, 'guard_deny')
        with patch.object(probe, 'REGISTERED_CASES', tuple(broken)):
            with self.assertRaisesRegex(ValueError, 'DEADLINE_CASE_INVALID'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.registered_cases()]), 'FAIL')

    def test_runner_registry_drift_is_refused(self):
        # Internally consistent but different from the pinned contract.
        drifted = [list(case) for case in probe.REGISTERED_CASES]
        drifted[0][2] = 1300
        with patch.object(probe, 'REGISTERED_CASES', tuple(tuple(c) for c in drifted)):
            with self.assertRaisesRegex(ValueError, 'RUNNER_REGISTRY_MISMATCH'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.registered_cases()]), 'FAIL')

    def test_contract_digest_and_boundary_are_both_pinned(self):
        # Editing the gate's expectation without its digest is refused outright.
        broken = list(probe.EXPECTED_CONTRACT)
        broken[3] = ('just_over_budget_request', 'request', 10, 'guard_deadline_decision')
        with patch.object(probe, 'EXPECTED_CONTRACT', tuple(broken)):
            with self.assertRaisesRegex(ValueError, 'CONTRACT_CHANGED'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.runner_cases()]), 'FAIL')
        # A contract whose boundary contradicts its expectation is refused even
        # when its digest is pinned correctly, so this reaches _validate_contract.
        inconsistent = tuple(broken)
        with patch.object(probe, 'EXPECTED_CONTRACT', inconsistent), \
             patch.object(probe, 'EXPECTED_CONTRACT_SHA256', probe.contract_digest(inconsistent)):
            with self.assertRaisesRegex(ValueError, 'DEADLINE_CASE_INVALID'):
                probe.cases()
            self.assertEqual(probe.deadline_status([observation(c) for c in probe.runner_cases()]), 'FAIL')

    def test_shrunk_or_replaced_suite_cannot_pass(self):
        rows = [observation(c) for c in probe.cases()]
        self.assertEqual(probe.deadline_status(rows), 'PASS')
        self.assertEqual(probe.deadline_status(rows[:-1]), 'FAIL')
        duplicated = copy.deepcopy(rows)
        duplicated[-1] = duplicated[0]
        self.assertEqual(probe.deadline_status(duplicated), 'FAIL')
        with patch.object(probe, 'cases', return_value=probe.cases()[:-1]):
            self.assertEqual(probe.deadline_status(rows[:-1]), 'FAIL')

    def test_truthy_flags_do_not_override_the_observations(self):
        rows = [observation(c) for c in probe.cases()]
        index = {r['id']: i for i, r in enumerate(rows)}
        # A guard denial reported as a 200 with a visible marker must not pass.
        bad = copy.deepcopy(rows)
        bad[index['over_budget_request']].update(http_status=200, client_marker_visible=True)
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # A denial without the fail-closed body must not pass.
        bad = copy.deepcopy(rows)
        bad[index['just_over_budget_response']]['client_body_is_guard_denial'] = False
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # A fast "timeout" is not an availability fault.
        bad = copy.deepcopy(rows)
        bad[index['unbounded_stage_timeout_request']]['elapsed_ms'] = 500.0
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # An availability fault may not carry a delivered guard decision.
        bad = copy.deepcopy(rows)
        decision = bad[index['unbounded_stage_timeout_response']]['guard_decisions'][-1]
        decision.update(delivered=True, allowed=False, reason=budget.GUARD_DEADLINE_EXCEEDED)
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # assertion_passed is never read as evidence.
        bad = copy.deepcopy(rows)
        bad[index['inside_budget_request']].update(http_status=503, assertion_passed=True)
        self.assertEqual(probe.deadline_status(bad), 'FAIL')
        # An extra hook decision must not satisfy the decision-count pin.
        bad = copy.deepcopy(rows)
        bad[index['over_budget_request']]['guard_decisions'].append(
            {'phase': 'response', 'allowed': True, 'reason': 'FIXTURE_ALLOW', 'stage_ms': 0, 'delivered': True})
        self.assertEqual(probe.deadline_status(bad), 'FAIL')

    def test_fixture_denies_over_budget_and_allows_inside_it(self):
        for stage_ms, expected_reason, expected_status in ((50, budget.GUARD_DEADLINE_EXCEEDED, 503),
                                                           (5, 'FIXTURE_ALLOW', None)):
            with self.subTest(stage_ms=stage_ms):
                # Small explicit budget keeps the fixture-logic test fast; the
                # registered suite is what exercises the declared 1500 ms budget.
                with probe.deadline_fixture('request', stage_ms, budget_ms=10) as (state, port):
                    request = Request(f'http://127.0.0.1:{port}/request', data=b'{"body":{}}',
                                      headers={'Content-Type': 'application/json'})
                    with urlopen(request, timeout=5) as response:
                        doc = json.load(response)
                    self.assertEqual(doc['action']['reason'], expected_reason)
                    self.assertEqual(doc['action'].get('status_code'), expected_status)
                self.assertEqual([d['reason'] for d in state.guard_decisions], [expected_reason])
                self.assertTrue(state.guard_decisions[0]['delivered'])


if __name__ == '__main__':
    unittest.main()
