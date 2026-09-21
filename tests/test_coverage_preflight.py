import copy
import hashlib
import json
import unittest

from agentguard.context import HEADER_EXPRESSIONS
from agentguard.coverage import (
    COVERAGE_SCOPE_PHASE,
    EVIDENCE_KEYS,
    EVIDENCE_KIND,
    EVIDENCE_ROW_KEYS,
    INGRESS_REJECTION_CODE,
    MATRIX_KIND,
    CoverageRejected,
    deployment_config_sha256,
    gateway_evidence_sha256,
    matrix_sha256,
    route_sha256,
    validate_coverage_evidence,
    validate_coverage_route,
    validate_matrix,
)


class CoveragePreflight(unittest.TestCase):
    NOW = 150
    BINDINGS = {key: hashlib.sha256(key.encode()).hexdigest()
                for key in ('gateway_image', 'gateway_config', 'compiler', 'adapter')}

    def route(self):
        hook = {
            'webhook': {
                'target': {'host': '127.0.0.1:9101'},
                'headers': dict(HEADER_EXPRESSIONS),
                'failureMode': 'failClosed',
            }
        }
        return {
            'backends': [{
                'ai': {
                    'name': 'fixture',
                    'hostOverride': '127.0.0.1:9100',
                    'provider': {'openAI': {}},
                }
            }],
            'policies': {'ai': {'promptGuard': {
                'request': [copy.deepcopy(hook)],
                'response': [copy.deepcopy(hook)],
            }}},
        }

    def scope(self, route=None):
        return {
            'route_id': 'fixture-completions',
            'protocol': 'openai-chat-completions',
            'phase': COVERAGE_SCOPE_PHASE,
            'schema_sha256': '1' * 64,
            'route_sha256': route_sha256(route or self.route()),
        }

    def deployment_config(self, route=None):
        return {'binds': [{'port': 9000, 'listeners': [{'routes': [route or self.route()]}]}]}

    def row(self, phase, pointer, *, field_type, normalized_pointer,
            status, native_enforcement, lossiness, fixture_id):
        return {
            'phase': phase,
            'pointer': pointer,
            'field_type': field_type,
            'normalized_pointer': normalized_pointer,
            'status': status,
            'native_enforcement': native_enforcement,
            'lossiness': lossiness,
            'fixture_id': fixture_id,
            'artifact_sha256': 'a' * 64,
        }

    def matrix(self, route=None):
        rows = [
            self.row('request', '/messages', field_type='message',
                     normalized_pointer='/messages', status='observed_inspected',
                     native_enforcement='hook_and_egress', lossiness='none',
                     fixture_id='request-messages'),
            self.row('response', '/choices', field_type='array',
                     normalized_pointer='/choices', status='observed_inspected',
                     native_enforcement='hook_and_egress', lossiness='none',
                     fixture_id='response-choices'),
            self.row('request', '/unknown_request', field_type='unknown',
                     normalized_pointer=None, status='ingress_rejected',
                     native_enforcement='reject_before_normalization',
                     lossiness='rejected', fixture_id='request-unknown'),
            self.row('response', '/unknown_response', field_type='unknown',
                     normalized_pointer=None, status='ingress_rejected',
                     native_enforcement='reject_before_normalization',
                     lossiness='rejected', fixture_id='response-unknown'),
        ]
        return {
            'kind': MATRIX_KIND,
            'bindings': copy.deepcopy(self.BINDINGS),
            'scope': self.scope(route),
            'generated_at': 100,
            'expires_at': 200,
            'provenance': {
                'source': 'trusted-field-catalog',
                'source_revision': 'b' * 40,
                'retrieved_at': 100,
                'trusted': True,
            },
            'rows': rows,
            'unknown_original_fields_rejected_before_normalization': True,
        }

    def evidence(self, matrix=None, route=None):
        matrix = matrix or self.matrix(route)
        gateway_evidence = self.gateway_evidence()
        rows = []
        for expected in matrix['rows']:
            rejected = expected['status'] == 'ingress_rejected'
            rows.append({
                'phase': expected['phase'],
                'pointer': expected['pointer'],
                'fixture_id': expected['fixture_id'],
                'status': expected['status'],
                'pre_normalization_present': True,
                'normalized_pointer': expected['normalized_pointer'],
                'hook_observed': not rejected,
                'backend_observed': not rejected,
                'client_observed': True,
                'native_enforcement': expected['native_enforcement'],
                'lossiness': expected['lossiness'],
                'artifact_sha256': expected['artifact_sha256'],
                'gateway_rejected_before_normalization': rejected,
                'gateway_http_status': 503 if rejected else 200,
                'gateway_rejection_code': INGRESS_REJECTION_CODE if rejected else None,
                'gateway_log_sha256': 'c' * 64,
                'detector_observed': not rejected,
                'detector_evidence_sha256': None if rejected else 'd' * 64,
                'payload_preserved': None if rejected else True,
                'payload_evidence_sha256': None if rejected else 'd' * 64,
            })
        return {
            'kind': EVIDENCE_KIND,
            'matrix_sha256': matrix_sha256(matrix),
            'bindings': copy.deepcopy(matrix['bindings']),
            'scope': copy.deepcopy(matrix['scope']),
            'generated_at': 100,
            'expires_at': 200,
            'gates': {'G0-COVERAGE': 'NOT_EVALUATED'},
            'runtime_status': 'NOT_EVALUATED',
            'gateway_evidence': gateway_evidence,
            'rows': rows,
            'unknown_original_fields_rejected_before_normalization': True,
        }

    def gateway_evidence(self):
        return {
                'runner_kind': 'native_gateway',
                'process_listener_owned': True,
                'request_id': 'coverage-run-1',
                'log_artifact_sha256': 'c' * 64,
                'observation_artifact_sha256': 'd' * 64,
        }

    def validate(self, matrix=None, evidence=None, route=None, **overrides):
        route = route or self.route()
        matrix = copy.deepcopy(matrix or self.matrix(route))
        evidence = copy.deepcopy(evidence or self.evidence(matrix, route))
        raw = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()
        args = {
            'expected_matrix': matrix,
            'trusted_matrix_sha256': matrix_sha256(matrix),
            'trusted_artifact_sha256': hashlib.sha256(raw).hexdigest(),
            'trusted_gateway_log_sha256':
                self.gateway_evidence()['log_artifact_sha256'],
            'trusted_gateway_evidence_sha256':
                gateway_evidence_sha256(self.gateway_evidence()),
            'expected_bindings': self.BINDINGS,
            'expected_scope': matrix['scope'],
            'now': self.NOW,
        }
        args.update(overrides)
        return validate_coverage_evidence(raw, **args)

    def test_valid_external_matrix_is_preflight_only(self):
        result = self.validate()
        self.assertEqual(result['status'], 'COVERAGE_PREFLIGHT_VALIDATED')
        self.assertEqual(result['runtime_status'], 'NOT_EVALUATED')
        self.assertEqual(result['row_count'], 4)

    def test_runtime_pass_cannot_be_self_asserted(self):
        matrix = self.matrix()
        evidence = self.evidence(matrix)
        evidence['gates'] = {'G0-COVERAGE': 'PASS'}
        evidence['runtime_status'] = 'PASS'
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_RUNTIME_STATUS_INVALID'):
            self.validate(matrix, evidence)

    def test_partial_or_request_only_scope_is_rejected(self):
        matrix = self.matrix()
        scope = dict(matrix['scope'], phase='request')
        matrix['scope'] = scope
        with self.assertRaisesRegex(CoverageRejected, 'MATRIX_EXPECTED_SCOPE_INVALID'):
            self.validate(matrix)

    def test_forwarded_and_unknown_statuses_cannot_be_protected(self):
        for status in ('forwarded_uninspected', 'unknown'):
            matrix = self.matrix()
            matrix['rows'][0]['status'] = status
            with self.subTest(status=status), self.assertRaises(CoverageRejected):
                self.validate(matrix)

    def test_unknown_field_rows_are_required_for_both_phases(self):
        matrix = self.matrix()
        matrix['rows'] = [row for row in matrix['rows'] if row['field_type'] != 'unknown']
        matrix['unknown_original_fields_rejected_before_normalization'] = True
        with self.assertRaisesRegex(CoverageRejected, 'MATRIX_PHASE_COVERAGE_MISSING|MATRIX_UNKNOWN_FIELD_COVERAGE_MISSING|MATRIX_UNKNOWN_INGRESS_UNPROTECTED'):
            self.validate(matrix)

    def test_client_only_rejection_has_no_native_evidence(self):
        matrix = self.matrix()
        evidence = self.evidence(matrix)
        rejection = next(row for row in evidence['rows']
                         if row['status'] == 'ingress_rejected')
        rejection['gateway_rejected_before_normalization'] = False
        rejection['gateway_rejection_code'] = None
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_NATIVE_REJECTION_EVIDENCE_MISSING'):
            self.validate(matrix, evidence)

    def test_gateway_evidence_is_required_and_row_logs_are_bound(self):
        matrix = self.matrix()
        evidence = self.evidence(matrix)
        del evidence['gateway_evidence']
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_SCHEMA_INVALID'):
            self.validate(matrix, evidence)
        evidence = self.evidence(matrix)
        evidence['gateway_evidence']['runner_kind'] = []
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_GATEWAY_RUNNER_INVALID'):
            self.validate(matrix, evidence)
        evidence = self.evidence(matrix)
        evidence['rows'][0]['gateway_log_sha256'] = 'd' * 64
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_GATEWAY_LOG_BINDING_MISMATCH'):
            self.validate(matrix, evidence)

    def test_missing_gateway_log_digest_is_rejected(self):
        matrix = self.matrix()
        evidence = self.evidence(matrix)
        rejection = next(row for row in evidence['rows']
                         if row['status'] == 'ingress_rejected')
        del rejection['gateway_log_sha256']
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_ROW_SCHEMA_INVALID'):
            self.validate(matrix, evidence)

    def test_normalization_disappearance_is_rejected(self):
        matrix = self.matrix()
        evidence = self.evidence(matrix)
        observed = next(row for row in evidence['rows']
                        if row['status'] == 'observed_inspected')
        observed['normalized_pointer'] = None
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_NORMALIZATION_LOSS'):
            self.validate(matrix, evidence)

    def test_expired_future_and_stale_matrix_are_rejected(self):
        for now, max_age, expected in (
            (200, 3600, 'MATRIX_STALE_OR_FUTURE'),
            (99, 3600, 'MATRIX_STALE_OR_FUTURE'),
            (150, 49, 'MATRIX_STALE_OR_FUTURE'),
        ):
            with self.subTest(now=now, max_age=max_age):
                with self.assertRaisesRegex(CoverageRejected, expected):
                    self.validate(now=now, max_age_seconds=max_age)

    def test_matrix_digest_mismatch_is_rejected(self):
        matrix = self.matrix()
        with self.assertRaisesRegex(CoverageRejected, 'MATRIX_REFERENCE_MISMATCH'):
            self.validate(matrix, trusted_matrix_sha256='d' * 64)

    def test_binding_mismatch_is_rejected(self):
        matrix = self.matrix()
        expected = dict(self.BINDINGS, compiler='e' * 64)
        with self.assertRaisesRegex(CoverageRejected, 'MATRIX_DEPLOYMENT_BINDING_MISMATCH'):
            self.validate(matrix, expected_bindings=expected)

    def test_route_target_mutation_changes_digest_and_fails_route_preflight(self):
        route = self.route()
        matrix = self.matrix(route)
        mutated = copy.deepcopy(route)
        mutated['policies']['ai']['promptGuard']['response'][0]['webhook']['target']['host'] = '127.0.0.1:9999'
        mutated_config = self.deployment_config(mutated)
        bindings = dict(self.BINDINGS,
                        gateway_config=deployment_config_sha256(mutated_config))
        matrix['bindings'] = bindings
        evidence = self.evidence(matrix, route)
        raw = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_ROUTE_SCOPE_MISMATCH'):
            validate_coverage_route(
                mutated,
                deployment_config=mutated_config,
                coverage_raw=raw,
                coverage_artifact_sha256=hashlib.sha256(raw).hexdigest(),
                expected_matrix=matrix,
                trusted_matrix_sha256=matrix_sha256(matrix),
                trusted_gateway_log_sha256=self.gateway_evidence()['log_artifact_sha256'],
                trusted_gateway_evidence_sha256=gateway_evidence_sha256(
                    self.gateway_evidence()),
                expected_bindings=bindings,
                expected_scope=matrix['scope'],
                now=self.NOW,
            )

    def test_route_preflight_binds_complete_deployment_config(self):
        route = self.route()
        config = self.deployment_config(route)
        bindings = dict(self.BINDINGS, gateway_config=deployment_config_sha256(config))
        matrix = self.matrix(route)
        matrix['bindings'] = bindings
        evidence = self.evidence(matrix, route)
        raw = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()
        result = validate_coverage_route(
            route,
            deployment_config=config,
            coverage_raw=raw,
            coverage_artifact_sha256=hashlib.sha256(raw).hexdigest(),
            expected_matrix=matrix,
            trusted_matrix_sha256=matrix_sha256(matrix),
            trusted_gateway_log_sha256=self.gateway_evidence()['log_artifact_sha256'],
            trusted_gateway_evidence_sha256=gateway_evidence_sha256(
                self.gateway_evidence()),
            expected_bindings=bindings,
            expected_scope=matrix['scope'],
            now=self.NOW,
        )
        self.assertEqual(result['runtime_status'], 'NOT_EVALUATED')
        changed_config = copy.deepcopy(config)
        changed_config['binds'][0]['port'] = 9001
        with self.assertRaisesRegex(CoverageRejected, 'COVERAGE_DEPLOYMENT_BINDING_MISMATCH'):
            validate_coverage_route(
                route,
                deployment_config=changed_config,
                coverage_raw=raw,
                coverage_artifact_sha256=hashlib.sha256(raw).hexdigest(),
                expected_matrix=matrix,
                trusted_matrix_sha256=matrix_sha256(matrix),
                trusted_gateway_log_sha256=self.gateway_evidence()['log_artifact_sha256'],
                trusted_gateway_evidence_sha256=gateway_evidence_sha256(
                    self.gateway_evidence()),
                expected_bindings=bindings,
                expected_scope=matrix['scope'],
                now=self.NOW,
            )

    def test_route_digest_covers_backend_identity_too(self):
        route = self.route()
        changed = copy.deepcopy(route)
        changed['backends'][0]['ai']['name'] = 'other'
        self.assertNotEqual(route_sha256(route), route_sha256(changed))

    def test_phase_swap_or_omission_cannot_pass(self):
        matrix = self.matrix()
        evidence = self.evidence(matrix)
        evidence['rows'][0]['phase'] = 'response'
        with self.assertRaises(CoverageRejected):
            self.validate(matrix, evidence)
        matrix = self.matrix()
        matrix['rows'] = matrix['rows'][:-1]
        with self.assertRaisesRegex(CoverageRejected, 'MATRIX_PHASE_COVERAGE_MISSING|MATRIX_UNKNOWN_FIELD_COVERAGE_MISSING|MATRIX_UNKNOWN_INGRESS_UNPROTECTED'):
            self.validate(matrix)

    def test_empty_pointer_is_rejected_but_root_and_escaped_pointers_remain_valid(self):
        matrix = self.matrix()
        matrix['rows'][0]['pointer'] = ''
        with self.assertRaisesRegex(CoverageRejected, 'MATRIX_ROW_ID_INVALID'):
            self.validate(matrix)
        matrix = self.matrix()
        matrix['rows'][0]['pointer'] = '/'
        self.assertEqual(self.validate(matrix)['status'], 'COVERAGE_PREFLIGHT_VALIDATED')
        for pointer in ('/a~0b', '/a~1b', '/a//b'):
            matrix = self.matrix()
            matrix['rows'][0]['pointer'] = pointer
            self.assertEqual(self.validate(matrix)['status'], 'COVERAGE_PREFLIGHT_VALIDATED')

    def test_valid_unsupported_field_rejection_requires_native_gateway_observation(self):
        matrix = self.matrix()
        result = self.validate(matrix, self.evidence(matrix))
        self.assertEqual(result['runtime_status'], 'NOT_EVALUATED')
        self.assertTrue(all(
            row['gateway_rejected_before_normalization']
            for row in self.evidence(matrix)['rows']
            if row['status'] == 'ingress_rejected'
        ))

    def test_route_preflight_binds_actual_route_and_keeps_status_not_evaluated(self):
        route = self.route()
        config = self.deployment_config(route)
        bindings = dict(self.BINDINGS, gateway_config=deployment_config_sha256(config))
        matrix = self.matrix(route)
        matrix['bindings'] = bindings
        evidence = self.evidence(matrix, route)
        raw = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()
        result = validate_coverage_route(
            route,
            deployment_config=self.deployment_config(route),
            coverage_raw=raw,
            coverage_artifact_sha256=hashlib.sha256(raw).hexdigest(),
            expected_matrix=matrix,
            trusted_matrix_sha256=matrix_sha256(matrix),
            trusted_gateway_log_sha256=self.gateway_evidence()['log_artifact_sha256'],
            trusted_gateway_evidence_sha256=gateway_evidence_sha256(
                self.gateway_evidence()),
            expected_bindings=bindings,
            expected_scope=matrix['scope'],
            now=self.NOW,
        )
        self.assertEqual(result['status'], 'COVERAGE_ROUTE_PREFLIGHTED')
        self.assertEqual(result['runtime_status'], 'NOT_EVALUATED')


if __name__ == '__main__':
    unittest.main()
