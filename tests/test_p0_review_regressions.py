import copy
import hashlib
import json
import unittest
from agentguard.evidence import BINDINGS, CONTEXT, GATES, EvidenceRejected, validate_evidence
from tools.gateway_probe import (control_passes, expected_messages, rejected_without_leak,
                                 stock_assertion, valid_request_structure, valid_response_structure)


class ProbeReviewRegressions(unittest.TestCase):
    def row(self, phase='request', status=200):
        return {'phase': phase, 'http_status': status,
                'counts': {'request': 1, 'response': 1, 'upstream': 1},
                'client_marker_visible': phase == 'response', 'upstream_received_marker': True,
                'request_structure_preserved': True, 'response_structure_preserved': True,
                'upstream_messages_empty': False, 'client_body_sha256': hashlib.sha256(b'x').hexdigest()}

    def test_supported_expectations_detect_mismatches(self):
        row = self.row()
        for expectation in ('parse_error', 'reject', 'mask', 'reject_variant_not_http_assertion'):
            with self.subTest(expectation=expectation):
                self.assertFalse(stock_assertion(row, expectation))
        self.assertTrue(stock_assertion(row, 'pass'))
        row['http_status'] = 503
        self.assertFalse(stock_assertion(row, 'pass'))

    def test_unknown_is_unscored_or_error_not_pass(self):
        for expectation in ('not_verified', 'mask_phase_handling_not_verified'):
            self.assertIsNone(stock_assertion(self.row(), expectation))
        with self.assertRaises(ValueError):
            stock_assertion(self.row(), 'typo')

    def test_bad_http_status_cannot_be_a_protected_rejection(self):
        row = self.row(status=200)
        row['counts']['upstream'] = 0
        self.assertTrue(stock_assertion(row, 'reject_variant_not_http_assertion'))
        self.assertFalse(rejected_without_leak(row))

    def test_reject_is_phase_specific(self):
        for phase in ('request', 'response'):
            row = self.row(phase, 403)
            row['client_marker_visible'] = False
            row['counts']['upstream'] = 0 if phase == 'request' else 1
            self.assertTrue(stock_assertion(row, 'reject'))
            self.assertTrue(rejected_without_leak(row))
            row['counts'][phase] = 0
            self.assertFalse(rejected_without_leak(row))

    def test_mask_control_needs_preserved_request_and_response(self):
        for key in ('request_structure_preserved', 'response_structure_preserved'):
            row = self.row()
            row['upstream_received_marker'] = False
            self.assertTrue(control_passes(row, 'mask'))
            row[key] = False
            self.assertFalse(control_passes(row, 'mask'))

    def test_request_empty_or_removed_message_does_not_pass_mask(self):
        payload = {'model': 'fixture', 'messages': expected_messages('[REDACTED]')}
        self.assertTrue(valid_request_structure(payload, '[REDACTED]'))
        for messages in ([], expected_messages('[REDACTED]')[1:], expected_messages('')):
            self.assertFalse(valid_request_structure(dict(payload, messages=messages), '[REDACTED]'))

    def test_response_mask_preserves_metadata_and_redacted_text(self):
        payload = {'id': 'fixture', 'object': 'chat.completion', 'created': 1, 'model': 'fixture',
                   'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'prefix [REDACTED] suffix'},
                                'finish_reason': 'stop'}],
                   'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}
        self.assertTrue(valid_response_structure(payload, 'prefix [REDACTED] suffix'))
        for key in payload:
            changed = copy.deepcopy(payload)
            del changed[key]
            self.assertFalse(valid_response_structure(changed, 'prefix [REDACTED] suffix'))
        self.assertFalse(valid_response_structure(payload, ''))

    def test_pointer_escapes_and_invalid_tokens(self):
        bindings = {k: hashlib.sha256(k.encode()).hexdigest() for k in BINDINGS}
        scope = {'route_id': 'test', 'protocol': 'llm', 'phase': 'request', 'schema_sha256': '1' * 64}
        for pointer, valid in [('/a~0b', True), ('/a~1b', True), ('/', True), ('/a//b', True),
                               ('/bad~', False), ('/bad~2', False), ('#/a', False), ('', False)]:
            doc = {'kind': 'gateway-e2e-evidence/v1', 'bindings': bindings, 'scope': scope,
                   'generated_at': 100, 'expires_at': 200, 'gates': {k: 'PASS' for k in GATES},
                   'trusted_context': sorted(CONTEXT), 'field_coverage': {pointer: 'observed_inspected'},
                   'unknown_fields_rejected': True}
            raw = json.dumps(doc).encode()
            kwargs = dict(bindings=bindings, scope=scope, required_fields={pointer}, now=150,
                          trusted_artifact_sha256=hashlib.sha256(raw).hexdigest())
            with self.subTest(pointer=pointer):
                if valid:
                    self.assertEqual(validate_evidence(raw, **kwargs)['status'], 'EVIDENCE_VALIDATED')
                else:
                    with self.assertRaises(EvidenceRejected):
                        validate_evidence(raw, **kwargs)


if __name__ == '__main__':
    unittest.main()
