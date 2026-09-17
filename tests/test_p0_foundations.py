import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from urllib.request import Request, urlopen
from agentguard.evidence import BINDINGS, CONTEXT, GATES, EvidenceRejected, validate_evidence
from tools.gateway_probe import fixture_server, gateway_config, replace_marker, run


class EvidencePreflight(unittest.TestCase):
    def setUp(self):
        self.bindings = {key: hashlib.sha256(key.encode()).hexdigest() for key in BINDINGS}
        self.scope = {'route_id': 'test', 'protocol': 'llm', 'phase': 'request', 'schema_sha256': '1' * 64}
        self.doc = {'kind': 'gateway-e2e-evidence/v1', 'bindings': copy.deepcopy(self.bindings),
                    'scope': copy.deepcopy(self.scope), 'generated_at': 100, 'expires_at': 200,
                    'gates': {k: 'PASS' for k in GATES}, 'trusted_context': sorted(CONTEXT),
                    'field_coverage': {'/messages': 'observed_inspected'}, 'unknown_fields_rejected': True}

    def check(self, doc=None, **overrides):
        raw = json.dumps(self.doc if doc is None else doc).encode()
        args = dict(bindings=self.bindings, scope=self.scope, required_fields={'/messages'}, now=150,
                    trusted_artifact_sha256=hashlib.sha256(raw).hexdigest())
        args.update(overrides)
        return validate_evidence(raw, **args)

    def test_unit_evidence_acceptance_is_not_protected_status(self):
        self.assertEqual(self.check()['status'], 'EVIDENCE_VALIDATED')

    def test_every_digest_is_bound_even_with_same_version(self):
        for key in BINDINGS:
            doc = copy.deepcopy(self.doc)
            doc['bindings'][key] = '2' * 64
            with self.subTest(key=key), self.assertRaises(EvidenceRejected):
                self.check(doc)

    def test_missing_or_untrusted_artifact_hash(self):
        for value in (None, '', '0' * 64):
            with self.subTest(value=value), self.assertRaises(EvidenceRejected):
                self.check(trusted_artifact_sha256=value)

    def test_expiry_and_max_age(self):
        for overrides in ({'now': 200}, {'now': 99}, {'max_age_seconds': 49}, {'now': True}):
            with self.subTest(overrides=overrides), self.assertRaises(EvidenceRejected):
                self.check(**overrides)

    def test_mismatched_scope(self):
        for key in self.scope:
            scope = dict(self.scope, **{key: '3' * 64})
            with self.subTest(key=key), self.assertRaises(EvidenceRejected):
                self.check(scope=scope)

    def test_every_gate_is_required(self):
        for gate in GATES:
            for state in ('FAIL', 'NOT_RUN', 'VULNERABILITY_REPRODUCED', True):
                doc = copy.deepcopy(self.doc)
                doc['gates'][gate] = state
                with self.subTest(gate=gate, state=state), self.assertRaises(EvidenceRejected):
                    self.check(doc)

    def test_unknown_or_missing_field_coverage_rejected(self):
        for fields in ({}, {'/messages': 'unknown'}, {'/messages': 'forwarded_uninspected'},
                       {'/messages': 'observed_inspected', '/unexpected': 'observed_inspected'}):
            with self.subTest(fields=fields), self.assertRaises(EvidenceRejected):
                self.check(dict(self.doc, field_coverage=fields))

    def test_no_implicit_context_defaults(self):
        for missing in CONTEXT:
            doc = dict(self.doc, trusted_context=sorted(CONTEXT - {missing}))
            with self.subTest(missing=missing), self.assertRaises(EvidenceRejected):
                self.check(doc)

    def test_closed_envelope_obligation(self):
        for value in (False, None, 1):
            with self.subTest(value=value), self.assertRaises(EvidenceRejected):
                self.check(dict(self.doc, unknown_fields_rejected=value))

    def test_duplicate_json_keys(self):
        payload = json.dumps(self.doc, separators=(',', ':')).encode()
        raw = payload.replace(b'"kind":"gateway-e2e-evidence/v1"',
                              b'"kind":"x","kind":"gateway-e2e-evidence/v1"', 1)
        self.assertEqual(json.loads(raw), self.doc)  # Ordinary last-key-wins parsing would accept it.
        with self.assertRaises(EvidenceRejected):
            validate_evidence(raw, bindings=self.bindings, scope=self.scope, required_fields={'/messages'},
                              now=150, trusted_artifact_sha256=hashlib.sha256(raw).hexdigest())


class GatewayProbeFoundations(unittest.TestCase):
    def test_fixture_is_real_loopback_http_not_gateway_e2e(self):
        with fixture_server() as (state, port):
            for endpoint in ('/request', '/response', '/v1/chat/completions'):
                request = Request(f'http://127.0.0.1:{port}{endpoint}', data=b'{"body":{"messages":[]}}',
                                  headers={'Content-Type': 'application/json'})
                with urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    json.load(response)
            self.assertEqual(state.counts, {'request': 1, 'response': 1, 'upstream': 1})

    def test_fixture_raw_bytes_are_not_normalized(self):
        with fixture_server() as (state, port):
            raw = '{"action":{"reason":"a","reason":"b"}}'
            state.reset('request', 'raw', raw)
            request = Request(f'http://127.0.0.1:{port}/request', data=b'{"body":{"messages":[]}}')
            with urlopen(request, timeout=2) as response:
                self.assertEqual(response.read().decode(), raw)

    def test_mismatched_binary_cannot_be_called_gateway_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'not-gateway'
            path.write_bytes(b'fake')
            with self.assertRaises(ValueError):
                run(path, Path(d) / 'report.json')

    def test_mask_preserves_structure(self):
        original = {'role': 'user', 'content': [{'text': 'secret', 'index': 1}]}
        result = replace_marker(original, 'secret', '[REDACTED]')
        self.assertEqual(result['content'][0], {'text': '[REDACTED]', 'index': 1})
        self.assertEqual(original['content'][0]['text'], 'secret')

    def test_config_targets_only_fixture(self):
        encoded = json.dumps(gateway_config(12345, 23456))
        self.assertIn('127.0.0.1:23456', encoded)
        self.assertNotIn('api.openai.com', encoded)


if __name__ == '__main__':
    unittest.main()
