"""Helpers are unit-tested with synthetic records, not claimed as Gateway E2E."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch as mock_patch

from tools import patch_gateway as patcher
from tools import protected_gateway_probe as probe


class BuildBindingTests(unittest.TestCase):
    def setUp(self):
        self.binary = b'unit-only-not-an-executable'
        self.doc = {'kind': 'agentguard-gateway-build/v1',
                    'upstream_revision': patcher.SOURCE_REVISION,
                    'upstream_webhook_blob': patcher.WEBHOOK_BLOB,
                    'upstream_webhook_sha256': patcher.WEBHOOK_SHA256,
                    'patched_webhook_sha256': patcher.PATCHED_WEBHOOK_SHA256,
                    'module_sha256': patcher.sha256(patcher.MODULE.read_bytes()),
                    'patcher_sha256': patcher.sha256(Path(patcher.__file__).read_bytes()),
                    'fixtures_sha256': patcher.sha256(patcher.FIXTURES.read_bytes()),
                    'binary_sha256': patcher.sha256(self.binary), 'agentguard_commit': 'a'*40,
                    'rust_toolchain': '1.98.0', 'build_profile': 'dev',
                    'target': 'x86_64-unknown-linux-gnu', 'features': ['crypto-aws-lc'],
                    'default_features': False}

    def check(self, doc=None, binary=None):
        raw = json.dumps(self.doc if doc is None else doc).encode()
        return probe.validate_build(self.binary if binary is None else binary, raw, patcher.sha256(raw))

    def test_synthetic_manifest_validation_is_not_compilation(self):
        self.assertEqual(self.check()['kind'], 'agentguard-gateway-build/v1')

    def test_each_binding_must_match(self):
        for field in ('upstream_revision', 'upstream_webhook_blob', 'upstream_webhook_sha256',
                      'patched_webhook_sha256', 'module_sha256', 'patcher_sha256', 'fixtures_sha256',
                      'binary_sha256', 'rust_toolchain', 'build_profile', 'target', 'kind'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(dict(self.doc, **{field: 'b'*64}))

    def test_untrusted_or_missing_manifest_hash(self):
        raw = json.dumps(self.doc).encode()
        for h in (None, '', False, 'b'*64):
            with self.subTest(h=h), self.assertRaises(ValueError):
                probe.validate_build(self.binary, raw, h)

    def test_same_hash_does_not_allow_unknown_fields(self):
        with self.assertRaisesRegex(ValueError, 'SCHEMA'):
            self.check(dict(self.doc, unchecked=True))

    def test_duplicate_keys_cannot_pass_valid_schema(self):
        raw = json.dumps(self.doc).encode().replace(b'{', b'{"kind":"forged",', 1)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            probe.validate_build(self.binary, raw, patcher.sha256(raw))

    def test_changed_binary_cannot_use_valid_manifest(self):
        with self.assertRaisesRegex(ValueError, 'BINARY_IDENTITY'):
            self.check(binary=b'tampered')

    def test_build_features_and_commit_are_checked(self):
        for field, value in [('features', []), ('default_features', 0), ('agentguard_commit', 'HEAD')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(dict(self.doc, **{field: value}))

    def test_stock_binary_cannot_masquerade_as_patched(self):
        with mock_patch.object(probe.stock, 'BINARY_SHA256', patcher.sha256(self.binary)):
            with self.assertRaisesRegex(ValueError, 'STOCK_BUILD'):
                self.check()

    def test_pinned_dev_allocator_environment(self):
        self.assertEqual(probe.RUNTIME_ENV, {'RUST_LOG': 'info', '_RJEM_MALLOC_CONF': 'prof:true'})

    def test_bounded_manifest(self):
        raw = b'x'*16385
        with self.assertRaisesRegex(ValueError, 'SIZE'):
            probe.validate_build(self.binary, raw, patcher.sha256(raw))


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.controls = [{'id': p+'_'+a, 'assertion_passed': True} for p in ('request', 'response') for a in ('allow','deny','mask')]
        self.negatives = [{'id': 'request/negative', 'assertion_passed': True}]
        self.faults = [{'id': p+'/'+f, 'assertion_passed': True} for p in ('request','response') for f in probe.FAULTS]
        self.expected = {'request/negative'}

    def result(self):
        return probe.acceptance(self.controls, self.negatives, self.faults, self.expected)

    def test_all_required_parts_pass(self):
        self.assertTrue(self.result())

    def test_missing_controls_negatives_or_faults_never_pass(self):
        for rows in (self.controls, self.negatives, self.faults):
            row = rows.pop()
            self.assertFalse(self.result())
            rows.append(row)

    def test_unknown_false_and_truthy_nonbool_never_pass(self):
        for value in (False, None, 1, 'PASS'):
            self.negatives[0]['assertion_passed'] = value
            self.assertFalse(self.result())

    def test_duplicate_control_does_not_satisfy_manifest(self):
        self.controls[-1] = dict(self.controls[0])
        self.assertFalse(self.result())

    def test_empty_expected_suite_does_not_pass(self):
        self.expected.clear()
        self.negatives.clear()
        self.assertFalse(self.result())

    def test_every_existing_fixture_has_protected_expectation(self):
        suite = probe.cases()
        self.assertEqual(sum(len(c['phases']) for c in suite), 72)
        self.assertTrue(all(c['canonical_expected'] == 'reject_noncanonical' for c in suite))

    def test_safety_assertion_requires_phase_hook_and_real_status(self):
        row = {'phase': 'response', 'http_status': 503, 'client_marker_visible': False,
               'counts': {'request': 1, 'response': 1, 'upstream': 1}}
        self.assertTrue(probe.stock.rejected_without_leak(row))
        for change in ({'client_marker_visible':True}, {'http_status':200},
                       {'counts':{'request':1,'response':0,'upstream':1}}):
            self.assertFalse(probe.stock.rejected_without_leak(dict(row, **change)))

    def test_runtime_context_or_full_p0_are_not_reported_as_pass(self):
        source = Path(probe.__file__).read_text()
        for gate in ('G0-CONTEXT','G0-COVERAGE','G0-DEADLINE'):
            self.assertIn("'"+gate+"': 'NOT_EVALUATED'", source)


class PatchSafetyTests(unittest.TestCase):
    def test_refuse_different_upstream_without_partial_writes(self):
        with self.assertRaisesRegex(ValueError, 'UPSTREAM_SOURCE_MISMATCH'):
            patcher.patched_source(b'unreviewed code')

    def test_patch_requires_all_four_type_anchors(self):
        raw = b'not the audited structs'
        blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        with mock_patch.object(patcher, 'WEBHOOK_BLOB', blob), mock_patch.object(patcher, 'WEBHOOK_SHA256', patcher.sha256(raw)):
            with self.assertRaisesRegex(ValueError, 'PATCH_ANCHOR_MISMATCH'):
                patcher.patched_source(raw)

    def test_status_checks_must_cover_both_send_paths(self):
        source = Path(patcher.__file__).read_text()
        self.assertIn('text.count(anchor) != 2', source)
        self.assertIn('res.status() != ::http::StatusCode::OK', source)


if __name__ == '__main__':
    unittest.main()
