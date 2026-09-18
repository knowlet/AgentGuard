"""Execute the build entrypoint with mocked compiler I/O, not workflow text matching."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import build_gateway as b
from tools import apply_gateway_patch as p


class BuildContract(unittest.TestCase):
    def setup_tree(self, root):
        source = root / 'upstream'; source.mkdir()
        raw = b'patched test code'
        for name in (p.WEBHOOK_PATH, p.WEBHOOK_PATH.replace('webhook.rs', 'agentguard_strict_wire.rs')):
            f = source / name; f.parent.mkdir(parents=True, exist_ok=True); f.write_bytes(raw)
        cargo = source / 'crates/agentgateway-app/Cargo.toml'; cargo.parent.mkdir(parents=True)
        cargo.write_text('[features]\ndefault = ["jemalloc","mimalloc","crypto-aws-lc"]\n')
        (source / 'Cargo.lock').write_text('test-lock')
        exe = source / 'target/debug/agentgateway'; exe.parent.mkdir(parents=True); exe.write_bytes(b'\x7fELFtest')
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps({'source_revision': p.UPSTREAM_REVISION,
            'patched_webhook_sha256': hashlib.sha256(raw).hexdigest(), 'decoder_sha256': hashlib.sha256(raw).hexdigest()}))
        return source, manifest, cargo

    def output(self, argv, **kwargs):
        if argv[-1] == 'HEAD' and 'rev-parse' in argv: return p.UPSTREAM_REVISION + '\n'
        if 'diff' in argv: return p.WEBHOOK_PATH + '\n' + p.WEBHOOK_PATH.replace('webhook.rs', 'agentguard_strict_wire.rs') + '\n'
        self.assertEqual(argv, ['rustc', '--version'])
        self.assertEqual(kwargs['env']['RUSTUP_TOOLCHAIN'], '1.98.0')
        return 'rustc 1.98.0 (test compiler)'

    def test_actual_argv_env_and_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            source, manifest, _ = self.setup_tree(Path(t))
            with patch.object(b.subprocess, 'check_output', side_effect=self.output), patch.object(b.subprocess, 'run') as run:
                result = b.build(source, manifest, Path(t) / 'output')
            self.assertEqual(run.call_args.args[0], ['cargo','build','--locked','-p','agentgateway-app','--bin','agentgateway'])
            self.assertFalse(run.call_args.kwargs['shell'])
            self.assertEqual(run.call_args.kwargs['env']['RUSTUP_TOOLCHAIN'], '1.98.0')
            self.assertEqual(result['build_features'], b.DEFAULT_FEATURES)
            self.assertEqual(result['suite']['phase_cases'], 84)

    def test_changed_default_features_never_invokes_compiler(self):
        with tempfile.TemporaryDirectory() as t:
            source, manifest, cargo = self.setup_tree(Path(t))
            cargo.write_text('[features]\ndefault=[]\n')
            with patch.object(b.subprocess, 'check_output', side_effect=self.output), patch.object(b.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'DEFAULT_FEATURES'):
                    b.build(source, manifest, Path(t) / 'output')
            run.assert_not_called()

    def test_wrong_toolchain_is_rejected(self):
        def bad(argv, **kwargs):
            return 'rustc 1.97.0 (wrong)' if argv[0] == 'rustc' else self.output(argv, **kwargs)
        with tempfile.TemporaryDirectory() as t:
            source, manifest, _ = self.setup_tree(Path(t))
            with patch.object(b.subprocess, 'check_output', side_effect=bad), patch.object(b.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'TOOLCHAIN'):
                    b.build(source, manifest, Path(t) / 'output')
            run.assert_not_called()
