"""Exercise a real temporary Git tree; only compiler execution is mocked."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools import build_gateway as b, apply_gateway_patch as p
from test_consolidated_reviews import tiny_upstream


class BuildContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.source = self.root / 'upstream'; self.source.mkdir()
        self.raw = tiny_upstream()
        self.webhook = self.source / p.WEBHOOK_PATH
        self.webhook.parent.mkdir(parents=True); self.webhook.write_bytes(self.raw)
        self.cargo = self.source / 'crates/agentgateway-app/Cargo.toml'; self.cargo.parent.mkdir(parents=True)
        self.cargo.write_text('[features]\ndefault = ["jemalloc","mimalloc","crypto-aws-lc"]\n')
        (self.source / 'Cargo.lock').write_text('test-lock')
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.source), *args], text=True).strip()
        self.git = git
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Unit', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
        for key, val in [('UPSTREAM_REVISION', git('rev-parse', 'HEAD')), ('WEBHOOK_BLOB', p.git_blob(self.raw))]:
            ctx = patch.object(p, key, val); ctx.start(); self.addCleanup(ctx.stop)
        self.manifest = self.root / 'manifest.json'
        p.apply(self.source, self.manifest)
        self.decoder = self.webhook.with_name('agentguard_strict_wire.rs')
        git('add', '-N', str(self.decoder.relative_to(self.source)))
        self.output = self.root / 'output'
        self.real_check = subprocess.check_output

    def checked(self, argv, **kwargs):
        if argv == ['rustc', '--version']:
            return 'rustc 1.98.0 (unit compiler)'
        return self.real_check(argv, **kwargs)

    def compile(self, argv, **kwargs):
        env = kwargs['env']
        target = Path(env['CARGO_TARGET_DIR']) / b.TARGET / 'debug/agentgateway'
        target.parent.mkdir(parents=True); target.write_bytes(b'\x7fELFunit-compiler-output')
        return subprocess.CompletedProcess(argv, 0)

    def call_build(self, compiler=None):
        with patch.object(b.subprocess, 'check_output', side_effect=self.checked), \
             patch.object(b, 'run_compiler', side_effect=compiler or self.compile) as run:
            result = b.build(self.source, self.manifest, self.output)
        return result, run

    def test_actual_argv_env_and_manifest(self):
        result, run = self.call_build()
        argv, env = run.call_args.args[0], run.call_args.kwargs['env']
        self.assertEqual(argv, b.ARGV + ['--target-dir', env['CARGO_TARGET_DIR']])
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertEqual(env['RUSTUP_TOOLCHAIN'], '1.98.0')
        self.assertEqual(result['build_features'], b.DEFAULT_FEATURES)
        self.assertEqual(result['build_target'], b.TARGET)
        self.assertEqual(result['suite']['phase_cases'], 84)
        self.assertFalse(Path(env['CARGO_TARGET_DIR']).exists())

    def test_forged_manifest_cannot_bless_modified_webhook_or_decoder(self):
        for target, key in [(self.webhook, 'patched_webhook_sha256'), (self.decoder, 'decoder_sha256')]:
            with self.subTest(key=key):
                original, manifest = target.read_bytes(), self.manifest.read_bytes()
                changed = original + b'\n// unreviewed modification\n'; target.write_bytes(changed)
                doc = json.loads(manifest); doc[key] = hashlib.sha256(changed).hexdigest()
                self.manifest.write_text(json.dumps(doc))
                with patch.object(b, 'run_compiler') as run:
                    with self.assertRaisesRegex(ValueError, 'BUILD_PATCH_MANIFEST_MISMATCH'):
                        b.build(self.source, self.manifest, self.output)
                    run.assert_not_called()
                target.write_bytes(original); self.manifest.write_bytes(manifest)

    def test_unmodified_manifest_does_not_hide_worktree_tampering(self):
        self.webhook.write_bytes(self.webhook.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'BUILD_PATCH_MISMATCH'):
            b.build(self.source, self.manifest, self.output)

    def test_index_flags_cannot_hide_modified_build_inputs(self):
        relative = 'crates/agentgateway-app/Cargo.toml'
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.cargo.write_text(self.cargo.read_text() + '# unreviewed build input\n')
                self.git('update-index', flag, relative)
                # `git diff` and `git status` omit flagged entries, so nothing
                # else reports this edit; only an explicit flag check stops it.
                self.assertNotIn(relative, self.git('diff', '--name-only', 'HEAD').splitlines())
                self.assertNotIn(relative, self.git('status', '--porcelain').splitlines())
                with patch.object(b.subprocess, 'check_output', side_effect=self.checked), \
                     patch.object(b, 'run_compiler', side_effect=self.compile) as run:
                    with self.assertRaisesRegex(ValueError, 'INDEX_FLAG'):
                        b.build(self.source, self.manifest, self.output)
                run.assert_not_called()
                self.assertFalse(self.output.exists())
                self.git('update-index', '--no-' + flag[2:], relative)
                self.cargo.write_text('[features]\ndefault = ["jemalloc","mimalloc","crypto-aws-lc"]\n')

    def test_changed_default_features_never_invokes_compiler(self):
        self.cargo.write_text('[features]\ndefault=[]\n')
        with patch.object(b, 'run_compiler') as run:
            with self.assertRaisesRegex(ValueError, 'DEFAULT_FEATURES'):
                b.build(self.source, self.manifest, self.output)
            run.assert_not_called()

    def test_untracked_and_ignored_build_inputs_are_rejected(self):
        directory = self.source / '.cargo'; directory.mkdir()
        (directory / 'config.toml').write_text('[build]\nrustflags=["--cfg=unreviewed"]\n')
        with self.assertRaisesRegex(ValueError, 'UNTRACKED'):
            b.build(self.source, self.manifest, self.output)
        (self.source / '.git/info/exclude').write_text('.cargo/\n')
        with self.assertRaisesRegex(ValueError, 'UNTRACKED'):
            b.build(self.source, self.manifest, self.output)

    def test_all_inherited_build_overrides_and_secrets_removed(self):
        polluted = {name: '/untrusted' for name in (
            'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_TARGET_DIR',
            'CARGO_BUILD_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR', 'CARGO_HOME',
            'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', 'RUSTC', 'RUSTFLAGS',
            'RUSTUP_TOOLCHAIN', 'CARGO_ENCODED_RUSTFLAGS', 'CC', 'CFLAGS', 'LD_PRELOAD', 'GH_TOKEN')}
        with patch.dict(os.environ, polluted):
            result, run = self.call_build()
        env = run.call_args.kwargs['env']
        for key in polluted:
            self.assertNotEqual(env.get(key), '/untrusted')
        self.assertEqual(result['build_environment_policy'], 'allowlist-v1-fresh-cargo-home-and-target')
        self.assertFalse(Path(env['CARGO_HOME']).exists())

    def test_wrong_toolchain_is_rejected(self):
        def wrong(argv, **kw):
            return 'rustc 1.98.1 (wrong)' if argv[0] == 'rustc' else self.real_check(argv, **kw)
        with patch.object(b.subprocess, 'check_output', side_effect=wrong), patch.object(b, 'run_compiler') as run:
            with self.assertRaisesRegex(ValueError, 'TOOLCHAIN'):
                b.build(self.source, self.manifest, self.output)
            run.assert_not_called()

    def test_build_script_source_mutation_prevents_publication(self):
        def evil(argv, **kw):
            result = self.compile(argv, **kw)
            self.webhook.write_bytes(self.webhook.read_bytes() + b'\nchanged during compilation')
            return result
        with self.assertRaisesRegex(ValueError, 'BUILD_PATCH_MISMATCH'):
            self.call_build(evil)
        self.assertFalse(self.output.exists())

    def test_failed_compilation_never_publishes_stale_binary(self):
        self.output.write_bytes(b'previous-output')
        def fail(argv, **kw):
            raise subprocess.CalledProcessError(7, argv)
        with self.assertRaises(subprocess.CalledProcessError):
            self.call_build(fail)
        self.assertEqual(self.output.read_bytes(), b'previous-output')
