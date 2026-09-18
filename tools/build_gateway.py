"""Build the exact reviewed patch, not the manifest's self-reported source bytes.

Build scripts run only on a trusted disposable runner. The runner's installed
compiler/linker, PATH and kernel are trust roots, not untrusted request inputs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from subprocess import run as run_compiler
import tempfile
import tomllib
from tools.atomic_files import write_set

TOOLCHAIN = '1.98.0'
TARGET = 'x86_64-unknown-linux-gnu'
DEFAULT_FEATURES = ['jemalloc', 'mimalloc', 'crypto-aws-lc']
ARGV = ['cargo', 'build', '--locked', '-p', 'agentgateway-app', '--bin', 'agentgateway', '--target', TARGET]


def verify_source(source: Path, info: dict) -> dict:
    from tools import apply_gateway_patch as patcher
    def git(*args, text=False):
        return subprocess.check_output(['git', '-C', str(source), *args], text=text,
                                       env=host_environment())
    revision = git('rev-parse', 'HEAD', text=True).strip()
    root = git('rev-parse', '--show-toplevel', text=True).strip()
    if Path(root).resolve() != source or revision != patcher.UPSTREAM_REVISION or info.get('source_revision') != revision:
        raise ValueError('BUILD_SOURCE_MISMATCH')
    # This bytestring comes from the pinned commit, NOT from the mutable manifest
    # or worktree. patched_source also checks the original Git blob before patching.
    original = git('show', f'{revision}:{patcher.WEBHOOK_PATH}')
    expected_webhook = patcher.patched_source(original)
    expected_decoder = (patcher.ROOT / 'patches/agentgateway-v1.5.0/strict_wire.rs').read_bytes()
    decoder_path = patcher.WEBHOOK_PATH.replace('webhook.rs', 'agentguard_strict_wire.rs')
    expected = {
        'patched_webhook_sha256': hashlib.sha256(expected_webhook).hexdigest(),
        'decoder_sha256': hashlib.sha256(expected_decoder).hexdigest(),
        'installer_sha256': hashlib.sha256(Path(patcher.__file__).read_bytes()).hexdigest(),
        'upstream_webhook_git_blob': patcher.git_blob(original),
    }
    if any(info.get(k) != v for k, v in expected.items()):
        raise ValueError('BUILD_PATCH_MANIFEST_MISMATCH')
    if (source / patcher.WEBHOOK_PATH).read_bytes() != expected_webhook or (source / decoder_path).read_bytes() != expected_decoder:
        raise ValueError('BUILD_PATCH_MISMATCH')
    cargo_path = source / 'crates/agentgateway-app/Cargo.toml'
    cargo = tomllib.loads(cargo_path.read_text())
    if cargo.get('features', {}).get('default') != DEFAULT_FEATURES:
        raise ValueError('BUILD_DEFAULT_FEATURES_MISMATCH')
    changed = git('diff', '--name-only', '-z', 'HEAD').split(b'\0')
    if set(filter(None, changed)) != {patcher.WEBHOOK_PATH.encode(), decoder_path.encode()}:
        raise ValueError('BUILD_UNREVIEWED_DIFF')
    # `git diff`/`git status` trust the index stat cache, so an entry flagged
    # assume-unchanged or skip-worktree hides its worktree edits from the check
    # above. Reject those flags instead of compiling unreviewed source.
    if patcher.hidden_index_entries(git('ls-files', '-v', '-z')):
        raise ValueError('BUILD_INDEX_FLAG_SET')
    # Also reject untracked/ignored Cargo config, build scripts and stale artifacts.
    # The installer caller marks the one new decoder with git add -N first.
    if git('ls-files', '--others', '-z'):
        raise ValueError('BUILD_UNREVIEWED_UNTRACKED')
    return expected


def host_environment() -> dict[str, str]:
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'SYSTEMROOT') if k in os.environ}
    if not env.get('HOME') or not env.get('PATH'):
        raise ValueError('BUILD_ENVIRONMENT_MISSING')
    return env


def build_environment(directory: Path) -> dict[str, str]:
    # An allowlist removes ALL Cargo/Rust overrides, plus CC/CFLAGS, wrappers,
    # linker/preload overrides and credentials. Do not load ~/.cargo/config either.
    env = host_environment()
    env.update(RUSTUP_TOOLCHAIN=TOOLCHAIN,
               RUSTUP_HOME=str(Path(env['HOME']) / '.rustup'),
               CARGO_HOME=str(directory / 'cargo-home'),
               CARGO_TARGET_DIR=str(directory / 'target'),
               CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0',
               CARGO_PROFILE_DEV_DEBUG='0', CARGO_NET_GIT_FETCH_WITH_CLI='true')
    return env


def build(source: Path, manifest: Path, binary: Path) -> dict:
    from tools.gateway_acceptance import suite_binding, unique_object
    source = source.resolve()
    raw = manifest.read_bytes()
    if len(raw) > 65536:
        raise ValueError('BUILD_MANIFEST_TOO_LARGE')
    info = json.loads(raw, object_pairs_hook=unique_object)
    if type(info) is not dict:
        raise ValueError('BUILD_MANIFEST_INVALID')
    expected = verify_source(source, info)
    with tempfile.TemporaryDirectory(prefix='agentguard-build-') as directory:
        env = build_environment(Path(directory))
        compiler = subprocess.check_output(['rustc', '--version'], cwd=source, env=env, text=True).strip()
        if not compiler.startswith('rustc 1.98.0 '):
            raise ValueError('BUILD_TOOLCHAIN_MISMATCH')
        # Fixed argv, never a shell. Neither CLI paths nor model/webhook input can
        # add Cargo flags; artifact paths and target are selected here.
        argv = ARGV + ['--target-dir', env['CARGO_TARGET_DIR']]
        run_compiler(argv, cwd=source, env=env, check=True, shell=False)
        data = (Path(env['CARGO_TARGET_DIR']) / TARGET / 'debug/agentgateway').read_bytes()
        if not data.startswith(b'\x7fELF'):
            raise ValueError('BUILD_NOT_ELF')
        # Cargo/build scripts may touch files. Revalidate before publishing outputs.
        verify_source(source, info)
    info.update(expected)
    info.update(binary_sha256=hashlib.sha256(data).hexdigest(), rustc=compiler,
                build_features=DEFAULT_FEATURES, toolchain=TOOLCHAIN, build_target=TARGET,
                cargo_lock_sha256=hashlib.sha256((source / 'Cargo.lock').read_bytes()).hexdigest(),
                app_cargo_sha256=hashlib.sha256((source / 'crates/agentgateway-app/Cargo.toml').read_bytes()).hexdigest(),
                build_environment_policy='allowlist-v1-fresh-cargo-home-and-target',
                suite=suite_binding(), build_scope='CI_TEST_BUILD_NOT_RELEASE_APPROVAL')
    write_set({binary: data, manifest: (json.dumps(info, indent=2) + '\n').encode()})
    binary.chmod(0o700)
    return info


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(build(a.source, a.manifest, a.binary), indent=2))
