"""Single executable build entrypoint with verified feature and toolchain selection."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib
from tools.atomic_files import write_set

TOOLCHAIN = '1.98.0'
DEFAULT_FEATURES = ['jemalloc', 'mimalloc', 'crypto-aws-lc']
ARGV = ['cargo', 'build', '--locked', '-p', 'agentgateway-app', '--bin', 'agentgateway']


def build(source: Path, manifest: Path, binary: Path) -> dict:
    from tools.apply_gateway_patch import UPSTREAM_REVISION, WEBHOOK_PATH
    from tools.gateway_acceptance import suite_binding
    source = source.resolve()
    info = json.loads(manifest.read_text())
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != UPSTREAM_REVISION or info.get('source_revision') != revision:
        raise ValueError('BUILD_SOURCE_MISMATCH')
    for path, key in [(source / WEBHOOK_PATH, 'patched_webhook_sha256'),
                      (source / WEBHOOK_PATH.replace('webhook.rs', 'agentguard_strict_wire.rs'), 'decoder_sha256')]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != info.get(key):
            raise ValueError('BUILD_PATCH_MISMATCH')
    cargo_path = source / 'crates/agentgateway-app/Cargo.toml'
    cargo = tomllib.loads(cargo_path.read_text())
    if cargo['features']['default'] != DEFAULT_FEATURES:
        raise ValueError('BUILD_DEFAULT_FEATURES_MISMATCH')
    # Only the reviewed two-file patch is allowed. Includes new decoder after git add -N.
    changed = subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only', 'HEAD'], text=True)
    if set(changed.splitlines()) != {WEBHOOK_PATH, WEBHOOK_PATH.replace('webhook.rs', 'agentguard_strict_wire.rs')}:
        raise ValueError('BUILD_UNREVIEWED_DIFF')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('RUST', 'CARGO_PROFILE', 'CARGO_ENCODED', 'LD_', 'DYLD_'))}
    env.update(RUSTUP_TOOLCHAIN=TOOLCHAIN, CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0',
               CARGO_PROFILE_DEV_DEBUG='0', CARGO_NET_GIT_FETCH_WITH_CLI='true')
    compiler = subprocess.check_output(['rustc', '--version'], cwd=source, env=env, text=True).strip()
    if not compiler.startswith('rustc 1.98.0 '):
        raise ValueError('BUILD_TOOLCHAIN_MISMATCH')
    subprocess.run(ARGV, cwd=source, env=env, check=True, shell=False)
    data = (source / 'target/debug/agentgateway').read_bytes()
    if not data.startswith(b'\x7fELF'):
        raise ValueError('BUILD_NOT_ELF')
    info.update(binary_sha256=hashlib.sha256(data).hexdigest(), rustc=compiler,
                build_features=DEFAULT_FEATURES, toolchain=TOOLCHAIN,
                cargo_lock_sha256=hashlib.sha256((source / 'Cargo.lock').read_bytes()).hexdigest(),
                app_cargo_sha256=hashlib.sha256(cargo_path.read_bytes()).hexdigest(),
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
