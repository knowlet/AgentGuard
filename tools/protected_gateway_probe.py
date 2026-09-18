"""Strict Gateway wire acceptance. Only a bound, independently built binary is accepted.

The trusted manifest digest must come from the caller's authenticated build job
or release catalog, never from an untrusted manifest submitted with the binary.
A wire PASS is not a complete P0 release, field-coverage proof or ASR benchmark.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from tools import gateway_probe as stock
from tools import patch_gateway as patch

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r'[0-9a-f]{64}')
FAULTS = ('http_500_allow', 'disconnect', 'timeout_allow')
EXTRA = ROOT / 'tests/fixtures/webhook-strict-extra.json'


def unique_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    def constant(_value):
        raise ValueError('NON_JSON_CONSTANT')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def validate_build(binary: bytes, raw: bytes, trusted_manifest_sha256: str) -> dict:
    if not isinstance(trusted_manifest_sha256, str) or not SHA.fullmatch(trusted_manifest_sha256):
        raise ValueError('TRUSTED_BUILD_REFERENCE_REQUIRED')
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 16384:
        raise ValueError('INVALID_BUILD_MANIFEST_SIZE')
    if patch.sha256(raw) != trusted_manifest_sha256:
        raise ValueError('BUILD_MANIFEST_HASH_MISMATCH')
    manifest = unique_json(raw)
    keys = {'kind', 'upstream_revision', 'upstream_webhook_blob', 'upstream_webhook_sha256',
            'patched_webhook_sha256', 'module_sha256', 'patcher_sha256', 'fixtures_sha256',
            'binary_sha256', 'agentguard_commit', 'rust_toolchain', 'build_profile',
            'target', 'features', 'default_features'}
    if not isinstance(manifest, dict) or set(manifest) != keys:
        raise ValueError('INVALID_BUILD_MANIFEST_SCHEMA')
    expected = {'kind': 'agentguard-gateway-build/v1', 'upstream_revision': patch.SOURCE_REVISION,
                'upstream_webhook_blob': patch.WEBHOOK_BLOB,
                'upstream_webhook_sha256': patch.WEBHOOK_SHA256,
                'patched_webhook_sha256': patch.PATCHED_WEBHOOK_SHA256,
                'module_sha256': patch.sha256(patch.MODULE.read_bytes()),
                'patcher_sha256': patch.sha256(Path(patch.__file__).read_bytes()),
                'fixtures_sha256': patch.sha256(patch.FIXTURES.read_bytes()),
                'rust_toolchain': '1.98.0', 'build_profile': 'dev',
                'target': 'x86_64-unknown-linux-gnu', 'features': ['crypto-aws-lc']}
    if any(manifest[k] != v for k, v in expected.items()) or manifest['default_features'] is not False:
        raise ValueError('BUILD_INPUT_BINDING_MISMATCH')
    if not isinstance(manifest['agentguard_commit'], str) or not re.fullmatch(r'[0-9a-f]{40}', manifest['agentguard_commit']):
        raise ValueError('BUILD_COMMIT_REQUIRED')
    for key in ('patched_webhook_sha256', 'binary_sha256'):
        if not isinstance(manifest[key], str) or not SHA.fullmatch(manifest[key]):
            raise ValueError('INVALID_BUILD_DIGEST')
    if not isinstance(binary, bytes) or not 0 < len(binary) <= 512 * 1024 * 1024:
        raise ValueError('INVALID_BINARY_SIZE')
    digest = patch.sha256(binary)
    if digest != manifest['binary_sha256'] or digest == stock.BINARY_SHA256:
        raise ValueError('BINARY_IDENTITY_MISMATCH_OR_STOCK_BUILD')
    return manifest


def cases():
    result = []
    identities = set()
    for source in (patch.FIXTURES, EXTRA):
        document = unique_json(source.read_bytes())
        if not isinstance(document, dict) or not isinstance(document.get('cases'), list) or not document['cases']:
            raise ValueError('EMPTY_OR_INVALID_CASE_MANIFEST')
        for case in document['cases']:
            if (not isinstance(case, dict) or case.get('canonical_expected') != 'reject_noncanonical'
                    or not isinstance(case.get('id'), str) or not case['id']
                    or not isinstance(case.get('raw'), str) or not case['raw']
                    or not isinstance(case.get('phases'), list) or not case['phases']
                    or any(p not in ('request', 'response') for p in case['phases'])
                    or len(case['phases']) != len(set(case['phases']))):
                raise ValueError('INVALID_CASE_CONTRACT')
            for phase in case['phases']:
                identity = phase + '/' + case['id']
                if identity in identities:
                    raise ValueError('DUPLICATE_CASE_IDENTITY')
                identities.add(identity)
            result.append(case)
    return result


def fault_handler(state):
    base = stock.handler_for(state)
    class Handler(base):
        def do_POST(self):
            with state.lock:
                fault = state.action if self.path == '/' + state.phase else None
                marker = state.marker
            if fault not in FAULTS:
                return super().do_POST()
            self.connection.settimeout(5)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= stock.LIMIT:
                self.send_error(400)
                return
            self.rfile.read(length)
            with state.lock:
                state.counts[self.path[1:]] += 1
            if fault == 'disconnect':
                self.close_connection = True
                return
            if fault == 'timeout_allow':
                # Delay beyond the pinned Gateway's 10s webhook timeout.
                # Never mutate shared trial state after this sleep.
                time.sleep(10.5)
            payload = json.dumps({'action': {'reason': 'FAULT_ALLOW_' + marker}}).encode()
            try:
                self.send_response(500 if fault == 'http_500_allow' else 200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('X-Fault-Canary', marker)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except OSError:
                pass
    return Handler


@contextmanager
def fixtures():
    state = stock.FixtureState()
    server = ThreadingHTTPServer(('127.0.0.1', 0), fault_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def observe(url, state, phase, action, raw=''):
    state.reset(phase, action, raw)
    payload = json.dumps({'model': 'fixture', 'stream': False,
                          'messages': stock.expected_messages(state.marker)}).encode()
    request = Request(url, data=payload, headers={'Content-Type': 'application/json'})
    start = time.monotonic()
    try:
        response = build_opener(ProxyHandler({})).open(request, timeout=15)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(stock.LIMIT + 1)
        if len(body) > stock.LIMIT:
            raise ValueError('OVERSIZE_CLIENT_RESPONSE')
        headers = '\r\n'.join(k + ': ' + v for k, v in response.headers.items()).encode()
        status = response.status
    try:
        decoded = unique_json(body)
    except (ValueError, UnicodeError, RecursionError):
        decoded = None
    with state.lock:
        content = 'prefix ' + state.marker + ' suffix' if phase == 'response' else 'fixture-ok'
        if action == 'mask' and phase == 'response':
            content = content.replace(state.marker, '[REDACTED]')
        request_marker = '[REDACTED]' if action == 'mask' and phase == 'request' else state.marker
        row = {'phase': phase, 'http_status': status, 'counts': dict(state.counts),
               'client_marker_visible': state.marker.encode() in body or state.marker.encode() in headers,
               'upstream_received_marker': state.upstream_received_marker,
               'request_structure_preserved': stock.valid_request_structure(state.upstream_payload, request_marker),
               'response_structure_preserved': stock.valid_response_structure(decoded, content),
               'client_body_sha256': patch.sha256(body), 'client_headers_sha256': patch.sha256(headers),
               'availability_fault': action in FAULTS,
               'elapsed_ms': round((time.monotonic() - start) * 1000, 3)}
    return row


def acceptance(controls: list, negatives: list, faults: list, expected: set[str]) -> bool:
    def identities(rows):
        return [r['id'] for r in rows]
    control_ids = {p + '_' + a for p in ('request', 'response') for a in ('allow', 'deny', 'mask')}
    fault_ids = {p + '/' + f for p in ('request', 'response') for f in FAULTS}
    if len(controls) != 6 or set(identities(controls)) != control_ids:
        return False
    if not expected or len(negatives) != len(expected) or set(identities(negatives)) != expected:
        return False
    if len(faults) != len(fault_ids) or set(identities(faults)) != fault_ids:
        return False
    return all(r.get('assertion_passed') is True for r in controls + negatives + faults)


def run(binary: Path, manifest_path: Path, trusted_hash: str, report_path: Path) -> int:
    def read_limited(path, limit):
        with path.open('rb') as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError('BUILD_INPUT_TOO_LARGE')
        return data
    binary_bytes = read_limited(binary, 512 * 1024 * 1024)
    manifest_raw = read_limited(manifest_path, 16384)
    manifest = validate_build(binary_bytes, manifest_raw, trusted_hash)
    suite = cases()
    controls, negatives, faults = [], [], []
    expected = {p + '/' + c['id'] for c in suite for p in c['phases']}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    observations = report_path.with_suffix('.observations.jsonl')
    observations.write_text('')
    def record(kind, row):
        with observations.open('a') as f:
            f.write(json.dumps({'kind': kind, **row}) + '\n')
    with fixtures() as (state, fixture_port), tempfile.TemporaryDirectory() as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = json.dumps(stock.gateway_config(port, fixture_port)).encode()
        config_path = Path(directory) / 'gateway.json'
        config_path.write_bytes(config)
        report_path.with_suffix('.config.json').write_bytes(config)
        executable = Path(directory) / 'agentgateway'
        executable.write_bytes(binary_bytes)
        executable.chmod(0o700)
        with report_path.with_suffix('.gateway.log').open('w') as log:
            process = subprocess.Popen([str(executable), '-f', str(config_path)], shell=False,
                stdout=log, stderr=subprocess.STDOUT,
                env={'PATH': os.environ.get('PATH', ''), 'HOME': directory, 'RUST_LOG': 'info'})
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError('GATEWAY_STARTUP_FAILED')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('GATEWAY_READINESS_TIMEOUT')
                        time.sleep(.1)
                url = f'http://127.0.0.1:{port}/v1/chat/completions'
                for phase in ('request', 'response'):
                    for action in ('allow', 'deny', 'mask'):
                        row = observe(url, state, phase, action)
                        row.update(id=f'{phase}_{action}', assertion_passed=stock.control_passes(row, action))
                        controls.append(row)
                        record('control', row)
                for case in suite:
                    for phase in case['phases']:
                        row = observe(url, state, phase, 'raw', case['raw'])
                        row.update(id=phase + '/' + case['id'], canonical_expected=case['canonical_expected'],
                            assertion_passed=stock.rejected_without_leak(row) and row['elapsed_ms'] < 5000)
                        negatives.append(row)
                        record('negative', row)
                for phase in ('request', 'response'):
                    for fault in FAULTS:
                        row = observe(url, state, phase, fault)
                        recovery = observe(url, state, phase, 'allow')
                        row.update(id=phase + '/' + fault, recovery_control=recovery, recovery_control_passed=stock.control_passes(recovery, 'allow'),
                            assertion_passed=stock.rejected_without_leak(row) and stock.control_passes(recovery, 'allow'))
                        faults.append(row)
                        record('fault', row)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    passed = acceptance(controls, negatives, faults, expected)
    report = {'kind': 'REAL_GATEWAY_PROTECTED_WIRE_ACCEPTANCE', 'build': manifest,
              'trusted_manifest_sha256': trusted_hash, 'config_sha256': patch.sha256(config),
              'runner_sha256': patch.sha256(Path(__file__).read_bytes()),
              'stock_helper_sha256': patch.sha256(Path(stock.__file__).read_bytes()),
              'extra_fixtures_sha256': patch.sha256(EXTRA.read_bytes()),
              'controls': controls, 'negative_cases': negatives, 'fault_cases': faults,
              'wire_acceptance': 'PASS' if passed else 'FAIL',
              'scope': 'nonstream-text-chat action boundary; client body+headers; isolated failClosed route',
              'p0_release_gate': 'NOT_EVALUATED', 'asr_fpr': 'NOT_EVALUATED',
              'G0-CONTEXT': 'NOT_EVALUATED', 'G0-COVERAGE': 'NOT_EVALUATED', 'G0-DEADLINE': 'NOT_EVALUATED'}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'wire_acceptance': report['wire_acceptance'], 'controls': len(controls),
        'negatives': len(negatives), 'faults': len(faults), 'p0_release_gate': 'NOT_EVALUATED'}))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway-bin', type=Path, required=True)
    parser.add_argument('--build-manifest', type=Path, required=True)
    parser.add_argument('--trusted-manifest-sha256', required=True)
    parser.add_argument('--report', type=Path, default=Path('reports/gateway-protected.json'))
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        return run(args.gateway_bin, args.build_manifest, args.trusted_manifest_sha256, args.report)
    except (OSError, ValueError, RuntimeError, RecursionError) as exc:
        args.report.write_text(json.dumps({'kind': 'REAL_GATEWAY_PROTECTED_WIRE_ACCEPTANCE',
            'wire_acceptance': 'ERROR', 'p0_release_gate': 'NOT_EVALUATED', 'error': str(exc)}, indent=2) + '\n')
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 2
    finally:
        log_path = args.report.with_suffix('.gateway.log')
        if log_path.is_file():
            print('=== Gateway process log ===', file=sys.stderr)
            with log_path.open(errors='replace') as log:
                print(log.read(stock.LIMIT), file=sys.stderr)


if __name__ == '__main__':
    raise SystemExit(main())
