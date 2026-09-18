"""Protected wire acceptance for the locally patched Gateway, not a full P0 gate.

Run only in a disposable test environment. The build manifest is a trusted local
CI input, not a signature or an authentication mechanism. No deployment activation.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

from tools import gateway_probe as stock
from tools.apply_gateway_patch import UPSTREAM_REVISION, WEBHOOK_BLOB

ROOT = Path(__file__).resolve().parents[1]
EXTRA_ACTIONS = (
    '{"reason":"ALLOW","body":null}',
    '{"reason":"ALLOW","status_code":null}',
    '{"reason":"ALLOW","body":"x"}',
    '{"reason":"ALLOW","status_code":403}',
    '{"reason":"DENY","body":"x","status_code":403.0}',
    '{"reason":"DENY","body":"x","status_code":399}',
    '{"reason":"DENY","body":"x","status_code":600}',
    '{"reason":"ALLOW","re\\u0061son":"ALLOW"}',
    '{"reason":"   "}',
    '{"reason":"MASK","body":[[{"role":"user","content":"x"}]]}',
    '{"reason":"MASK","body":{"messages":[["user","x"]]}}',
    '{"reason":"MASK","body":{"choices":[[{"role":"assistant","content":"x"}]]}}',
    '{"reason":"MASK","body":{"choices":[{"message":["assistant","x"]}]}}',
    '{"reason":"MASK","body":{"messages":[],"choices":[]}}',
    '{"reason":"MASK","body":{"messages":[{"role":"user","content":"x","content":"y"}]}}',
    '{"reason":"MASK","body":{"choices":[{"message":{"role":"assistant","content":"x","extra":1}}]}}',
    '{"reason":"MASK","body":{"messages":[{"role":"user","content":"x"}]},"status_code":403}',
)
EXTRA_ENVELOPES = (
    '[{"reason":"ALLOW"}]',
    '{"action":{"reason":"ALLOW"},"action":{"reason":"ALLOW"}}',
    '{"action":{"reason":"ALLOW"}} {}',
    '{"action":{"reason":"' + 'x' * 513 + '"}}',
)
FAULTS = ('http_error', 'non_json', 'disconnect', 'truncated')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest key')
        result[key] = value
    return result


def verify_build(binary: Path, manifest: Path) -> tuple[bytes, dict]:
    raw = manifest.read_bytes()
    if len(raw) > 65536:
        raise ValueError('build manifest too large')
    info = json.loads(raw, object_pairs_hook=unique_object)
    expected = {
        'kind': 'agentguard-gateway-patch/v1', 'source_revision': UPSTREAM_REVISION,
        'upstream_webhook_git_blob': WEBHOOK_BLOB,
        'decoder_sha256': hashlib.sha256((ROOT / 'patches/agentgateway-v1.5.0/strict_wire.rs').read_bytes()).hexdigest(),
        'installer_sha256': hashlib.sha256((ROOT / 'tools/apply_gateway_patch.py').read_bytes()).hexdigest(),
        'wire_profile': 'normalized-text-v1',
    }
    if not isinstance(info, dict) or any(info.get(k) != v for k, v in expected.items()):
        raise ValueError('build provenance does not match this source checkout')
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != info.get('binary_sha256'):
        raise ValueError('built binary hash mismatch')
    if info['binary_sha256'] == stock.BINARY_SHA256:
        raise ValueError('stock binary is not a patched build')
    return data, info


@contextmanager
def fixtures():
    state = stock.FixtureState()
    base = stock.handler_for(state)
    class Handler(base):
        def do_POST(self):
            with state.lock:
                active = self.path == '/' + state.phase and state.action in FAULTS
                fault = state.action
                if active:
                    state.counts[state.phase] += 1
            if not active:
                return super().do_POST()
            self.connection.settimeout(5)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= stock.LIMIT:
                return self.send_error(400)
            self.rfile.read(length)
            if fault == 'disconnect':
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            # An HTTP error carries VALID allow JSON: status and JSON failures are isolated.
            if fault == 'http_error':
                raw = b'{"action":{"reason":"FAULT_MUST_NOT_ALLOW"}}'
            else:
                raw = b'invalid-json' if fault == 'non_json' else b'{"action":'
            self.send_response(500 if fault == 'http_error' else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw) + (50 if fault == 'truncated' else 0)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def negative_cases() -> list[dict]:
    cases = json.loads((ROOT / 'tests/fixtures/webhook-negative.json').read_text())['cases']
    cases = [dict(c) for c in cases]
    for i, raw in enumerate(['{"action":' + a + '}' for a in EXTRA_ACTIONS] + list(EXTRA_ENVELOPES)):
        cases.append({'id': f'strict_{i}', 'raw': raw, 'phases': ['request', 'response']})
    # The expected behavior is independent of old stock_source_expectation.
    return cases


def strict_rejection(row: dict) -> bool:
    try:
        phase = row['phase']
        if phase not in ('request', 'response'):
            return False
        expected = {'request': 1, 'response': 0 if phase == 'request' else 1,
                    'upstream': 0 if phase == 'request' else 1}
        return row['counts'] == expected and stock.rejected_without_leak(row)
    except (KeyError, TypeError):
        return False


def acceptance_status(controls: list, rows: list, faults: list, cases: list | None = None) -> str:
    """Require exact case identity and recompute assertions from observations, not flags."""
    if cases is None:
        cases = negative_cases()
    expected_rows = {(c['id'], phase) for c in cases for phase in c['phases']}
    expected_controls = {(phase + '_' + action, phase) for phase in ('request', 'response')
                         for action in ('allow', 'deny', 'mask')}
    expected_faults = {(fault, phase) for fault in FAULTS for phase in ('request', 'response')}
    for group, expected in ((controls, expected_controls), (rows, expected_rows), (faults, expected_faults)):
        if not isinstance(group, list) or len(group) != len(expected):
            return 'FAIL'
        try:
            if {(r['id'], r['phase']) for r in group} != expected:
                return 'FAIL'
            if not all(r.get('assertion_passed') is True for r in group):
                return 'FAIL'
        except (KeyError, TypeError, AttributeError):
            return 'FAIL'
    try:
        if not all(stock.control_passes(r, r['id'].split('_', 1)[1]) for r in controls):
            return 'FAIL'
        if not all(strict_rejection(r) for r in rows + faults):
            return 'FAIL'
    except (KeyError, TypeError):
        return 'FAIL'
    return 'PASS'


def run(binary: Path, manifest: Path, report_path: Path) -> int:
    data, build = verify_build(binary, manifest)
    cases = negative_cases()
    controls, rows, fault_rows = [], [], []
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = report_path.with_suffix('.gateway.log')
    with fixtures() as (state, fixture_port), tempfile.TemporaryDirectory() as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = json.dumps(stock.gateway_config(port, fixture_port)).encode()
        config_path = Path(directory) / 'gateway.yaml'
        config_path.write_bytes(config)
        report_path.with_suffix('.config.json').write_bytes(config)
        exe = Path(directory) / 'agentgateway'
        exe.write_bytes(data)
        exe.chmod(0o700)
        with log_path.open('w') as log:
            process = subprocess.Popen([str(exe), '-f', str(config_path)], shell=False,
                stdout=log, stderr=subprocess.STDOUT,
                env={'PATH': os.environ.get('PATH', ''), 'HOME': directory, 'RUST_LOG': 'info'})
            try:
                import time
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise RuntimeError('patched Gateway exited before readiness')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError('patched Gateway readiness timeout')
                        time.sleep(.1)
                url = f'http://127.0.0.1:{port}/v1/chat/completions'
                for phase in ('request', 'response'):
                    for action in ('allow', 'deny', 'mask'):
                        row = stock.observe(url, state, phase, action)
                        row.update(id=phase + '_' + action, assertion_passed=stock.control_passes(row, action))
                        controls.append(row)
                for case in cases:
                    for phase in case['phases']:
                        row = stock.observe(url, state, phase, 'raw', case['raw'])
                        row.update(id=case['id'], assertion_passed=strict_rejection(row))
                        rows.append(row)
                for phase in ('request', 'response'):
                    for fault in FAULTS:
                        row = stock.observe(url, state, phase, fault)
                        row.update(id=fault, assertion_passed=strict_rejection(row),
                                   outcome_class='availability_fault')
                        fault_rows.append(row)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    status = acceptance_status(controls, rows, fault_rows, cases)
    report = {'kind': 'REAL_GATEWAY_PATCHED_WIRE_ACCEPTANCE', 'build': build,
        'config_sha256': hashlib.sha256(config).hexdigest(),
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'base_probe_sha256': hashlib.sha256(Path(stock.__file__).read_bytes()).hexdigest(),
        'cases_sha256': hashlib.sha256(json.dumps(cases, sort_keys=True).encode()).hexdigest(),
        'controls': controls, 'negative_cases': rows, 'fault_cases': fault_rows,
        'protected_wire_gate': status, 'scope': 'normalized-text-v1 webhook wire only',
        'p0_release_gate': 'NOT_EVALUATED', 'asr_fpr': 'NOT_EVALUATED',
        'provenance_authentication': 'TRUSTED_CI_INPUT_NOT_SIGNED',
        'limitations': ['no original-request coverage evidence', 'no deployment activation',
                        'no complete deadline/load suite', 'no MCP enforcement claim']}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'wire_gate': status, 'controls': len(controls), 'negatives': len(rows),
                      'transport_faults': len(fault_rows), 'p0_release_gate': 'NOT_EVALUATED'}))
    return 0 if status == 'PASS' else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gateway-bin', type=Path, required=True)
    p.add_argument('--build-manifest', type=Path, required=True)
    p.add_argument('--report', type=Path, default=Path('reports/gateway-patched.json'))
    args = p.parse_args()
    try:
        return run(args.gateway_bin, args.build_manifest, args.report)
    except (OSError, ValueError, RuntimeError) as exc:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'kind': 'REAL_GATEWAY_PATCHED_WIRE_ACCEPTANCE',
            'protected_wire_gate': 'ERROR', 'p0_release_gate': 'NOT_EVALUATED', 'error': str(exc)}) + '\n')
        print(f'ERROR: {exc}')
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
