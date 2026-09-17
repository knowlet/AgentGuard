"""Run isolated wire diagnostics against a real, checksum-pinned AgentGateway.

No LLM, GPU, credentials, third-party Python packages or simulated Gateway.
Default success means the STOCK VULNERABILITY was reproduced, not protection.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
BINARY_SHA256 = 'daca5cda76e8c5ab0c1a75912fecf2d6365095403f810db72029c49d14a37e7b'
LIMIT = 1024 * 1024


def replace_marker(value, marker, replacement):
    if isinstance(value, str):
        return value.replace(marker, replacement)
    if isinstance(value, list):
        return [replace_marker(v, marker, replacement) for v in value]
    if isinstance(value, dict):
        return {k: replace_marker(v, marker, replacement) for k, v in value.items()}
    return value


class FixtureState:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset('request', 'allow', '')

    def reset(self, phase, action, raw):
        with self.lock:
            self.phase, self.action, self.raw = phase, action, raw
            self.marker = secrets.token_hex(24)
            self.counts = {'request': 0, 'response': 0, 'upstream': 0}
            self.upstream_received_marker = False


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                self.connection.settimeout(5)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= LIMIT:
                    raise ValueError('invalid length')
                payload = json.loads(self.rfile.read(length))
                with state.lock:
                    if self.path in ('/request', '/response'):
                        phase = self.path[1:]
                        state.counts[phase] += 1
                        action = state.action if phase == state.phase else 'allow'
                        if action == 'raw':
                            raw = state.raw.encode()
                        elif action == 'deny':
                            raw = json.dumps({'action': {'reason': 'FIXTURE_DENY', 'status_code': 403,
                                                         'body': 'Fixture blocked'}}).encode()
                        elif action == 'mask':
                            raw = json.dumps({'action': {'reason': 'FIXTURE_MASK',
                                'body': replace_marker(payload['body'], state.marker, '[REDACTED]')}}).encode()
                        else:
                            raw = b'{"action":{"reason":"FIXTURE_ALLOW"}}'
                    elif self.path == '/v1/chat/completions':
                        state.counts['upstream'] += 1
                        state.upstream_received_marker = state.marker in json.dumps(payload)
                        content = state.marker if state.phase == 'response' else 'fixture-ok'
                        raw = json.dumps({'id': 'fixture', 'object': 'chat.completion', 'created': 1,
                            'model': 'fixture', 'choices': [{'index': 0,
                                'message': {'role': 'assistant', 'content': content},
                                'finish_reason': 'stop'}],
                            'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}).encode()
                    else:
                        self.send_error(404)
                        return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (ValueError, KeyError, OSError):
                self.send_error(400, 'Invalid fixture request')
    return Handler


@contextmanager
def fixture_server():
    state = FixtureState()
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def gateway_config(port, fixture_port):
    target = f'127.0.0.1:{fixture_port}'
    hook = {'webhook': {'target': {'host': target}, 'failureMode': 'failClosed'}}
    return {'binds': [{'port': port, 'listeners': [{'routes': [{
        'backends': [{'ai': {'name': 'fixture', 'hostOverride': target,
                            'provider': {'openAI': {'model': 'fixture'}}}}],
        'policies': {'ai': {'promptGuard': {'request': [hook], 'response': [hook]}}}
    }]}]}]}


def observe(url, state, phase, action, raw=''):
    state.reset(phase, action, raw)
    payload = json.dumps({'model': 'fixture', 'stream': False,
        'messages': [{'role': 'user', 'content': state.marker}]}).encode()
    start = time.monotonic()
    request = Request(url, data=payload, headers={'Content-Type': 'application/json'})
    # Never inherit HTTP_PROXY for an isolated loopback test.
    opener = build_opener(ProxyHandler({}))
    try:
        response = opener.open(request, timeout=15)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError('oversize gateway response')
        status = response.status
    with state.lock:
        result = {'phase': phase, 'http_status': status, 'counts': dict(state.counts),
                  'client_marker_visible': state.marker.encode() in body,
                  'upstream_received_marker': state.upstream_received_marker,
                  'client_body_sha256': hashlib.sha256(body).hexdigest(),
                  'elapsed_ms': round((time.monotonic() - start) * 1000, 3)}
    return result


def control_passes(row, action):
    count = row['counts']['upstream']
    if row['counts'][row['phase']] != 1:
        return False
    if action == 'deny':
        return row['http_status'] == 403 and count == (0 if row['phase'] == 'request' else 1) and not row['client_marker_visible']
    if row['http_status'] != 200 or count != 1 or row['counts'][row['phase']] != 1:
        return False
    if action == 'mask':
        return not row['upstream_received_marker'] if row['phase'] == 'request' else not row['client_marker_visible']
    return row['upstream_received_marker'] if row['phase'] == 'request' else row['client_marker_visible']


def run(binary: Path, report_path: Path, require_protected=False):
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != BINARY_SHA256:
        raise ValueError('unexpected Gateway binary; update pin and review before testing a different build')
    fixtures_path = ROOT / 'tests/fixtures/webhook-negative.json'
    fixture_bytes = fixtures_path.read_bytes()
    fixtures = json.loads(fixture_bytes)['cases']
    rows, controls, violations = [], [], []
    with fixture_server() as (state, fixture_port), tempfile.TemporaryDirectory() as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = json.dumps(gateway_config(port, fixture_port)).encode()
        config_path = Path(directory) / 'gateway.yaml'
        config_path.write_bytes(config)
        log_path = report_path.with_suffix('.gateway.log')
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open('w') as log:
            process = subprocess.Popen([str(binary.resolve()), '-f', str(config_path)],
                stdout=log, stderr=subprocess.STDOUT,
                env={'PATH': os.environ.get('PATH', ''), 'HOME': directory, 'RUST_LOG': 'info'})
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f'Gateway exited before readiness; see {log_path}')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('Gateway readiness deadline exceeded')
                        time.sleep(.1)
                url = f'http://127.0.0.1:{port}/v1/chat/completions'
                for phase in ('request', 'response'):
                    for action in ('allow', 'deny', 'mask'):
                        row = observe(url, state, phase, action)
                        row.update(id=f'{phase}_{action}', assertion_passed=control_passes(row, action))
                        controls.append(row)
                        if not row['assertion_passed']:
                            violations.append(row['id'])
                for case in fixtures:
                    for phase in case['phases']:
                        row = observe(url, state, phase, 'raw', case['raw'])
                        row.update(id=case['id'], source_expectation=case['stock_source_expectation'])
                        if row['counts'][phase] != 1:
                            violations.append(f'{phase}/{case["id"]}/hook_not_observed')
                        expected = case['stock_source_expectation']
                        if expected == 'pass' and not control_passes(row, 'allow'):
                            violations.append(f'{phase}/{case["id"]}/expected_stock_pass')
                        if expected == 'parse_error':
                            blocked = row['http_status'] >= 400 and not row['client_marker_visible']
                            blocked &= row['counts']['upstream'] == (0 if phase == 'request' else 1)
                            if not blocked:
                                violations.append(f'{phase}/{case["id"]}/expected_parse_rejection')
                        row['protected_assertion_passed'] = (
                            row['counts']['upstream'] == 0 if phase == 'request'
                            else not row['client_marker_visible'] and row['http_status'] >= 400)
                        rows.append(row)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    protection_failed = any(not r['protected_assertion_passed'] for r in rows)
    report = {'kind': 'REAL_GATEWAY_STOCK_DIAGNOSTIC', 'gateway_version': 'v1.5.0',
              'binary_sha256': digest, 'config_sha256': hashlib.sha256(config).hexdigest(),
              'fixtures_sha256': hashlib.sha256(fixture_bytes).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'controls': controls, 'negative_cases': rows, 'diagnostic_violations': violations,
              'diagnostic_status': 'FAIL' if violations else 'VULNERABILITY_REPRODUCED',
              'protected_wire_gate': 'FAIL' if protection_failed else 'NOT_EVALUATED',
              'p0_release_gate': 'NOT_EVALUATED', 'asr_fpr': 'NOT_EVALUATED'}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 1 if violations or require_protected else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway-bin', type=Path, required=True)
    parser.add_argument('--report', type=Path, default=Path('reports/gateway-stock.json'))
    parser.add_argument('--require-protected', action='store_true',
                        help='always nonzero until an independently verified protected runner exists')
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        return run(args.gateway_bin, args.report, args.require_protected)
    except (OSError, ValueError, RuntimeError) as exc:
        args.report.write_text(json.dumps({'kind': 'REAL_GATEWAY_STOCK_DIAGNOSTIC',
            'diagnostic_status': 'ERROR', 'p0_release_gate': 'NOT_EVALUATED', 'error': str(exc)}, indent=2) + '\n')
        print(f'ERROR: {exc}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
