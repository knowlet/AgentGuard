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
import sys
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


def expected_messages(marker):
    return [{'role': 'system', 'content': 'Preserve this instruction.'},
            {'role': 'user', 'content': 'prefix ' + marker + ' suffix'}]


def valid_request_structure(payload, marker):
    return (isinstance(payload, dict) and payload.get('model') == 'fixture'
            and payload.get('messages') == expected_messages(marker))


def valid_response_structure(payload, content):
    if not isinstance(payload, dict):
        return False
    choices = payload.get('choices')
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        return False
    choice = choices[0]
    message = choice.get('message')
    return (isinstance(message, dict) and message.get('role') == 'assistant'
            and message.get('content') == content and choice.get('index') == 0
            and choice.get('finish_reason') == 'stop' and payload.get('model') == 'fixture'
            and payload.get('id') == 'fixture' and payload.get('object') == 'chat.completion'
            and payload.get('created') == 1
            and payload.get('usage') == {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2})


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
            self.upstream_payload = None


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
                        state.upstream_payload = payload
                        content = ('prefix ' + state.marker + ' suffix') if state.phase == 'response' else 'fixture-ok'
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
        'messages': expected_messages(state.marker)}).encode()
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
    try:
        decoded = json.loads(body)
    except (ValueError, UnicodeError):
        decoded = None
    with state.lock:
        original_content = 'prefix ' + state.marker + ' suffix' if phase == 'response' else 'fixture-ok'
        expected_content = original_content.replace(state.marker, '[REDACTED]') if action == 'mask' and phase == 'response' else original_content
        expected_request_marker = '[REDACTED]' if action == 'mask' and phase == 'request' else state.marker
        result = {'phase': phase, 'http_status': status, 'counts': dict(state.counts),
                  'client_marker_visible': state.marker.encode() in body,
                  'upstream_received_marker': state.upstream_received_marker,
                  'request_structure_preserved': valid_request_structure(state.upstream_payload, expected_request_marker),
                  'response_structure_preserved': valid_response_structure(decoded, expected_content),
                  'upstream_messages_empty': isinstance(state.upstream_payload, dict) and state.upstream_payload.get('messages') == [],
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
    if not row['request_structure_preserved'] or not row['response_structure_preserved']:
        return False
    if action == 'mask':
        return not row['upstream_received_marker'] if row['phase'] == 'request' else not row['client_marker_visible']
    return row['upstream_received_marker'] if row['phase'] == 'request' else row['client_marker_visible']


def rejected_without_leak(row):
    return (400 <= row['http_status'] <= 599 and not row['client_marker_visible']
            and row['counts'][row['phase']] == 1
            and row['counts']['upstream'] == (0 if row['phase'] == 'request' else 1))


def stock_assertion(row, expectation):
    """Wire observations only; never infer a Rust enum solely from HTTP status."""
    if expectation == 'not_verified' or expectation.endswith('_not_verified'):
        return None
    if expectation == 'pass':
        return control_passes(row, 'allow')
    if expectation == 'parse_error':
        return rejected_without_leak(row)
    if expectation == 'reject':
        return control_passes(row, 'deny')
    if expectation == 'reject_variant_not_http_assertion':
        # This exact fixture supplies status_code=200 and literal error body x.
        return (row['http_status'] == 200 and row['counts'][row['phase']] == 1
                and row['counts']['upstream'] == (0 if row['phase'] == 'request' else 1)
                and row['client_body_sha256'] == hashlib.sha256(b'x').hexdigest()
                and not row['client_marker_visible'])
    if expectation == 'mask':
        # The mixed fixture supplies an empty messages mutation plus status_code.
        # In the response phase that mutation has the wrong direction.
        if row['phase'] == 'response':
            return rejected_without_leak(row)
        return (row['http_status'] == 200 and row['counts']['request'] == 1
                and row['counts']['upstream'] == 1 and row['upstream_messages_empty'])
    raise ValueError('unknown fixture expectation: ' + expectation)


def run(binary: Path, report_path: Path, require_protected=False):
    binary_bytes = binary.read_bytes()
    digest = hashlib.sha256(binary_bytes).hexdigest()
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
        # Execute the exact verified bytes from our private temporary directory.
        # shell=False and a fixed argv eliminate shell interpretation; do not shlex-escape argv.
        verified_binary = Path(directory) / 'agentgateway'
        verified_binary.write_bytes(binary_bytes)
        verified_binary.chmod(0o700)
        log_path = report_path.with_suffix('.gateway.log')
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open('w') as log:
            process = subprocess.Popen([str(verified_binary), '-f', str(config_path)], shell=False,
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
                        observed = stock_assertion(row, expected)
                        row['stock_assertion_passed'] = observed
                        if observed is False:
                            violations.append(f'{phase}/{case["id"]}/stock_expectation_mismatch')
                        # Unknown source behavior remains visible but is not scored.
                        # A complete protected suite still cannot pass with missing evidence.
                        row['protected_assertion_passed'] = (rejected_without_leak(row)
                                                            if observed is not None else None)
                        rows.append(row)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    protection_failed = any(r['protected_assertion_passed'] is False for r in rows)
    reproduced = any(r['source_expectation'] == 'pass' and r['stock_assertion_passed'] is True for r in rows)
    if not reproduced:
        violations.append('no_vulnerability_reproduced')
    report = {'kind': 'REAL_GATEWAY_STOCK_DIAGNOSTIC', 'gateway_version': 'v1.5.0',
              'binary_sha256': digest, 'config_sha256': hashlib.sha256(config).hexdigest(),
              'fixtures_sha256': hashlib.sha256(fixture_bytes).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'controls': controls, 'negative_cases': rows, 'diagnostic_violations': violations,
              'unscored_negative_cases': sum(r['stock_assertion_passed'] is None for r in rows),
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
    finally:
        log_path = args.report.with_suffix('.gateway.log')
        if log_path.is_file():
            print('=== Gateway process log ===', file=sys.stderr)
            with log_path.open(errors='replace') as log:
                print(log.read(LIMIT), file=sys.stderr)


if __name__ == '__main__':
    raise SystemExit(main())
