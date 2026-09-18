"""Real Gateway request AND response CEL context slice, not full route approval."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from agentguard.context import HEADER_EXPRESSIONS, decide, validate_route
from tools import gateway_probe as stock
from tools.gateway_acceptance import verify_build
from tools.process_identity import wait_listener, require_listener

EXPECTED_CONTEXT = {'x-ag-original-path': '/v1/chat/completions',
                    'x-ag-original-media-type': 'application/json',
                    'x-ag-effective-stream': 'false', 'x-ag-requested-model': 'fixture'}

# Frozen identity registry. The gate is bound to THESE values, not to whatever
# cases() currently returns, so a shortened suite cannot validate itself.
PHASES = ('request', 'response')
CONTROL_CASE_IDS = ('valid', 'default_stream', 'spoofed_headers_overwritten',
                    'stream_true_spoofed_false', 'wrong_model_spoofed_fixture')
EXPECTED_MAPPING_HEADERS = ('x-ag-original-path', 'x-ag-original-media-type',
                            'x-ag-effective-stream', 'x-ag-requested-model')
MAPPING_FAILURES = ('missing', 'cel_error')
MAPPING_CASES_PER_PHASE = len(EXPECTED_MAPPING_HEADERS) * len(MAPPING_FAILURES) * 2
EXPECTED_CASE_COUNT = len(CONTROL_CASE_IDS) + len(PHASES) * MAPPING_CASES_PER_PHASE


def registered_ids() -> frozenset[str]:
    """Frozen case identities, derived from the registry rather than cases()."""
    ids = set(CONTROL_CASE_IDS)
    for phase in PHASES:
        for key in EXPECTED_MAPPING_HEADERS:
            for failure in MAPPING_FAILURES:
                for spoof in (False, True):
                    ids.add('_'.join((phase, failure, key, 'spoof' if spoof else 'plain')))
    return frozenset(ids)


def cases():
    if set(HEADER_EXPRESSIONS) != set(EXPECTED_MAPPING_HEADERS):
        raise ValueError('CONTEXT_MAPPING_CHANGED: review the header contract before changing the suite')
    result = [
        {'id': 'valid', 'stream': False, 'allow': True, 'reason': 'CONTEXT_ALLOW'},
        {'id': 'default_stream', 'allow': True, 'reason': 'CONTEXT_ALLOW'},
        {'id': 'spoofed_headers_overwritten', 'stream': False, 'spoof': True, 'allow': True, 'reason': 'CONTEXT_ALLOW'},
        {'id': 'stream_true_spoofed_false', 'stream': True, 'spoof': True, 'allow': False, 'reason': 'STREAMING_DENIED'},
        {'id': 'wrong_model_spoofed_fixture', 'stream': False, 'model': 'unapproved', 'spoof': True,
         'allow': False, 'reason': 'MODEL_DENIED'},
    ]
    for phase in PHASES:
        for key in EXPECTED_MAPPING_HEADERS:
            for failure in MAPPING_FAILURES:
                for spoof in (False, True):
                    result.append({'id': '_'.join((phase, failure, key, 'spoof' if spoof else 'plain')),
                                   'stream': False, 'header': key, 'mapping_phase': phase, 'spoof': spoof,
                                   'mapping_failure': failure, 'allow': False, 'reason': 'CONTEXT_UNAVAILABLE'})
    identities = [c['id'] for c in result]
    if (len(identities) != EXPECTED_CASE_COUNT or len(set(identities)) != EXPECTED_CASE_COUNT
            or set(identities) != registered_ids()):
        raise ValueError('CONTEXT_SUITE_CHANGED: review the registered suite before changing its size')
    return result


@contextmanager
def context_fixture():
    state = stock.FixtureState()
    # Positive controls emit an unpredictable marker in the upstream response.
    state.reset('response', 'allow', '')
    state.context_decisions = []
    base = stock.handler_for(state)
    class Handler(base):
        def do_POST(self):
            if self.path not in ('/request', '/response'):
                return super().do_POST()
            try:
                self.connection.settimeout(5)
                n = int(self.headers.get('Content-Length', '0'))
                if not 0 < n <= stock.LIMIT or len(self.rfile.read(n)) != n:
                    return self.send_error(400)
                phase = self.path[1:]
                allowed, reason, context = decide(self.headers)
                with state.lock:
                    state.counts[phase] += 1
                    state.context_decisions.append({'phase': phase, 'allow': allowed, 'reason': reason, 'context': context})
                action = {'reason': reason}
                if not allowed:
                    action.update(status_code=403, body='Blocked by context contract')
                raw = json.dumps({'action': action}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (OSError, ValueError):
                self.close_connection = True
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def case_passes(row: dict, case: dict) -> bool:
    """Recompute from phase-specific observations; flags/counts alone never suffice."""
    try:
        request_allowed = case['allow'] or case.get('mapping_phase') == 'response'
        phases = ['request', 'response'] if request_allowed else ['request']
        expected_counts = {'request': 1, 'response': int(request_allowed), 'upstream': int(request_allowed)}
        if (row.get('id') != case['id'] or row.get('process_listener_owned') is not True
            or row['preflight_rejected'] is not bool(case.get('mapping_failure'))
            or type(row['http_status']) is not int or row['http_status'] != (200 if case['allow'] else 403)
            or row['counts'] != expected_counts or not all(type(v) is int for v in row['counts'].values())
            or row['client_marker_visible'] is not case['allow']):
            return False
        decisions = row['observations']
        if type(decisions) is not list or len(decisions) != len(phases):
            return False
        for phase, decision in zip(phases, decisions):
            allowed = request_allowed if phase == 'request' else case['allow']
            if (decision['phase'] != phase or decision['allow'] is not allowed
                or decision['reason'] != ('CONTEXT_ALLOW' if allowed else case['reason'])):
                return False
            if allowed and decision['context'] != EXPECTED_CONTEXT:
                return False
            if not allowed and case['reason'] == 'CONTEXT_UNAVAILABLE' and decision['context'] != {}:
                return False
        if request_allowed and row['request_structure_preserved'] is not True:
            return False
        if case['allow'] and row['response_structure_preserved'] is not True:
            return False
        return True
    except (KeyError, TypeError, AttributeError):
        return False


def context_status(rows: list) -> str:
    expected = registered_ids()
    try:
        if type(rows) is not list or len(rows) != EXPECTED_CASE_COUNT or {r['id'] for r in rows} != set(expected):
            return 'FAIL'
        registered = {c['id']: c for c in cases()}
        if set(registered) != set(expected):
            return 'FAIL'
        return 'PASS' if all(case_passes(r, registered[r['id']]) for r in rows) else 'FAIL'
    except (KeyError, TypeError, ValueError):
        return 'FAIL'


def context_config(port: int, target: int, case: dict) -> dict:
    config = stock.gateway_config(port, target)
    route = config['binds'][0]['listeners'][0]['routes'][0]
    # Original-model profile explicitly prohibits provider overrides.
    route['backends'][0]['ai']['provider']['openAI'] = {}
    hooks = route['policies']['ai']['promptGuard']
    for phase in ('request', 'response'):
        mapping = dict(HEADER_EXPRESSIONS)
        if case.get('mapping_phase') == phase:
            if case['mapping_failure'] == 'missing':
                del mapping[case['header']]
            else:
                mapping[case['header']] = 'request.headers["x-never-present"]'
        # gateway_config shares its hook object across phases. Break that alias
        # explicitly so a response-only fault cannot corrupt request mappings.
        hooks[phase] = [{'webhook': dict(hooks[phase][0]['webhook'], headers=mapping)}]
    return config


def run_suite(data: bytes, build: dict, report_path: Path) -> dict:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases():
        with context_fixture() as (state, target), tempfile.TemporaryDirectory() as directory:
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
            config = context_config(port, target, case)
            route = config['binds'][0]['listeners'][0]['routes'][0]
            try:
                validate_route(route)
                preflight_rejected = False
            except ValueError:
                preflight_rejected = True
            # Rejected routes run ONLY for this explicit fault-injection test.
            cfg = Path(directory) / 'config.json'; cfg.write_text(json.dumps(config))
            saved_config = report_path.parent / (report_path.stem + '-' + case['id'] + '.config.json')
            saved_config.write_bytes(cfg.read_bytes())
            exe = Path(directory) / 'agentgateway'; exe.write_bytes(data); exe.chmod(0o700)
            log_path = saved_config.with_suffix('.gateway.log')
            with log_path.open('w') as log:
                # Exact verified bytes, fixed argv, no shell, no inherited client env.
                proc = subprocess.Popen([str(exe), '-f', str(cfg)], stdout=log, stderr=subprocess.STDOUT,
                                        shell=False, env={'HOME': directory, 'RUST_LOG': 'info'})
                try:
                    wait_listener(proc, exe, port)
                    payload = {'model': case.get('model', 'fixture'), 'messages': stock.expected_messages(state.marker)}
                    if 'stream' in case:
                        payload['stream'] = case['stream']
                    headers = {'Content-Type': 'application/json'}
                    if case.get('spoof'):
                        headers.update({k: 'spoof' for k in HEADER_EXPRESSIONS})
                        headers['x-ag-effective-stream'] = 'false'
                        headers['x-ag-requested-model'] = 'fixture'
                    opener = build_opener(ProxyHandler({}))
                    request = Request(f'http://127.0.0.1:{port}/v1/chat/completions',
                                      data=json.dumps(payload).encode(), headers=headers)
                    require_listener(proc, exe, port)
                    try:
                        response = opener.open(request, timeout=15)
                    except HTTPError as exc:
                        response = exc
                    with response:
                        body = response.read(stock.LIMIT + 1); status = response.status
                    if len(body) > stock.LIMIT:
                        raise ValueError('CONTEXT_RESPONSE_TOO_LARGE')
                    require_listener(proc, exe, port)
                    try:
                        decoded = json.loads(body)
                    except (ValueError, UnicodeError):
                        decoded = None
                    with state.lock:
                        observed = list(state.context_decisions); counts = dict(state.counts)
                        upstream = state.upstream_payload
                    row = {'id': case['id'], 'http_status': status, 'counts': counts,
                           'observations': observed, 'preflight_rejected': preflight_rejected,
                           'client_marker_visible': state.marker.encode() in body,
                           'request_structure_preserved': stock.valid_request_structure(upstream, state.marker),
                           'response_structure_preserved': stock.valid_response_structure(decoded, 'prefix ' + state.marker + ' suffix'),
                           'process_listener_owned': True, 'config_sha256': hashlib.sha256(cfg.read_bytes()).hexdigest(),
                           'config_file': saved_config.name, 'gateway_log_file': log_path.name,
                           'body_sha256': hashlib.sha256(body).hexdigest()}
                    row['assertion_passed'] = case_passes(row, case)
                    rows.append(row)
                finally:
                    proc.terminate()
                    try: proc.wait(timeout=5)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    result = {'kind': 'REAL_GATEWAY_CONTEXT_SLICE', 'build': build, 'cases': rows,
              'context_slice_gate': context_status(rows), 'phases': ['request', 'response'],
              'registered_cases': EXPECTED_CASE_COUNT,
              'p0_release_gate': 'NOT_EVALUATED', 'asr_fpr': 'NOT_EVALUATED', 'route_activation': 'NOT_IMPLEMENTED',
              'scope': 'original path/media/stream/model CEL mappings, both phases; no identity/coverage claim'}
    report_path.write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gateway-bin', type=Path, required=True)
    p.add_argument('--build-manifest', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    try:
        data, build = verify_build(a.gateway_bin, a.build_manifest)
        report = run_suite(data, build, a.report)
        print(json.dumps({'context_slice_gate': report['context_slice_gate'], 'cases': len(report['cases'])}))
        return 0 if report['context_slice_gate'] == 'PASS' else 1
    except (ValueError, OSError, RuntimeError) as exc:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps({'kind': 'REAL_GATEWAY_CONTEXT_SLICE', 'context_slice_gate': 'ERROR',
                                       'p0_release_gate': 'NOT_EVALUATED', 'error': str(exc)}) + '\n')
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
