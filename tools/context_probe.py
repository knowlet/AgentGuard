"""Real Gateway CEL/header slice of G0-CONTEXT; not route activation or full coverage."""
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
from agentguard.context import HEADER_EXPRESSIONS, decide, validate_config, validate_route
from tools import gateway_probe as stock
from tools.gateway_acceptance import verify_build
from tools.process_identity import wait_listener, require_listener


def cases():
    result = [
        {'id': 'valid', 'stream': False, 'allow': True, 'reason': 'CONTEXT_ALLOW'},
        {'id': 'default_stream', 'allow': True, 'reason': 'CONTEXT_ALLOW'},
        {'id': 'spoofed_headers_overwritten', 'stream': False, 'spoof': True, 'allow': True, 'reason': 'CONTEXT_ALLOW'},
        {'id': 'stream_true_spoofed_false', 'stream': True, 'spoof': True, 'allow': False, 'reason': 'STREAMING_DENIED'},
        {'id': 'wrong_model_spoofed_fixture', 'stream': False, 'model': 'unapproved', 'spoof': True,
         'allow': False, 'reason': 'MODEL_DENIED'},
    ]
    for key in HEADER_EXPRESSIONS:
        for failure in ('missing', 'cel_error'):
            result.append({'id': failure + '_' + key, 'stream': False, 'header': key,
                           'mapping_failure': failure, 'allow': False, 'reason': 'CONTEXT_UNAVAILABLE'})
    return result


@contextmanager
def context_fixture():
    state = stock.FixtureState()
    state.context_decisions = []
    base = stock.handler_for(state)
    class Handler(base):
        def do_POST(self):
            if self.path != '/request':
                return super().do_POST()
            self.connection.settimeout(5)
            n = int(self.headers.get('Content-Length', '0'))
            if not 0 < n <= stock.LIMIT:
                return self.send_error(400)
            self.rfile.read(n)
            allowed, reason, context = decide(self.headers)
            with state.lock:
                state.counts['request'] += 1
                state.context_decisions.append({'allow': allowed, 'reason': reason, 'context': context})
            action = {'reason': reason}
            if not allowed:
                action.update(status_code=403, body='Blocked by context contract')
            raw = json.dumps({'action': action}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def run_suite(data: bytes, build: dict, report_path: Path) -> dict:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases():
        with context_fixture() as (state, target), tempfile.TemporaryDirectory() as directory:
            config_headers = dict(HEADER_EXPRESSIONS)
            if case.get('mapping_failure') == 'missing':
                del config_headers[case['header']]
            elif case.get('mapping_failure') == 'cel_error':
                config_headers[case['header']] = 'request.headers["x-never-present"]'
            preflight_rejected = False
            try:
                validate_config(config_headers)
            except ValueError:
                preflight_rejected = True
            # Deliberately bypass rejected preflight ONLY in this fault-injection test.
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
            config = stock.gateway_config(port, target)
            route = config['binds'][0]['listeners'][0]['routes'][0]
            # llmRequest.model is evaluated after the provider's model override.
            # This original-model profile forbids that configuration, rather than silently mislabeling it.
            route['backends'][0]['ai']['provider']['openAI'] = {}
            hooks = route['policies']['ai']['promptGuard']
            for phase in ('request', 'response'):
                hooks[phase][0]['webhook']['headers'] = config_headers
            try:
                validate_route(route)
                route_rejected = False
            except ValueError:
                route_rejected = True
            if route_rejected != preflight_rejected:
                raise ValueError('CONTEXT_PREFLIGHT_INCONSISTENT')
            cfg = Path(directory) / 'config.json'; cfg.write_text(json.dumps(config))
            exe = Path(directory) / 'agentgateway'; exe.write_bytes(data); exe.chmod(0o700)
            log_path = report_path.parent / (report_path.stem + '-' + case['id'] + '.gateway.log')
            with log_path.open('w') as log:
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
                    require_listener(proc, exe, port)
                    with state.lock:
                        observed = list(state.context_decisions); counts = dict(state.counts)
                    ok = (len(observed) == 1 and observed[0]['allow'] is case['allow']
                          and observed[0]['reason'] == case['reason']
                          and status == (200 if case['allow'] else 403)
                          and counts['upstream'] == int(case['allow'])
                          and preflight_rejected == bool(case.get('mapping_failure')))
                    if case['allow']:
                        expected = {'x-ag-original-path': '/v1/chat/completions',
                                    'x-ag-original-media-type': 'application/json',
                                    'x-ag-effective-stream': 'false', 'x-ag-requested-model': 'fixture'}
                        ok &= observed[0]['context'] == expected
                    rows.append({'id': case['id'], 'assertion_passed': bool(ok), 'http_status': status,
                                 'counts': counts, 'observations': observed, 'preflight_rejected': preflight_rejected,
                                 'process_listener_owned': True, 'config_sha256': hashlib.sha256(cfg.read_bytes()).hexdigest(),
                                 'body_sha256': hashlib.sha256(body).hexdigest()})
                finally:
                    proc.terminate()
                    try: proc.wait(timeout=5)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    result = {'kind': 'REAL_GATEWAY_CONTEXT_SLICE', 'build': build, 'cases': rows,
              'context_slice_gate': 'PASS' if len(rows) == len(cases()) and all(r['assertion_passed'] for r in rows) else 'FAIL',
              'p0_release_gate': 'NOT_EVALUATED', 'asr_fpr': 'NOT_EVALUATED', 'route_activation': 'NOT_IMPLEMENTED',
              'scope': 'original path/media/stream/model CEL mappings on non-streaming chat fixtures; no identity/coverage claim'}
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
