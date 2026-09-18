"""Guard-deadline slice on a real patched Gateway: below, at and above budget.

The webhook fixture models the guard adapter: it consumes a DECLARED stage
latency and answers fail-closed with GUARD_DEADLINE_EXCEEDED once that declared
latency exceeds the declared guard budget. The declared value drives the decision
so the boundary comparison is deterministic; wall-clock elapsed time is still
observed and asserted.

A guard outcome and a Gateway outcome are never interchangeable, and neither is
inferred from timing alone:

* guard outcome  - the decision reached the Gateway (delivered), and the
  Gateway's own access log records the guardrail reject or the allow;
* Gateway outcome - the hook never answered, and the Gateway's own log has to say
  why: "upstream call timeout" versus a premature connection close.

This is a fixture-modelled adapter on the context-preflighted route, not a real
detector, not a latency SLO, and not a complete G0-DEADLINE evaluation.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from agentguard.context import validate_route
from agentguard.deadline import (DECLARED_BUDGET_MS, DECLARED_GUARD_BUDGET_MS,
                                GATEWAY_WEBHOOK_TIMEOUT_MS, GUARD_DEADLINE_EXCEEDED,
                                SAFETY_MARGIN_MS, TRANSPORT_RESERVE_MS, over_budget,
                                validate_budget)
from tools import gateway_probe as stock
from tools.context_probe import context_config
from tools.gateway_acceptance import verify_build
from tools.process_identity import require_listener, wait_listener

GUARD_DENIAL_BODY = b'Guard deadline exceeded'
# The Gateway-side boundary. These bounds are sanity checks only; the REASON comes
# from the Gateway's own log evidence below, never from an elapsed-time window.
TIMEOUT_MIN_MS = 9000
TIMEOUT_MAX_MS = 16000
# A hook that dies just before the timeout must not be counted as a timeout.
EARLY_DISCONNECT_MS = 9000
LOG_SETTLE_SECONDS = 3.0
EXPECTED_CASE_COUNT = 9
AVAILABILITY_FAULTS = ('gateway_timeout', 'upstream_transport_fault')
EXPECTED_CLASS = {'allow': 'allow', 'guard_deny': 'guard_deadline_decision',
                  'gateway_timeout': 'gateway_timeout',
                  'transport_disconnect': 'upstream_transport_fault'}
# Gateway log evidence, per phase. The matched marker NAMES are recorded in the
# report so a reviewer re-checks the classification instead of trusting timing.
GATEWAY_MARKERS = {
    'timeout': {
        'request': b'failed to call prompt guard webhook: upstream call timeout',
        'response': b'failed to apply response prompt guard: upstream call timeout'},
    'transport': {
        'request': b'failed to call prompt guard webhook: upstream call failed: SendRequest: connection closed before message completed',
        'response': b'failed to apply response prompt guard: upstream call failed: SendRequest: connection closed before message completed'},
    'guardrail_reject': {
        'request': b'"phase": "request", "guard": "webhook", "action": "reject"',
        'response': b'"phase": "response", "guard": "webhook", "action": "reject"'},
}
# The GATE's expectation: (id, slow phase, declared stage ms, expected class). It is
# a separate literal from the runner registry below and is pinned by its own digest,
# so editing what the runner executes cannot redefine what the gate accepts. Update
# the digest only as part of a reviewed suite change.
EXPECTED_CONTRACT = (
    ('inside_budget_request', 'request', 1200, 'allow'),
    ('inside_budget_response', 'response', 1200, 'allow'),
    ('at_budget_boundary_request', 'request', DECLARED_GUARD_BUDGET_MS, 'allow'),
    ('just_over_budget_request', 'request', DECLARED_GUARD_BUDGET_MS + 1, 'guard_deadline_decision'),
    ('just_over_budget_response', 'response', DECLARED_GUARD_BUDGET_MS + 1, 'guard_deadline_decision'),
    ('over_budget_request', 'request', 4000, 'guard_deadline_decision'),
    ('unbounded_stage_timeout_request', 'request', 11000, 'gateway_timeout'),
    ('unbounded_stage_timeout_response', 'response', 11000, 'gateway_timeout'),
    ('early_disconnect_request', 'request', EARLY_DISCONNECT_MS, 'upstream_transport_fault'),
)
EXPECTED_CONTRACT_SHA256 = '535cffdaa5d479cfc6bdcb972eb0eeceb7fc6ed2e7ec1ec366cccd305943a8bf'
# The RUNNER's registry: the same cases, expressed as the outcomes the fixture
# reproduces. cases() refuses to run unless it agrees with the contract above.
REGISTERED_CASES = (
    ('inside_budget_request', 'request', 1200, 'allow'),
    ('inside_budget_response', 'response', 1200, 'allow'),
    ('at_budget_boundary_request', 'request', DECLARED_GUARD_BUDGET_MS, 'allow'),
    ('just_over_budget_request', 'request', DECLARED_GUARD_BUDGET_MS + 1, 'guard_deny'),
    ('just_over_budget_response', 'response', DECLARED_GUARD_BUDGET_MS + 1, 'guard_deny'),
    ('over_budget_request', 'request', 4000, 'guard_deny'),
    ('unbounded_stage_timeout_request', 'request', 11000, 'gateway_timeout'),
    ('unbounded_stage_timeout_response', 'response', 11000, 'gateway_timeout'),
    ('early_disconnect_request', 'request', EARLY_DISCONNECT_MS, 'transport_disconnect'),
)


def contract_digest(contract=None) -> str:
    # Resolved at call time so patching the module constant is observable.
    contract = EXPECTED_CONTRACT if contract is None else contract
    return hashlib.sha256(json.dumps([list(case) for case in contract]).encode()).hexdigest()


def contract_matches_pin() -> bool:
    return contract_digest() == EXPECTED_CONTRACT_SHA256


def registered_ids() -> frozenset[str]:
    return frozenset(case[0] for case in EXPECTED_CONTRACT)


def registered_cases() -> list[dict]:
    """The gate's own view of the suite: built from the pinned contract."""
    return [{'id': i, 'phase': p, 'stage_ms': s, 'expected_class': k} for i, p, s, k in EXPECTED_CONTRACT]


def runner_cases() -> list[dict]:
    return [{'id': i, 'phase': p, 'stage_ms': s, 'outcome': o,
             'expected_class': EXPECTED_CLASS[o]} for i, p, s, o in REGISTERED_CASES]


def registries_agree() -> bool:
    """Both registries must exist, match the pinned digest and describe one suite."""
    try:
        expected, runner = registered_cases(), runner_cases()
    except (KeyError, TypeError, ValueError):
        return False
    if not contract_matches_pin():
        return False
    if [c['id'] for c in expected] != [c['id'] for c in runner]:
        return False
    return all((e['phase'], e['stage_ms'], e['expected_class']) == (r['phase'], r['stage_ms'], r['expected_class'])
               for e, r in zip(expected, runner))


def _validate_contract(contract) -> None:
    """Refuse a contract whose declared boundary contradicts its expectation."""
    ids = [case[0] for case in contract]
    if len(ids) != EXPECTED_CASE_COUNT or len(set(ids)) != EXPECTED_CASE_COUNT:
        raise ValueError('DEADLINE_SUITE_CHANGED: review the registered suite before changing its size')
    for _id, phase, stage_ms, expected_class in contract:
        if phase not in ('request', 'response') or expected_class not in set(EXPECTED_CLASS.values()):
            raise ValueError('DEADLINE_CASE_INVALID')
        if type(stage_ms) is not int or stage_ms < 0:
            raise ValueError('DEADLINE_CASE_INVALID')
        if expected_class == 'allow' and over_budget(stage_ms):
            raise ValueError('DEADLINE_CASE_INVALID')
        if expected_class == 'guard_deadline_decision' and not over_budget(stage_ms):
            raise ValueError('DEADLINE_CASE_INVALID')
        if expected_class == 'gateway_timeout' and stage_ms <= GATEWAY_WEBHOOK_TIMEOUT_MS:
            raise ValueError('DEADLINE_CASE_INVALID')
        # The negative control has to sit late enough to race the timeout, but
        # before it, otherwise it would not distinguish the two failure modes.
        if expected_class == 'upstream_transport_fault' and not TIMEOUT_MIN_MS <= stage_ms < GATEWAY_WEBHOOK_TIMEOUT_MS:
            raise ValueError('DEADLINE_CASE_INVALID')


def cases() -> list[dict]:
    """Runner cases; refused unless the contract and runner registry both agree."""
    if not contract_matches_pin():
        raise ValueError('DEADLINE_CONTRACT_CHANGED: review the expected contract before changing the suite')
    _validate_contract(EXPECTED_CONTRACT)
    try:
        runner = tuple((i, p, s, EXPECTED_CLASS[o]) for i, p, s, o in REGISTERED_CASES)
    except KeyError as exc:
        raise ValueError('DEADLINE_CASE_INVALID') from exc
    _validate_contract(runner)
    if not registries_agree():
        raise ValueError('DEADLINE_RUNNER_REGISTRY_MISMATCH: the runner and gate registries must agree')
    if validate_budget(DECLARED_BUDGET_MS, TRANSPORT_RESERVE_MS, SAFETY_MARGIN_MS) != DECLARED_GUARD_BUDGET_MS:
        raise ValueError('DEADLINE_DECLARATION_MISMATCH')
    return runner_cases()


def expected_counts(case: dict) -> dict:
    # Both hooks run for an allowed request; any stop ends the phases after it.
    if case['expected_class'] == 'allow':
        return {'request': 1, 'response': 1, 'upstream': 1}
    return ({'request': 1, 'response': 0, 'upstream': 0} if case['phase'] == 'request'
            else {'request': 1, 'response': 1, 'upstream': 1})


def expected_hook_calls(case: dict) -> int:
    """Only hooks answer; the upstream counter is not a guard decision."""
    counts = expected_counts(case)
    return counts['request'] + counts['response']


def decision_contract(case: dict) -> list[dict]:
    """Exact ordered decision contract: phase identity, order, role and delivery."""
    expected_class = case['expected_class']
    counts = expected_counts(case)
    contract = []
    for phase in ('request', 'response'):
        if counts[phase] == 0:
            continue
        slow = phase == case['phase']
        entry = {'phase': phase, 'stage_ms': case['stage_ms'] if slow else 0,
                 'allowed': True, 'reason': 'FIXTURE_ALLOW',
                 'delivered': True, 'decision_write': 'ok'}
        if slow and expected_class == 'guard_deadline_decision':
            entry.update(allowed=False, reason=GUARD_DEADLINE_EXCEEDED)
        if slow and expected_class in AVAILABILITY_FAULTS:
            # The adapter exceeded its budget but the answer never reached the
            # Gateway: written-but-unread for a Gateway timeout, never written for
            # a hook that died first.
            entry.update(allowed=False, reason=GUARD_DEADLINE_EXCEEDED, delivered=False,
                         decision_write='failed' if expected_class == 'gateway_timeout' else 'not_attempted')
        contract.append(entry)
    return contract


def decisions_match(row: dict, case: dict) -> bool:
    """Compare every registered field of every decision, in order."""
    expected = decision_contract(case)
    actual = row.get('guard_decisions')
    if type(actual) is not list or len(actual) != len(expected):
        return False
    for want, got in zip(expected, actual):
        if type(got) is not dict:
            return False
        for key, value in want.items():
            if got.get(key) != value or type(got.get(key)) is not type(value):
                return False
    return True


def gateway_evidence_matches(row: dict, case: dict) -> bool:
    """The Gateway log, not the clock, decides which failure this was."""
    markers = row.get('gateway_markers')
    if type(markers) is not list or any(type(m) is not str for m in markers):
        return False
    phase = case['phase']
    expected_class = case['expected_class']
    if expected_class == 'gateway_timeout':
        return markers == ['timeout:' + phase]
    if expected_class == 'upstream_transport_fault':
        return markers == ['transport:' + phase]
    if expected_class == 'guard_deadline_decision':
        return markers == ['guardrail_reject:' + phase]
    if expected_class == 'allow':
        return markers == []
    return False


def classify(row: dict) -> str:
    """Derive the outcome from observations; never read a self-reported class."""
    decisions = row.get('guard_decisions')
    if type(decisions) is not list or type(row.get('counts')) is not dict:
        return 'UNKNOWN'
    delivered = [d for d in decisions if isinstance(d, dict) and d.get('delivered') is True]
    last = decisions[-1] if decisions else None
    if isinstance(last, dict) and last.get('delivered') is False:
        # The last phase never answered, so the Gateway produced the result and only
        # its own log can name the reason.
        markers = row.get('gateway_markers')
        if type(markers) is not list:
            return 'UNKNOWN'
        if markers == ['timeout:' + str(row.get('phase'))]:
            return 'gateway_timeout'
        if markers == ['transport:' + str(row.get('phase'))]:
            return 'upstream_transport_fault'
        return 'UNKNOWN'
    if delivered and delivered[-1].get('allowed') is False and delivered[-1].get('reason') == GUARD_DEADLINE_EXCEEDED:
        return 'guard_deadline_decision'
    if delivered and all(d.get('allowed') is True for d in delivered) and row.get('http_status') == 200:
        return 'allow'
    return 'UNKNOWN'


def case_passes(row: dict, case: dict) -> bool:
    try:
        # Bind the row's own metadata too: id and phase identify which case these
        # observations belong to, so neither may drift from the contract.
        if (row.get('id') != case['id'] or row.get('phase') != case['phase']
                or row.get('process_listener_owned') is not True):
            return False
        if type(row['http_status']) is not int or type(row['elapsed_ms']) not in (int, float):
            return False
        if type(row['counts']) is not dict or any(type(v) is not int for v in row['counts'].values()):
            return False
        if row['counts'] != expected_counts(case):
            return False
        # The Gateway's own access log must agree with what the client observed.
        if row.get('gateway_http_status') != row['http_status']:
            return False
        if not decisions_match(row, case) or not gateway_evidence_matches(row, case):
            return False
        if classify(row) != case['expected_class']:
            return False
        if case['expected_class'] == 'allow':
            return stock.control_passes(row, 'allow') and row['elapsed_ms'] < TIMEOUT_MIN_MS
        if case['expected_class'] == 'guard_deadline_decision':
            return (row['http_status'] == 503 and row['client_marker_visible'] is False
                    and row['client_body_is_guard_denial'] is True
                    and 0 < row['elapsed_ms'] < TIMEOUT_MIN_MS)
        if case['expected_class'] in AVAILABILITY_FAULTS:
            return (400 <= row['http_status'] <= 599 and row['client_marker_visible'] is False
                    and row['client_body_is_guard_denial'] is False
                    and TIMEOUT_MIN_MS <= row['elapsed_ms'] <= TIMEOUT_MAX_MS
                    and row.get('gateway_log_bytes', 0) > 0)
        return False
    except (KeyError, TypeError, AttributeError):
        return False


def deadline_status(rows: list) -> str:
    """Bind the gate to the pinned contract, never to the runner registry."""
    expected = registered_cases()
    try:
        _validate_contract(EXPECTED_CONTRACT)
        if not registries_agree():
            return 'FAIL'
        if type(rows) is not list or len(rows) != EXPECTED_CASE_COUNT:
            return 'FAIL'
        if {r['id'] for r in rows} != registered_ids():
            return 'FAIL'
        by_id = {r['id']: r for r in rows}
        if not all(case_passes(by_id[case['id']], case) for case in expected):
            return 'FAIL'
        classes = {r['id']: classify(r) for r in rows}
        if not all(classes[case['id']] == case['expected_class'] for case in expected):
            return 'FAIL'
        # An availability fault must be attributable to the phase that never
        # delivered: only fast phases may have answered.
        for row in rows:
            if classes[row['id']] not in AVAILABILITY_FAULTS:
                continue
            if any(d.get('delivered') is True and type(d.get('stage_ms')) is int and d['stage_ms'] > 0
                   for d in row['guard_decisions']):
                return 'FAIL'
        return 'PASS'
    except (KeyError, TypeError, ValueError, AttributeError):
        return 'FAIL'


@contextmanager
def deadline_fixture(slow_phase: str, stage_ms: int, budget_ms: int = DECLARED_GUARD_BUDGET_MS,
                     disconnect: bool = False):
    """Loopback webhook fixture that models a budget-aware guard adapter."""
    state = stock.FixtureState()
    state.reset(slow_phase, 'allow', '')
    state.guard_decisions = []
    state.inflight = 0
    base = stock.handler_for(state)

    class Handler(base):
        def do_POST(self):
            if self.path not in ('/request', '/response'):
                return super().do_POST()
            try:
                self.connection.settimeout(15)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= stock.LIMIT or len(self.rfile.read(length)) != length:
                    return self.send_error(400)
                phase = self.path[1:]
                delay = stage_ms if phase == slow_phase else 0
                with state.lock:
                    state.counts[phase] += 1
                    state.inflight += 1
                try:
                    if delay:
                        time.sleep(delay / 1000)
                    if disconnect and phase == slow_phase:
                        # The hook dies before answering: nothing is written, so the
                        # Gateway can only report a transport failure.
                        with state.lock:
                            state.guard_decisions.append({
                                'phase': phase, 'allowed': False, 'reason': GUARD_DEADLINE_EXCEEDED,
                                'stage_ms': delay, 'delivered': False, 'decision_write': 'not_attempted'})
                        self.close_connection = True
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        return
                    exceeded = over_budget(delay, budget_ms)
                    reason = GUARD_DEADLINE_EXCEEDED if exceeded else 'FIXTURE_ALLOW'
                    action = {'reason': reason}
                    if exceeded:
                        action.update(status_code=503, body=GUARD_DENIAL_BODY.decode())
                    raw = json.dumps({'action': action}).encode()
                    decision_write = 'ok'
                    try:
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                    except OSError:
                        # The Gateway gave up on this hook; the decision exists but
                        # never reached it. Recording the WRITE outcome separately
                        # from the Gateway outcome keeps the two distinguishable.
                        decision_write = 'failed'
                    with state.lock:
                        state.guard_decisions.append({'phase': phase, 'allowed': not exceeded,
                                                      'reason': reason, 'stage_ms': delay,
                                                      'delivered': decision_write == 'ok',
                                                      'decision_write': decision_write})
                finally:
                    with state.lock:
                        state.inflight -= 1
            except (OSError, ValueError):
                self.close_connection = True

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=15)


def wait_idle(state, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        with state.lock:
            if state.inflight == 0:
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(.05)


def log_fragment(log_path: Path, offset: int) -> bytes:
    with log_path.open('rb') as log:
        log.seek(offset)
        return log.read(stock.LIMIT)


def wait_gateway_log(log_path: Path, offset: int, seconds: float = LOG_SETTLE_SECONDS) -> bytes:
    """Wait for the Gateway's own completion line, then keep the whole fragment."""
    deadline = time.monotonic() + seconds
    fragment = b''
    while True:
        fragment = log_fragment(log_path, offset)
        if b'http.status=' in fragment or time.monotonic() >= deadline:
            return fragment
        time.sleep(.02)


def log_evidence(fragment: bytes) -> tuple[list[str], int | None]:
    found = []
    for name, markers in GATEWAY_MARKERS.items():
        for phase, marker in markers.items():
            if marker in fragment:
                found.append(name + ':' + phase)
    statuses = re.findall(rb'http\.status=(\d{3})', fragment)
    return sorted(found), int(statuses[-1]) if statuses else None


def observed_call(url, state, case, log_path: Path) -> dict:
    payload = json.dumps({'model': 'fixture', 'stream': False,
                          'messages': stock.expected_messages(state.marker)}).encode()
    offset = log_path.stat().st_size
    start = time.monotonic()
    request = Request(url, data=payload, headers={'Content-Type': 'application/json'})
    # Never inherit HTTP_PROXY for an isolated loopback test.
    opener = build_opener(ProxyHandler({}))
    try:
        response = opener.open(request, timeout=25)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(stock.LIMIT + 1)
        if len(body) > stock.LIMIT:
            raise ValueError('DEADLINE_RESPONSE_TOO_LARGE')
        status = response.status
    elapsed_ms = round((time.monotonic() - start) * 1000, 3)
    # The slow phase must finish (or fail to deliver) before the row is snapshotted.
    if not wait_idle(state, case['stage_ms'] / 1000 + 5):
        raise ValueError('DEADLINE_FIXTURE_STILL_BUSY')
    fragment = wait_gateway_log(log_path, offset)
    markers, gateway_status = log_evidence(fragment)
    try:
        decoded = json.loads(body)
    except (ValueError, UnicodeError):
        decoded = None
    with state.lock:
        counts = dict(state.counts)
        decisions = [dict(d) for d in state.guard_decisions]
        upstream_payload = state.upstream_payload
        upstream_received_marker = state.upstream_received_marker
        marker = state.marker
    content = ('prefix ' + marker + ' suffix') if case['phase'] == 'response' else 'fixture-ok'
    return {'id': case['id'], 'phase': case['phase'], 'http_status': status, 'counts': counts,
            'elapsed_ms': elapsed_ms, 'client_marker_visible': marker.encode() in body,
            'client_body_sha256': hashlib.sha256(body).hexdigest(),
            'client_body_is_guard_denial': body == GUARD_DENIAL_BODY,
            'upstream_received_marker': upstream_received_marker,
            'request_structure_preserved': stock.valid_request_structure(upstream_payload, marker),
            'response_structure_preserved': stock.valid_response_structure(decoded, content),
            'guard_decisions': decisions, 'process_listener_owned': True,
            'gateway_markers': markers, 'gateway_http_status': gateway_status,
            'gateway_log_offset': offset, 'gateway_log_bytes': len(fragment),
            'gateway_log_sha256': hashlib.sha256(fragment).hexdigest()}


def run_suite(data: bytes, build: dict, report_path: Path) -> dict:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases():
        with deadline_fixture(case['phase'], case['stage_ms'],
                              disconnect=case['outcome'] == 'transport_disconnect') as (state, target), \
                tempfile.TemporaryDirectory() as directory:
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            # The deadline slice runs on the same preflighted route shape as the
            # context slice, so a rejected route can never produce a deadline PASS.
            config = context_config(port, target, {})
            route = config['binds'][0]['listeners'][0]['routes'][0]
            validate_route(route)
            cfg = Path(directory) / 'config.json'
            cfg.write_text(json.dumps(config))
            saved = report_path.parent / (report_path.stem + '-' + case['id'] + '.config.json')
            saved.write_bytes(cfg.read_bytes())
            exe = Path(directory) / 'agentgateway'
            exe.write_bytes(data)
            exe.chmod(0o700)
            log_path = saved.with_suffix('.gateway.log')
            with log_path.open('w') as log:
                process = subprocess.Popen([str(exe), '-f', str(cfg)], stdout=log, stderr=subprocess.STDOUT,
                                           shell=False, env={'HOME': directory, 'RUST_LOG': 'info'})
                try:
                    wait_listener(process, exe, port)
                    row = observed_call(f'http://127.0.0.1:{port}/v1/chat/completions', state, case, log_path)
                    require_listener(process, exe, port)
                    row.update(config_sha256=hashlib.sha256(cfg.read_bytes()).hexdigest(),
                               config_file=saved.name, gateway_log_file=log_path.name)
                    row['assertion_passed'] = case_passes(row, case)
                    rows.append(row)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    classes = {r['id']: classify(r) for r in rows}
    result = {'kind': 'REAL_GATEWAY_DEADLINE_SLICE', 'build': build, 'cases': rows,
              'registered_cases': EXPECTED_CASE_COUNT,
              'declared_guard_budget_ms': DECLARED_GUARD_BUDGET_MS,
              'declared_stages_ms': dict(DECLARED_BUDGET_MS),
              'transport_reserve_ms': TRANSPORT_RESERVE_MS, 'safety_margin_ms': SAFETY_MARGIN_MS,
              'effective_gateway_timeout_ms': GATEWAY_WEBHOOK_TIMEOUT_MS,
              'classes': classes,
              'availability_faults': [i for i, c in classes.items() if c in AVAILABILITY_FAULTS],
              'gateway_timeouts': [i for i, c in classes.items() if c == 'gateway_timeout'],
              'upstream_transport_faults': [i for i, c in classes.items() if c == 'upstream_transport_fault'],
              'guard_deadline_decisions': [i for i, c in classes.items() if c == 'guard_deadline_decision'],
              'deadline_gate': deadline_status(rows),
              'outcome_separation': {'guard_outcome': 'delivered decision or Gateway guardrail_reject marker',
                                     'gateway_outcome': 'Gateway log marker timeout vs transport'},
              'scope': ('fixture-modelled guard adapter on the preflighted context route; '
                        'declared-stage boundary, per-phase decision contract and Gateway-log '
                        'timeout/transport separation only'),
              'not_evaluated': ['detector latency', 'queue depth', 'backpressure', 'cancellation',
                                'long-LLM SLO'],
              'p0_release_gate': 'NOT_EVALUATED', 'asr_fpr': 'NOT_EVALUATED',
              'deployment_approved': False}
    report_path.write_text(json.dumps(result, indent=2) + '\n')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway-bin', type=Path, required=True)
    parser.add_argument('--build-manifest', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        data, build = verify_build(args.gateway_bin, args.build_manifest)
        report = run_suite(data, build, args.report)
        print(json.dumps({'deadline_gate': report['deadline_gate'], 'cases': len(report['cases']),
                          'classes': report['classes']}))
        return 0 if report['deadline_gate'] == 'PASS' else 1
    except (ValueError, OSError, RuntimeError) as exc:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'kind': 'REAL_GATEWAY_DEADLINE_SLICE',
                                           'deadline_gate': 'ERROR',
                                           'p0_release_gate': 'NOT_EVALUATED',
                                           'error': str(exc)}) + '\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
