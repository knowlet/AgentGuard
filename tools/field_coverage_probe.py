# Native field-coverage probe for text-nonstream-v1 (measurement only).
#
# Launches a real checksum-pinned Gateway with loopback hook and backend
# fixtures. For each profile field it sends a fresh random marker at that
# field, then records whether the marker reached the hook body, the backend
# payload, and the client response bytes. Unknown and out-of-profile fields
# are sent as-is. Whatever the Gateway does is recorded honestly as
# observed_inspected, forwarded_uninspected, or unknown. The probe never
# emits ingress_rejected without native Gateway rejection evidence and never
# emits any PASS gate. All gates stay NOT_EVALUATED.
# No LLM, GPU, credentials, or third-party packages. No network beyond
# loopback. Exit 0 means measurement completed, not protection.
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from agentguard import field_profile
from agentguard import promptguard
from agentguard.context import HEADER_EXPRESSIONS, validate_route
from tools import gateway_probe as stock
from tools.process_identity import require_listener, wait_listener

ROOT = Path(__file__).resolve().parents[1]
REPORT_KIND = "REAL_GATEWAY_FIELD_COVERAGE_OBSERVATIONS"
GATEWAY_VERSION = "v1.5.0"
BINARY_SHA256 = stock.BINARY_SHA256
LIMIT = stock.LIMIT
PROFILE_ID = field_profile.PROFILE_ID


def new_marker():
    return secrets.token_hex(16)


def numeric_marker(marker):
    return int(marker[:8], 16)


def base_messages():
    return [
        {"role": "system", "content": "Preserve this instruction."},
        {"role": "user", "content": "Control text without markers."},
        {"role": "user", "content": "Third control text without markers."},
    ]


def base_request():
    return {"model": "fixture", "stream": False, "messages": base_messages(), "temperature": 0}


def embed_request_marker(payload, pointer, marker):
    if pointer == "/model":
        payload["model"] = marker
    elif pointer == "/stream":
        payload["stream"] = True
    elif pointer == "/temperature":
        payload["temperature"] = numeric_marker(marker)
    elif pointer == "/messages":
        payload["messages"] = [{"role": "user", "content": marker}]
    elif pointer == "/messages/0/role":
        payload["messages"][0]["role"] = marker
    elif pointer == "/messages/0/content":
        payload["messages"][0]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/1/role":
        payload["messages"][1]["role"] = marker
    elif pointer == "/messages/1/content":
        payload["messages"][1]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/2/content":
        payload["messages"][2]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/1/tool_calls":
        payload["messages"][1]["tool_calls"] = [{"id": marker, "type": "function", "function": {"name": "probe_tool", "arguments": "{}"}}]
    elif pointer == "/messages/1/content_parts_image":
        payload["messages"][1]["content"] = [{"type": "text", "text": "probe"}, {"type": "image_url", "image_url": {"url": "http://probe.invalid/" + marker}}]
    elif pointer == "/top_unknown":
        payload["top_unknown"] = marker
    else:
        raise ValueError("FIELD_PROBE_UNKNOWN_REQUEST_POINTER")
    return payload


def marker_text(payload, marker):
    try:
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return marker in text


def base_response():
    return {"id": "fixture", "object": "chat.completion", "created": 1, "model": "fixture", "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def embed_response_marker(response, pointer, marker):
    if pointer == "/id":
        response["id"] = marker
    elif pointer == "/model":
        response["model"] = marker
    elif pointer == "/choices":
        response["choices"] = [{"index": 0, "message": {"role": "assistant", "content": marker}, "finish_reason": "stop"}]
    elif pointer == "/choices/0/index":
        response["choices"][0]["index"] = numeric_marker(marker)
    elif pointer == "/choices/0/message/role":
        response["choices"][0]["message"]["role"] = marker
    elif pointer == "/choices/0/message/content":
        response["choices"][0]["message"]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/choices/1/message/content":
        response["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}, {"index": 1, "message": {"role": "assistant", "content": "prefix " + marker + " suffix"}, "finish_reason": "stop"}]
    elif pointer == "/choices/0/finish_reason":
        response["choices"][0]["finish_reason"] = marker
    elif pointer == "/provider_extension":
        response["provider_extension"] = marker
    else:
        raise ValueError("FIELD_PROBE_UNKNOWN_RESPONSE_POINTER")
    return response


class ProbeState:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset({}, {})

    def reset(self, markers, response_plan):
        with self.lock:
            self.markers = dict(markers)
            self.response_plan = dict(response_plan)
            self.hook_bodies = {"request": [], "response": []}
            self.hook_observed_maps = {"request": [], "response": []}
            self.hook_counts = {"request": 0, "response": 0}
            self.backend_payloads = []
            self.upstream_count = 0


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _read_bytes(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= LIMIT:
                raise ValueError("invalid length")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("short read")
            return raw

        def _send_bytes(self, raw):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            try:
                if self.path in ("/request", "/response"):
                    phase = self.path[1:]
                    raw = self._read_bytes()
                    try:
                        envelope = promptguard.parse_envelope(raw)
                    except promptguard.PromptGuardRejected:
                        self.send_error(400, "Invalid hook envelope")
                        return
                    with state.lock:
                        markers = dict(state.markers)
                    allow, reason, observed = promptguard.decide(phase, envelope, markers)
                    with state.lock:
                        state.hook_counts[phase] += 1
                        state.hook_bodies[phase].append(envelope.get("body"))
                        state.hook_observed_maps[phase].append(observed)
                    out = promptguard.action_response(allow=allow, reason=reason)
                    self._send_bytes(out)
                    return
                if self.path == "/v1/chat/completions":
                    raw = self._read_bytes()
                    try:
                        payload = json.loads(raw)
                    except (ValueError, UnicodeError):
                        payload = None
                    with state.lock:
                        state.upstream_count += 1
                        state.backend_payloads.append(payload)
                        plan = dict(state.response_plan)
                    response = base_response()
                    for pointer, marker in plan.items():
                        response = embed_response_marker(response, pointer, marker)
                    self._send_bytes(json.dumps(response, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8"))
                    return
                self.send_error(404)
            except (ValueError, KeyError, OSError):
                try:
                    self.send_error(400, "Invalid fixture request")
                except OSError:
                    pass
    return Handler


@contextmanager
def fixture_server():
    state = ProbeState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield state, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def probe_gateway_config(port, target):
    config = stock.gateway_config(port, target)
    route = config["binds"][0]["listeners"][0]["routes"][0]
    route["backends"][0]["ai"]["provider"] = {"openAI": {}}
    target_host = "127.0.0.1:" + str(target)
    for phase in ("request", "response"):
        route["policies"]["ai"]["promptGuard"][phase] = [{"webhook": {"target": {"host": target_host}, "headers": dict(HEADER_EXPRESSIONS), "failureMode": "failClosed"}}]
    return config


def observe_case(url, state, payload, timeout=15):
    start = time.monotonic()
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    opener = build_opener(ProxyHandler({}))
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError("oversize gateway response")
        status = response.status
    elapsed = round((time.monotonic() - start) * 1000, 3)
    with state.lock:
        snapshot = {"hook_counts": dict(state.hook_counts), "hook_bodies": copy.deepcopy(state.hook_bodies), "hook_observed_maps": copy.deepcopy(state.hook_observed_maps), "backend_payloads": copy.deepcopy(state.backend_payloads), "upstream_count": state.upstream_count}
    return {"http_status": status, "client_body": body, "elapsed_ms": elapsed, "snapshot": snapshot}


def marker_in_bodies(bodies, marker):
    for body in bodies:
        if marker_text(body, marker):
            return True
    return False


def resolve_pointer(doc, pointer):
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return False, None
    current = doc
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit():
                return False, None
            index = int(token)
            if index < 0 or index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def value_matches(value, profile_row, marker):
    if profile_row["pointer"] == "/stream":
        return value is True
    if profile_row["field_type"] == "number":
        return value == numeric_marker(marker)
    if isinstance(value, str):
        return marker in value
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return marker in text


def pointer_hit(documents, pointer, profile_row, marker):
    for doc in documents:
        found, value = resolve_pointer(doc, pointer)
        if found and value_matches(value, profile_row, marker):
            return True
    return False


def parse_client(body):
    if type(body) is not bytes:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, (dict, list)):
        return None
    return doc


def derive_row(profile_row, marker, obs):
    phase = profile_row["phase"]
    fixture_id = profile_row["fixture_id"]
    obligation = profile_row["obligation"]
    snapshot = obs["snapshot"]
    status = obs["http_status"]
    hook_count = snapshot["hook_counts"][phase]
    ok_2xx = 200 <= status <= 299
    spy_maps = snapshot.get("hook_observed_maps", {}).get(phase, [])
    detector_hit = any(isinstance(entry, dict) and entry.get(fixture_id) is True for entry in spy_maps)
    client_bytes_hit = marker.encode("utf-8") in obs["client_body"]
    if obligation in ("reject_unknown", "reject_unsupported"):
        hook_any = marker_in_bodies(snapshot["hook_bodies"][phase], marker)
        if phase == "request":
            backend_any = any(marker_text(payload, marker) for payload in snapshot["backend_payloads"] if payload is not None)
        else:
            backend_any = snapshot["upstream_count"] >= 1
        hook_observed = hook_any
        backend_observed = backend_any
        client_observed = client_bytes_hit
        if 400 <= status <= 599 and hook_count == 0 and not backend_any and not client_bytes_hit:
            measured = "unknown"
            detail = "transport rejected before hook without native rejection code evidence"
        elif hook_any or backend_any or client_bytes_hit:
            measured = "forwarded_uninspected"
            detail = "out-of-profile marker reached hook, backend, or client instead of pre-normalization rejection"
        else:
            measured = "unknown"
            detail = "marker absent from hook and client views; pre-normalization rejection unproven"
        preserved = None
    else:
        hook_pointer = profile_row.get("normalized_pointer") or profile_row["pointer"]
        hook_hit = pointer_hit(snapshot["hook_bodies"][phase], hook_pointer, profile_row, marker)
        if phase == "request":
            live_payloads = [payload for payload in snapshot["backend_payloads"] if payload is not None]
            backend_hit = pointer_hit(live_payloads, profile_row["pointer"], profile_row, marker)
            client_hit = False
        else:
            backend_hit = snapshot["upstream_count"] >= 1
            client_doc = parse_client(obs["client_body"])
            client_hit = client_doc is not None and pointer_hit([client_doc], profile_row["pointer"], profile_row, marker)
        hook_observed = hook_hit
        backend_observed = backend_hit
        client_observed = client_hit
        downstream_ok = backend_hit and (client_hit if phase == "response" else True)
        if hook_hit and downstream_ok and ok_2xx:
            if obligation == "detector_text" and not detector_hit:
                measured = "unknown"
                detail = "hook carried marker at bound pointer but detector spy did not report it"
            else:
                measured = "observed_inspected"
                if phase == "response":
                    detail = "marker verified at bound pointer in hook, backend-call, and client views with 2xx"
                else:
                    detail = "marker verified at bound pointer in hook and backend views with 2xx"
        elif 400 <= status <= 599 and hook_count == 0 and not backend_hit and not client_hit:
            measured = "unknown"
            detail = "transport rejected before hook without native rejection code evidence"
        elif (backend_hit or client_hit) and not hook_hit:
            measured = "forwarded_uninspected"
            detail = "marker reached backend or client without hook observation at bound pointer"
        else:
            measured = "unknown"
            detail = "marker not correlated at bound pointer across hook, backend, and client"
        if measured == "observed_inspected":
            preserved = True
        else:
            preserved = None
    return {"phase": phase, "pointer": profile_row["pointer"], "fixture_id": fixture_id, "field_type": profile_row["field_type"], "obligation": obligation, "marker_sha256": hashlib.sha256(marker.encode("utf-8")).hexdigest(), "pre_normalization_present": True, "hook_observed": hook_observed, "backend_observed": backend_observed, "client_observed": client_observed, "detector_observed": detector_hit, "gateway_http_status": status, "gateway_rejected_before_normalization": False, "gateway_rejection_code": None, "measured_status": measured, "detail": detail, "payload_preserved": preserved, "hook_calls": hook_count, "upstream_count": snapshot["upstream_count"]}


def _control_row(phase, pointer, obligation):
    return {"phase": phase, "pointer": pointer, "normalized_pointer": pointer, "field_type": "string", "fixture_id": "control", "obligation": obligation}


def controls_pass(obs, req_marker, resp_marker):
    snapshot = obs["snapshot"]
    if obs["http_status"] != 200:
        return False
    if snapshot["hook_counts"] != {"request": 1, "response": 1}:
        return False
    if snapshot["upstream_count"] != 1:
        return False
    req_row = _control_row("request", "/messages/1/content", "detector_text")
    if not pointer_hit(snapshot["hook_bodies"]["request"], req_row["pointer"], req_row, req_marker):
        return False
    live_payloads = [payload for payload in snapshot["backend_payloads"] if payload is not None]
    if not pointer_hit(live_payloads, req_row["pointer"], req_row, req_marker):
        return False
    req_spy = snapshot.get("hook_observed_maps", {}).get("request", [])
    if not any(isinstance(entry, dict) and entry.get("control") is True for entry in req_spy):
        return False
    resp_row = _control_row("response", "/choices/0/message/content", "detector_text")
    if not pointer_hit(snapshot["hook_bodies"]["response"], resp_row["pointer"], resp_row, resp_marker):
        return False
    client_doc = parse_client(obs["client_body"])
    if client_doc is None or not pointer_hit([client_doc], resp_row["pointer"], resp_row, resp_marker):
        return False
    resp_spy = snapshot.get("hook_observed_maps", {}).get("response", [])
    if not any(isinstance(entry, dict) and entry.get("control-response") is True for entry in resp_spy):
        return False
    return True


def profile_digest():
    canon = json.dumps(field_profile.rows(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def run(binary, report_path, timeout=15):
    binary_bytes = binary.read_bytes()
    digest = hashlib.sha256(binary_bytes).hexdigest()
    if digest != BINARY_SHA256:
        raise ValueError("unexpected Gateway binary; update pin and review before testing a different build")
    field_profile.validate_profile()
    profile_rows = field_profile.rows()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    hook_digest = hashlib.sha256((ROOT / "agentguard" / "promptguard.py").read_bytes()).hexdigest()
    runner_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    rows = []
    control_ok = False
    control_detail = ""
    config_digest = ""
    with fixture_server() as (state, fixture_port), tempfile.TemporaryDirectory() as directory:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = probe_gateway_config(port, fixture_port)
        validate_route(config["binds"][0]["listeners"][0]["routes"][0])
        config_digest = hashlib.sha256(json.dumps(config, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
        config_path = Path(directory) / "gateway.yaml"
        config_path.write_text(json.dumps(config))
        verified_binary = Path(directory) / "agentgateway"
        verified_binary.write_bytes(binary_bytes)
        verified_binary.chmod(0o700)
        log_path = report_path.with_suffix(".gateway.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w") as log:
            process = subprocess.Popen([str(verified_binary), "-f", str(config_path)], shell=False, stdout=log, stderr=subprocess.STDOUT, env={"PATH": os.environ.get("PATH", ""), "HOME": directory, "RUST_LOG": "info"})
            try:
                wait_listener(process, verified_binary, port)
                url = "http://127.0.0.1:" + str(port) + "/v1/chat/completions"
                require_listener(process, verified_binary, port)
                req_marker = new_marker()
                resp_marker = new_marker()
                payload = base_request()
                payload["messages"][1]["content"] = "prefix " + req_marker + " suffix"
                state.reset({"control": req_marker, "control-response": resp_marker}, {"/choices/0/message/content": resp_marker})
                control_obs = observe_case(url, state, payload, timeout=timeout)
                control_ok = controls_pass(control_obs, req_marker, resp_marker)
                if not control_ok:
                    control_detail = "positive control failed to flow end to end"
                else:
                    control_detail = "positive control flowed end to end"
                for profile_row in profile_rows:
                    marker = new_marker()
                    markers = {profile_row["fixture_id"]: marker}
                    if profile_row["phase"] == "request":
                        case_payload = embed_request_marker(base_request(), profile_row["pointer"], marker)
                        response_plan = {}
                    else:
                        case_payload = base_request()
                        response_plan = {profile_row["pointer"]: marker}
                    state.reset(markers, response_plan)
                    require_listener(process, verified_binary, port)
                    obs = observe_case(url, state, case_payload, timeout=timeout)
                    rows.append(derive_row(profile_row, marker, obs))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    summary = {"observed_inspected": 0, "forwarded_uninspected": 0, "unknown": 0, "ingress_rejected": 0}
    findings = []
    for row in rows:
        summary[row["measured_status"]] += 1
        contract = "hook_and_egress" if row["obligation"] in ("type_value", "structure", "detector_text") else "reject_before_normalization"
        if contract == "hook_and_egress" and row["measured_status"] != "observed_inspected":
            findings.append(row["fixture_id"] + ": contract " + contract + " measured " + row["measured_status"])
        if contract == "reject_before_normalization" and row["measured_status"] != "ingress_rejected":
            findings.append(row["fixture_id"] + ": contract reject_before_normalization measured " + row["measured_status"] + " (no native gate in stock build)")
    report = {"kind": REPORT_KIND, "gateway_version": GATEWAY_VERSION, "profile": PROFILE_ID, "binary_sha256": digest, "config_sha256": config_digest, "profile_sha256": profile_digest(), "runner_sha256": runner_digest, "hook_sha256": hook_digest, "process_listener_owned": True, "control_passed": control_ok, "control_detail": control_detail, "rows": rows, "summary": summary, "findings": findings, "coverage_gate": "NOT_EVALUATED", "p0_release_gate": "NOT_EVALUATED", "asr_fpr": "NOT_EVALUATED"}
    report_path.write_text(json.dumps(report, indent=2) + nl_or_empty())
    print(json.dumps(report, indent=2))
    if not control_ok:
        return 1
    return 0


def nl_or_empty():
    return chr(10)


def main():
    parser = argparse.ArgumentParser(description="Native field-coverage probe (measurement only, never PASS).")
    parser.add_argument("--gateway-bin", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=Path("reports/field-coverage.json"))
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        return run(args.gateway_bin, args.report, timeout=args.timeout)
    except (OSError, ValueError, RuntimeError) as exc:
        args.report.write_text(json.dumps({"kind": REPORT_KIND, "profile": PROFILE_ID, "measurement_status": "ERROR", "coverage_gate": "NOT_EVALUATED", "p0_release_gate": "NOT_EVALUATED", "error": str(exc)}, indent=2) + chr(10))
        print("ERROR: " + str(exc))
        return 2
    finally:
        log_path = args.report.with_suffix(".gateway.log")
        if log_path.is_file():
            print("=== Gateway process log ===", file=sys.stderr)
            with log_path.open(errors="replace") as log:
                print(log.read(LIMIT), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
