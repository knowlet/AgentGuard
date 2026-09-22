# Native field-coverage probe for text-nonstream-v1 (measurement only).
#
# Launches a real checksum-pinned Gateway with loopback hook and backend
# fixtures. Text fields carry fresh markers; metadata uses legal typed
# values. The oracle compares complete fields at their declared pointers
# across the source, hook, and phase destination. Unknown and out-of-profile fields
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
import re
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


def base_messages():
    return [
        {"role": "system", "content": "Preserve this instruction."},
        {"role": "user", "content": "Control text without markers."},
        {"role": "assistant", "content": "Third control text without markers."},
    ]


def base_request():
    return {"model": "fixture", "stream": False, "messages": base_messages(), "temperature": 0}


def embed_request_marker(payload, pointer, marker):
    if pointer == "/model":
        payload["model"] = marker
    elif pointer == "/stream":
        payload["stream"] = True
    elif pointer == "/temperature":
        payload["temperature"] = 0.75
    elif pointer == "/messages":
        payload["messages"][1]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/0/role":
        payload["messages"][0]["role"] = "system"
    elif pointer == "/messages/0/content":
        payload["messages"][0]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/1/role":
        payload["messages"][1]["role"] = "user"
    elif pointer == "/messages/1/content":
        payload["messages"][1]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/2/content":
        payload["messages"][2]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/messages/1/tool_calls":
        payload["messages"][1]["tool_calls"] = [{"id": marker, "type": "function", "function": {"name": "probe_tool", "arguments": "{}"}}]
    elif pointer == "/messages/1/content/1":
        payload["messages"][1]["content"] = [{"type": "text", "text": "probe"}, {"type": "image_url", "image_url": {"url": "http://probe.invalid/" + marker}}]
    elif pointer == "/top_unknown":
        payload["top_unknown"] = marker
    else:
        raise ValueError("FIELD_PROBE_UNKNOWN_REQUEST_POINTER")
    return payload


def base_response():
    return {"id": "fixture", "object": "chat.completion", "created": 1, "model": "fixture", "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def embed_response_marker(response, pointer, marker):
    if pointer == "/id":
        response["id"] = marker
    elif pointer == "/model":
        response["model"] = marker
    elif pointer == "/choices":
        response["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "prefix " + marker + " suffix"}, "finish_reason": "stop"}, {"index": 1, "message": {"role": "assistant", "content": "second choice"}, "finish_reason": "length"}]
    elif pointer == "/choices/0/index":
        response["choices"][0]["index"] = 0
    elif pointer == "/choices/0/message/role":
        response["choices"][0]["message"]["role"] = "assistant"
    elif pointer == "/choices/0/message/content":
        response["choices"][0]["message"]["content"] = "prefix " + marker + " suffix"
    elif pointer == "/choices/1/message/content":
        response["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}, {"index": 1, "message": {"role": "assistant", "content": "prefix " + marker + " suffix"}, "finish_reason": "stop"}]
    elif pointer == "/choices/0/finish_reason":
        response["choices"][0]["finish_reason"] = "length"
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
            self.backend_request_hex = []
            self.backend_responses = []
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
                        payload = promptguard.parse_json(raw)
                    except promptguard.PromptGuardRejected:
                        payload = None
                    with state.lock:
                        state.upstream_count += 1
                        state.backend_payloads.append(payload)
                        state.backend_request_hex.append(raw.hex())
                        plan = dict(state.response_plan)
                    response = base_response()
                    for pointer, marker in plan.items():
                        response = embed_response_marker(response, pointer, marker)
                    with state.lock:
                        state.backend_responses.append(copy.deepcopy(response))
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
        snapshot = {"hook_counts": dict(state.hook_counts), "hook_bodies": copy.deepcopy(state.hook_bodies), "hook_observed_maps": copy.deepcopy(state.hook_observed_maps), "backend_payloads": copy.deepcopy(state.backend_payloads), "backend_request_hex": list(state.backend_request_hex), "backend_responses": copy.deepcopy(state.backend_responses), "upstream_count": state.upstream_count}
    return {"http_status": status, "request_payload": json.loads(data), "client_body": body, "elapsed_ms": elapsed, "snapshot": snapshot}


def resolve_pointer(doc, pointer):
    # Field-level RFC 6901 pointers; root is intentionally outside this profile.
    if not isinstance(pointer, str) or not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        return False, None
    current = doc
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token) or len(token) > len(str(len(current))):
                return False, None
            index = int(token)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def value_matches(value, expected):
    # Canonical JSON preserves scalar types, complete strings, and array order.
    # Python equality alone would allow True == 1 and False == 0.
    try:
        return canonical(value) == canonical(expected)
    except (TypeError, ValueError, UnicodeError):
        return False


def container_shape(doc, pointer):
    """Bind ancestor container types and array lengths, not just the leaf value."""
    shape = []
    prefix = ""
    for token in pointer.split("/")[1:]:
        found, parent = (True, doc) if not prefix else resolve_pointer(doc, prefix)
        if not found or not isinstance(parent, (dict, list)):
            return None
        shape.append((type(parent).__name__, len(parent) if isinstance(parent, list) else None))
        prefix += "/" + token
    return shape


def pointer_hit(doc, pointer, expected, shape=None):
    found, value = resolve_pointer(doc, pointer)
    return (found and value_matches(value, expected)
            and (shape is None or container_shape(doc, pointer) == shape))


def parse_client(body):
    if type(body) is not bytes:
        return None
    try:
        doc = promptguard.parse_json(body)
    except promptguard.PromptGuardRejected:
        return None
    return doc if isinstance(doc, dict) else None


def fixture_document(profile_row, marker):
    if profile_row["phase"] == "request":
        return embed_request_marker(base_request(), profile_row["pointer"], marker)
    return embed_response_marker(base_response(), profile_row["pointer"], marker)


def spy_targets(profile_row, marker):
    if profile_row["obligation"] != "detector_text":
        return {}
    found, text = resolve_pointer(fixture_document(profile_row, marker), profile_row["pointer"])
    if not found or type(text) is not str:
        raise ValueError("FIELD_PROBE_TEXT_FIXTURE_INVALID")
    return {profile_row["fixture_id"]: {"pointer": profile_row["normalized_pointer"], "text": text}}


def derive_row(profile_row, marker, obs):
    phase = profile_row["phase"]
    pointer = profile_row["pointer"]
    fixture_id = profile_row["fixture_id"]
    obligation = profile_row["obligation"]
    snapshot = obs["snapshot"]
    status = obs["http_status"]
    fixture = fixture_document(profile_row, marker)
    found, expected = resolve_pointer(fixture, pointer)
    if not found:
        raise ValueError("FIELD_PROBE_FIXTURE_POINTER_MISSING")
    hook_count = snapshot["hook_counts"][phase]
    bodies = snapshot["hook_bodies"][phase]
    spy_maps = snapshot.get("hook_observed_maps", {}).get(phase, [])
    backend_payloads = snapshot["backend_payloads"]
    backend_responses = snapshot.get("backend_responses", [])
    upstream = snapshot["upstream_count"]
    # Each case has one backend call and at most one hook event per phase.
    # Never join a matching body with another event's successful spy result.
    hook_correlated = hook_count == len(bodies) == len(spy_maps) == 1
    hook_pointer = profile_row.get("normalized_pointer") or pointer
    shape = container_shape(fixture, pointer)
    hook_shape = shape if hook_pointer == pointer else None
    hook_hit = hook_correlated and pointer_hit(bodies[0], hook_pointer, expected, hook_shape)
    detector_hit = (obligation == "detector_text" and hook_hit
                    and isinstance(spy_maps[0], dict) and spy_maps[0].get(fixture_id) is True)
    if phase == "request":
        source = obs.get("request_payload")
        backend_hit = upstream == len(backend_payloads) == 1 and pointer_hit(backend_payloads[0], pointer, expected, shape)
        client_hit = False  # Request fields terminate at the backend; no echo requirement.
        destination_hit = backend_hit
    else:
        source = backend_responses[0] if upstream == len(backend_responses) == 1 else None
        backend_hit = source is not None and pointer_hit(source, pointer, expected, shape)
        client_hit = pointer_hit(parse_client(obs["client_body"]), pointer, expected, shape)
        destination_hit = client_hit
    source_present, _ = resolve_pointer(source, pointer)
    source_hit = source_present and pointer_hit(source, pointer, expected, shape)
    preserved = source_hit and hook_hit and destination_hit
    if not source_hit:
        measured = "unknown"
        detail = "original field missing or different from the expected fixture value"
    elif obligation in ("reject_unknown", "reject_unsupported"):
        if hook_hit or destination_hit:
            measured = "forwarded_uninspected"
            detail = "out-of-profile field reached hook or destination instead of pre-normalization rejection"
        else:
            measured = "unknown"
            detail = "field dropped or transport rejected without native rejection code evidence"
    elif preserved and 200 <= status <= 299:
        if obligation == "detector_text" and not detector_hit:
            measured = "unknown"
            detail = "field preserved but detector spy did not report the bound text in the same event"
        else:
            measured = "observed_inspected"
            detail = "complete field type, value and structure match source, hook and phase destination"
    elif destination_hit and not hook_hit:
        measured = "forwarded_uninspected"
        detail = "field reached destination without matching hook observation"
    else:
        measured = "unknown"
        detail = "field changed, dropped, uncorrelated, or transport rejected without native rejection code evidence"
    return {
        "phase": phase, "pointer": pointer, "normalized_pointer": profile_row.get("normalized_pointer"),
        "fixture_id": fixture_id, "field_type": profile_row["field_type"], "obligation": obligation,
        "marker_sha256": hashlib.sha256(marker.encode("utf-8")).hexdigest(),
        "expected_value_sha256": hashlib.sha256(canonical(expected)).hexdigest(),
        "pre_normalization_present": source_present, "source_matches_fixture": source_hit,
        "hook_observed": hook_hit, "backend_observed": backend_hit, "client_observed": client_hit,
        "detector_observed": detector_hit, "gateway_http_status": status,
        "gateway_rejected_before_normalization": False, "gateway_rejection_code": None,
        "measured_status": measured, "detail": detail,
        "payload_preserved": preserved if source_hit and not obligation.startswith("reject_") else None,
        "hook_calls": hook_count, "upstream_count": upstream,
    }


def control_rows():
    return [
        {"phase": phase, "pointer": pointer, "normalized_pointer": pointer,
         "field_type": "string", "fixture_id": fixture_id, "obligation": "detector_text"}
        for phase, pointer, fixture_id in (
            ("request", "/messages/1/content", "control"),
            ("response", "/choices/0/message/content", "control-response"),
        )
    ]


def controls_pass(obs, req_marker, resp_marker):
    snapshot = obs["snapshot"]
    if (obs["http_status"] != 200 or snapshot["hook_counts"] != {"request": 1, "response": 1}
            or snapshot["upstream_count"] != 1):
        return False
    return all(derive_row(row, marker, obs)["measured_status"] == "observed_inspected"
               for row, marker in zip(control_rows(), (req_marker, resp_marker)))


def serializable_observation(obs):
    result = copy.deepcopy(obs)
    # Retain exact synthetic client bytes, including non-JSON rejection/SSE bodies.
    result["client_body_hex"] = result.pop("client_body").hex()
    return result


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
    observations = []
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
                targets = {}
                for row, marker in zip(control_rows(), (req_marker, resp_marker)):
                    targets.update(spy_targets(row, marker))
                state.reset(targets, {"/choices/0/message/content": resp_marker})
                control_obs = observe_case(url, state, payload, timeout=timeout)
                observations.append({"fixture_id": "control", **serializable_observation(control_obs)})
                control_ok = controls_pass(control_obs, req_marker, resp_marker)
                if not control_ok:
                    control_detail = "positive control failed to flow end to end"
                else:
                    control_detail = "positive control flowed end to end"
                for profile_row in profile_rows:
                    marker = new_marker()
                    targets = spy_targets(profile_row, marker)
                    if profile_row["phase"] == "request":
                        case_payload = embed_request_marker(base_request(), profile_row["pointer"], marker)
                        response_plan = {}
                    else:
                        case_payload = base_request()
                        response_plan = {profile_row["pointer"]: marker}
                    state.reset(targets, response_plan)
                    require_listener(process, verified_binary, port)
                    obs = observe_case(url, state, case_payload, timeout=timeout)
                    observations.append({"fixture_id": profile_row["fixture_id"], **serializable_observation(obs)})
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
    raw_path = report_path.with_suffix(".observations.json")
    raw_bytes = canonical(observations)
    raw_path.write_bytes(raw_bytes + b"\n")
    report = {"kind": REPORT_KIND, "measurement_status": "COMPLETED" if control_ok else "CONTROL_FAILED", "gateway_version": GATEWAY_VERSION, "profile": PROFILE_ID, "binary_sha256": digest, "config_sha256": config_digest, "profile_sha256": profile_digest(), "runner_sha256": runner_digest, "hook_sha256": hook_digest, "observations_file": raw_path.name, "observations_sha256": hashlib.sha256(raw_bytes + b"\n").hexdigest(), "process_listener_owned": True, "control_passed": control_ok, "control_detail": control_detail, "rows": rows, "summary": summary, "findings": findings, "coverage_gate": "NOT_EVALUATED", "p0_release_gate": "NOT_EVALUATED", "asr_fpr": "NOT_EVALUATED"}
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
