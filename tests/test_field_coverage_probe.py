import copy
import json
import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.request import Request, ProxyHandler, build_opener

from agentguard import field_profile
from agentguard import promptguard
from agentguard.context import validate_route
from tools import field_coverage_probe as probe


FROZEN_IDS = frozenset([
    "req-model", "req-stream", "req-temperature", "req-messages",
    "req-msg0-role", "req-msg0-content", "req-msg1-role", "req-msg1-content",
    "req-msg2-content", "req-tool-calls", "req-image-part", "req-unknown",
    "resp-id", "resp-model", "resp-choices", "resp-choice0-index",
    "resp-choice0-role", "resp-choice0-content", "resp-choice1-content",
    "resp-finish-reason", "resp-unknown",
])


class FrozenProfile(unittest.TestCase):
    def test_profile_validates_and_count_is_frozen(self):
        field_profile.validate_profile()
        self.assertEqual(len(field_profile.rows()), 21)
        self.assertEqual(field_profile.registered_fixture_ids(), FROZEN_IDS)

    def test_both_phases_and_unknown_per_phase(self):
        rows = field_profile.rows()
        phases = {r["phase"] for r in rows}
        self.assertEqual(phases, {"request", "response"})
        unknown = {r["phase"] for r in rows if r["field_type"] == "unknown"}
        self.assertEqual(unknown, {"request", "response"})

    def test_pointers_are_field_level(self):
        for row in field_profile.rows():
            self.assertTrue(row["pointer"].startswith("/"))
            self.assertNotEqual(row["pointer"], "")
            if row["normalized_pointer"] is not None:
                self.assertTrue(row["normalized_pointer"].startswith("/"))

    def test_rows_are_copies(self):
        rows = field_profile.rows()
        rows[0]["pointer"] = "/mutated"
        self.assertNotEqual(field_profile.rows()[0]["pointer"], "/mutated")


class PromptGuardHook(unittest.TestCase):
    def test_spy_only_visits_text_at_the_bound_pointer(self):
        target = {"f": {"pointer": "/messages/1/content", "text": "exact text"}}
        for body in ({"id": "exact text"}, {"messages": [{"content": "exact text"}]},
                     {"messages": [{}, {"content": "prefix exact text"}]}):
            with self.subTest(body=body):
                self.assertEqual(promptguard.decide("request", {"body": body}, target)[2], {"f": False})

    def test_valid_envelope_allows(self):
        envelope = promptguard.parse_envelope(b"{\"body\":{\"messages\":[{\"content\":\"abc MARKER xyz\"}]}}")
        allow, reason, observed = promptguard.decide("request", envelope, {"f": {"pointer": "/messages/0/content", "text": "abc MARKER xyz"}})
        self.assertTrue(allow)
        self.assertEqual(reason, "PROMPTGUARD_ALLOW")
        self.assertEqual(observed, {"f": True})

    def test_missing_marker_is_not_observed(self):
        envelope = promptguard.parse_envelope(b"{\"body\":{\"messages\":[]}}")
        _, _, observed = promptguard.decide("response", envelope, {"f": {"pointer": "/choices/0/message/content", "text": "ABSENT"}})
        self.assertEqual(observed, {"f": False})

    def test_malformed_envelopes_rejected(self):
        for raw in (b"", b"{}", b"[]", b"{\"no_body\":1}", b"not json", b"{\"body\":1,\"body\":2}", b"NaN"):
            with self.subTest(raw=raw):
                with self.assertRaises(promptguard.PromptGuardRejected):
                    promptguard.parse_envelope(raw)

    def test_bad_phase_rejected(self):
        with self.assertRaises(promptguard.PromptGuardRejected):
            promptguard.decide("sideways", {"body": {}}, {})

    def test_nonfinite_and_non_utf8_observations_rejected_at_ingestion(self):
        for raw in (b'{"body":{"extra":1e400}}', b'{"body":{"extra":"\\ud800"}}',
                    b'{"body":{"content":"changed","content":"expected"}}'):
            with self.subTest(raw=raw), self.assertRaises(promptguard.PromptGuardRejected):
                promptguard.parse_envelope(raw)

    def test_action_shapes(self):
        allow = json.loads(promptguard.action_response(allow=True, reason="PROMPTGUARD_ALLOW"))
        self.assertEqual(allow, {"action": {"reason": "PROMPTGUARD_ALLOW"}})
        deny = json.loads(promptguard.action_response(allow=False, reason="HOOK_ENVELOPE_INVALID"))
        self.assertEqual(deny["action"]["reason"], "HOOK_ENVELOPE_INVALID")
        self.assertEqual(deny["action"]["status_code"], 403)
        with self.assertRaises(promptguard.PromptGuardRejected):
            promptguard.action_response(allow=True, reason="")


def profile_row(fixture_id):
    return next(row for row in field_profile.rows() if row["fixture_id"] == fixture_id)


MARKER = "AB12" * 8


def good_observation(row, marker=MARKER):
    request = probe.base_request()
    response = probe.base_response()
    if row["phase"] == "request":
        request = probe.fixture_document(row, marker)
    else:
        response = probe.fixture_document(row, marker)
    return {
        "http_status": 200, "request_payload": copy.deepcopy(request),
        "client_body": json.dumps(response).encode(), "elapsed_ms": 1.0,
        "snapshot": {
            "hook_counts": {"request": 1, "response": 1},
            "hook_bodies": {"request": [copy.deepcopy(request)], "response": [copy.deepcopy(response)]},
            "hook_observed_maps": {"request": [{row["fixture_id"]: True}], "response": [{row["fixture_id"]: True}]},
            "backend_payloads": [copy.deepcopy(request)], "backend_responses": [copy.deepcopy(response)],
            "upstream_count": 1,
        },
    }


class Fixtures(unittest.TestCase):
    def test_every_fixture_contains_its_declared_pointer(self):
        for row in field_profile.rows():
            with self.subTest(fixture=row["fixture_id"]):
                found, value = probe.resolve_pointer(probe.fixture_document(row, MARKER), row["pointer"])
                self.assertTrue(found)
                self.assertIsNotNone(value)

    def test_metadata_values_are_legal_typed_values(self):
        cases = {"req-temperature": (float, 0.75), "req-stream": (bool, True),
                 "resp-choice0-index": (int, 0), "req-msg0-role": (str, "system"),
                 "req-msg1-role": (str, "user"), "resp-choice0-role": (str, "assistant"),
                 "resp-finish-reason": (str, "length")}
        for fixture_id, (expected_type, expected_value) in cases.items():
            with self.subTest(fixture=fixture_id):
                row = profile_row(fixture_id)
                _, value = probe.resolve_pointer(probe.fixture_document(row, MARKER), row["pointer"])
                self.assertIs(type(value), expected_type)
                self.assertEqual(value, expected_value)

    def test_stream_true_is_a_rejection_case_and_false_is_the_control(self):
        row = profile_row("req-stream")
        self.assertEqual(row["obligation"], "reject_unsupported")
        self.assertEqual(row["native_enforcement"], "reject_before_normalization")
        self.assertIsNone(row["normalized_pointer"])
        self.assertIs(probe.base_request()["stream"], False)
        self.assertEqual(probe.derive_row(row, MARKER, good_observation(row))["measured_status"], "forwarded_uninspected")

    def test_unknown_embedding_pointer_fails(self):
        for embed, base in ((probe.embed_request_marker, probe.base_request), (probe.embed_response_marker, probe.base_response)):
            with self.assertRaises(ValueError):
                embed(base(), "/nope", MARKER)

    def test_probe_config_satisfies_context_route(self):
        validate_route(probe.probe_gateway_config(9000, 9101)["binds"][0]["listeners"][0]["routes"][0])

    def test_pointer_resolution_uses_json_pointer_rules(self):
        doc = {"": 1, "a/b": {"~c": [None]}}
        self.assertEqual(probe.resolve_pointer(doc, "/"), (True, 1))
        self.assertEqual(probe.resolve_pointer(doc, "/a~1b/~0c/0"), (True, None))
        for pointer in ("", "/a~1b/~0c/00", "/a~1b/~0c/²", "/a~1b/~0c/-", "/a~2b", "/missing"):
            self.assertEqual(probe.resolve_pointer(doc, pointer), (False, None))


class DeriveRow(unittest.TestCase):
    def assert_not_inspected(self, row, obs):
        result = probe.derive_row(row, MARKER, obs)
        self.assertNotEqual(result["measured_status"], "observed_inspected")
        return result

    def test_all_supported_obligations_have_reachable_success(self):
        for row in field_profile.rows():
            if row["obligation"].startswith("reject_"):
                continue
            with self.subTest(fixture=row["fixture_id"]):
                result = probe.derive_row(row, MARKER, good_observation(row))
                self.assertEqual(result["measured_status"], "observed_inspected")
                self.assertIs(result["payload_preserved"], True)
                self.assertEqual(result["detector_observed"], row["obligation"] == "detector_text")

    def test_request_does_not_require_client_echo(self):
        row = profile_row("req-msg1-content")
        obs = good_observation(row)
        self.assertNotIn(MARKER.encode(), obs["client_body"])
        result = probe.derive_row(row, MARKER, obs)
        self.assertEqual(result["measured_status"], "observed_inspected")
        self.assertIs(result["client_observed"], False)

    def test_request_marker_in_client_cannot_replace_backend_evidence(self):
        row = profile_row("req-msg1-content")
        obs = good_observation(row)
        obs["client_body"] = json.dumps(obs["request_payload"]).encode()
        obs["snapshot"]["backend_payloads"] = []
        self.assert_not_inspected(row, obs)

    def test_complete_text_must_survive_at_each_boundary(self):
        for fixture_id in ("req-msg1-content", "resp-choice0-content"):
            row = profile_row(fixture_id)
            for boundary in ("hook", "destination"):
                with self.subTest(fixture=fixture_id, boundary=boundary):
                    obs = good_observation(row)
                    if boundary == "hook":
                        doc = obs["snapshot"]["hook_bodies"][row["phase"]][0]
                    elif row["phase"] == "request":
                        doc = obs["snapshot"]["backend_payloads"][0]
                    else:
                        doc = json.loads(obs["client_body"])
                    if row["phase"] == "request":
                        doc["messages"][1]["content"] = MARKER
                    else:
                        doc["choices"][0]["message"]["content"] = MARKER
                        if boundary == "destination":
                            obs["client_body"] = json.dumps(doc).encode()
                    self.assertIs(self.assert_not_inspected(row, obs)["payload_preserved"], False)

    def test_moved_response_id_is_not_preserved(self):
        row = profile_row("resp-id")
        for boundary in ("hook", "client"):
            obs = good_observation(row)
            doc = obs["snapshot"]["hook_bodies"]["response"][0] if boundary == "hook" else json.loads(obs["client_body"])
            doc["choices"][0]["message"]["content"] = doc.pop("id")
            if boundary == "client":
                obs["client_body"] = json.dumps(doc).encode()
            self.assertIs(self.assert_not_inspected(row, obs)["payload_preserved"], False)

    def test_structure_preserves_siblings_order_and_types(self):
        for fixture_id in ("req-messages", "resp-choices"):
            row = profile_row(fixture_id)
            for mutation in ("drop", "reorder", "type"):
                with self.subTest(fixture=fixture_id, mutation=mutation):
                    obs = good_observation(row)
                    array = obs["snapshot"]["hook_bodies"][row["phase"]][0][row["pointer"][1:]]
                    if mutation == "drop":
                        array.pop()
                    elif mutation == "reorder":
                        array.reverse()
                    elif fixture_id == "req-messages":
                        array[0]["role"] = [array[0]["role"]]
                    else:
                        array[0]["index"] = False
                    self.assert_not_inspected(row, obs)

    def test_numeric_type_confusion_fails(self):
        row = profile_row("resp-choice0-index")
        for value in (False, "0", 0.0):
            obs = good_observation(row)
            obs["snapshot"]["hook_bodies"]["response"][0]["choices"][0]["index"] = value
            self.assert_not_inspected(row, obs)

    def test_matching_leaf_in_wrong_ancestor_structure_fails(self):
        row = profile_row("req-msg1-content")
        for mutation in ("object", "short_array"):
            obs = good_observation(row)
            hook = obs["snapshot"]["hook_bodies"]["request"][0]
            if mutation == "object":
                hook["messages"] = {str(i): message for i, message in enumerate(hook["messages"])}
            else:
                hook["messages"].pop()
            self.assert_not_inspected(row, obs)

    def test_object_key_order_is_allowed(self):
        row = profile_row("resp-choices")
        obs = good_observation(row)
        choice = obs["snapshot"]["hook_bodies"]["response"][0]["choices"][0]
        obs["snapshot"]["hook_bodies"]["response"][0]["choices"][0] = dict(reversed(list(choice.items())))
        self.assertEqual(probe.derive_row(row, MARKER, obs)["measured_status"], "observed_inspected")

    def test_normalized_pointer_is_used_for_hook_only(self):
        row = profile_row("resp-id")
        row["normalized_pointer"] = "/normalized/id"
        obs = good_observation(row)
        obs["snapshot"]["hook_bodies"]["response"] = [{"normalized": {"id": MARKER}}]
        self.assertEqual(probe.derive_row(row, MARKER, obs)["measured_status"], "observed_inspected")

    def test_spy_miss_or_missing_maps_cannot_pass(self):
        row = profile_row("req-msg1-content")
        for maps in ([], [{}], [{row["fixture_id"]: False}]):
            obs = good_observation(row)
            obs["snapshot"]["hook_observed_maps"]["request"] = maps
            result = self.assert_not_inspected(row, obs)
            self.assertIs(result["detector_observed"], False)

    def test_spy_and_hook_from_different_events_cannot_be_joined(self):
        row = profile_row("req-msg1-content")
        obs = good_observation(row)
        obs["snapshot"]["hook_bodies"]["request"].append(probe.base_request())
        obs["snapshot"]["hook_observed_maps"]["request"] = [{row["fixture_id"]: False}, {row["fixture_id"]: True}]
        obs["snapshot"]["hook_counts"]["request"] = 2
        self.assert_not_inspected(row, obs)

    def test_response_requires_actual_source_not_call_count(self):
        row = profile_row("resp-choice0-content")
        for responses in ([], [probe.base_response()]):
            obs = good_observation(row)
            obs["snapshot"]["backend_responses"] = responses
            result = self.assert_not_inspected(row, obs)
            self.assertIs(result["backend_observed"], False)
            self.assertIs(result["source_matches_fixture"], False)

    def test_missing_ingress_field_is_not_claimed_present(self):
        row = profile_row("req-image-part")
        obs = good_observation(row)
        obs["request_payload"] = probe.base_request()
        self.assertIs(self.assert_not_inspected(row, obs)["pre_normalization_present"], False)

    def test_unknown_response_silent_drop_is_not_forwarded_due_to_source(self):
        row = profile_row("resp-unknown")
        obs = good_observation(row)
        obs["snapshot"]["hook_bodies"]["response"] = [probe.base_response()]
        obs["client_body"] = json.dumps(probe.base_response()).encode()
        result = probe.derive_row(row, MARKER, obs)
        self.assertEqual(result["measured_status"], "unknown")
        self.assertIs(result["backend_observed"], True)

    def test_rejected_fields_are_never_inspected_or_protected(self):
        for row in field_profile.rows():
            if not row["obligation"].startswith("reject_"):
                continue
            obs = good_observation(row)
            self.assertEqual(probe.derive_row(row, MARKER, obs)["measured_status"], "forwarded_uninspected")
            obs["snapshot"]["hook_bodies"][row["phase"]] = []
            obs["snapshot"]["hook_observed_maps"][row["phase"]] = []
            obs["snapshot"]["hook_counts"][row["phase"]] = 0
            obs["snapshot"]["backend_payloads"] = []
            obs["client_body"] = b'{}'
            obs["http_status"] = 422
            result = probe.derive_row(row, MARKER, obs)
            self.assertEqual(result["measured_status"], "unknown")
            self.assertIsNone(result["gateway_rejection_code"])
            self.assertIs(result["gateway_rejected_before_normalization"], False)

    def test_ambiguous_or_invalid_client_json_fails(self):
        row = profile_row("resp-id")
        for raw in (b'not JSON', b'{"id":"other","id":"' + MARKER.encode() + b'"}',
                    b'{"id":"' + MARKER.encode() + b'","extra":NaN}'):
            obs = good_observation(row)
            obs["client_body"] = raw
            self.assert_not_inspected(row, obs)


class HTTPObservations(unittest.TestCase):
    def test_invalid_backend_json_retains_bytes_without_field_evidence(self):
        opener = build_opener(ProxyHandler({}))
        with probe.fixture_server() as (state, port):
            for raw in (b'{"messages":[{"content":"changed","content":"expected"}]}',
                        b'{"extra":1e400}', b'{"extra":"\\ud800"}'):
                with self.subTest(raw=raw):
                    state.reset({}, {})
                    with opener.open(Request(f"http://127.0.0.1:{port}/v1/chat/completions", data=raw), timeout=5) as response:
                        response.read()
                    with state.lock:
                        self.assertEqual(state.backend_payloads, [None])
                        self.assertEqual(state.backend_request_hex, [raw.hex()])

    def test_real_http_fixture_records_sources_spy_and_control_without_echo(self):
        # This relay tests our measuring instrument over HTTP; native Gateway is CI's job.
        req, resp = "R" * 32, "S" * 32
        rows = probe.control_rows()
        targets = {}
        for row, marker in zip(rows, (req, resp)):
            targets.update(probe.spy_targets(row, marker))
        opener = build_opener(ProxyHandler({}))
        with probe.fixture_server() as (state, fixture_port):
            fixture_url = f"http://127.0.0.1:{fixture_port}"

            def post(path, body):
                with opener.open(Request(fixture_url + path, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"}), timeout=5) as response:
                    return response.read()

            class Relay(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    post("/request", {"body": body})
                    response = post("/v1/chat/completions", body)
                    post("/response", {"body": json.loads(response)})
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)

            relay = ThreadingHTTPServer(("127.0.0.1", 0), Relay)
            thread = threading.Thread(target=relay.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{relay.server_address[1]}/v1/chat/completions"
                for spy_enabled in (True, False):
                    with self.subTest(spy_enabled=spy_enabled):
                        state.reset(targets, {"/choices/0/message/content": resp})
                        scanner = promptguard.find_markers if spy_enabled else lambda *args: {}
                        with patch.object(promptguard, "find_markers", side_effect=scanner):
                            obs = probe.observe_case(url, state, probe.fixture_document(rows[0], req))
                        self.assertNotIn(req.encode(), obs["client_body"])
                        self.assertEqual(probe.controls_pass(obs, req, resp), spy_enabled)
                        self.assertEqual(obs["snapshot"]["backend_responses"], [json.loads(obs["client_body"])])
                        self.assertEqual(obs["snapshot"]["hook_counts"], {"request": 1, "response": 1})
                        raw = probe.serializable_observation(obs)
                        self.assertEqual(bytes.fromhex(raw["client_body_hex"]), obs["client_body"])
                        json.dumps(raw)
            finally:
                relay.shutdown()
                relay.server_close()
                thread.join(timeout=5)


class ControlsCheck(unittest.TestCase):
    def good_obs(self):
        req_row, resp_row = probe.control_rows()
        req, resp = "R" * 32, "S" * 32
        obs = good_observation(req_row, req)
        response = probe.fixture_document(resp_row, resp)
        obs["snapshot"]["backend_responses"] = [copy.deepcopy(response)]
        obs["snapshot"]["hook_bodies"]["response"] = [copy.deepcopy(response)]
        obs["snapshot"]["hook_observed_maps"]["response"] = [{"control-response": True}]
        obs["client_body"] = json.dumps(response).encode()
        return obs, req, resp

    def test_control_is_reachable_without_echo(self):
        obs, req, resp = self.good_obs()
        self.assertNotIn(req.encode(), obs["client_body"])
        self.assertTrue(probe.controls_pass(obs, req, resp))

    def test_control_rejects_missing_source_spy_and_changed_field(self):
        for mutation in ("backend", "source", "spy", "truncated", "counts", "status"):
            obs, req, resp = self.good_obs()
            if mutation == "backend":
                obs["snapshot"]["backend_payloads"] = []
            elif mutation == "source":
                obs["snapshot"]["backend_responses"] = []
            elif mutation == "spy":
                obs["snapshot"]["hook_observed_maps"]["response"] = [{}]
            elif mutation == "truncated":
                obs["snapshot"]["hook_bodies"]["request"][0]["messages"][1]["content"] = req
            elif mutation == "counts":
                obs["snapshot"]["hook_counts"]["request"] = 0
            else:
                obs["http_status"] = 500
            with self.subTest(mutation=mutation):
                self.assertFalse(probe.controls_pass(obs, req, resp))

    def test_profile_digest_is_stable_hex(self):
        first = probe.profile_digest()
        self.assertEqual(len(first), 64)
        int(first, 16)
        self.assertEqual(first, probe.profile_digest())


if __name__ == "__main__":
    unittest.main()
