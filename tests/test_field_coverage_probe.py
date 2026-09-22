import copy
import hashlib
import json
import unittest

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
    def test_valid_envelope_allows(self):
        envelope = promptguard.parse_envelope(b"{\"body\":{\"messages\":[{\"content\":\"abc MARKER xyz\"}]}}")
        allow, reason, observed = promptguard.decide("request", envelope, {"f": "MARKER"})
        self.assertTrue(allow)
        self.assertEqual(reason, "PROMPTGUARD_ALLOW")
        self.assertEqual(observed, {"f": True})

    def test_missing_marker_is_not_observed(self):
        envelope = promptguard.parse_envelope(b"{\"body\":{\"messages\":[]}}")
        _, _, observed = promptguard.decide("response", envelope, {"f": "ABSENT"})
        self.assertEqual(observed, {"f": False})

    def test_malformed_envelopes_rejected(self):
        for raw in (b"", b"{}", b"[]", b"{\"no_body\":1}", b"not json", b"{\"body\":1,\"body\":2}", b"NaN"):
            with self.subTest(raw=raw):
                with self.assertRaises(promptguard.PromptGuardRejected):
                    promptguard.parse_envelope(raw)

    def test_bad_phase_rejected(self):
        with self.assertRaises(promptguard.PromptGuardRejected):
            promptguard.decide("sideways", {"body": {}}, {})

    def test_action_shapes(self):
        allow = json.loads(promptguard.action_response(allow=True, reason="PROMPTGUARD_ALLOW"))
        self.assertEqual(allow, {"action": {"reason": "PROMPTGUARD_ALLOW"}})
        deny = json.loads(promptguard.action_response(allow=False, reason="HOOK_ENVELOPE_INVALID"))
        self.assertEqual(deny["action"]["reason"], "HOOK_ENVELOPE_INVALID")
        self.assertEqual(deny["action"]["status_code"], 403)
        with self.assertRaises(promptguard.PromptGuardRejected):
            promptguard.action_response(allow=True, reason="")


class RequestEmbedding(unittest.TestCase):
    def test_each_request_pointer_carries_marker(self):
        marker = "AB12" * 8
        pointers = [r["pointer"] for r in field_profile.rows() if r["phase"] == "request"]
        self.assertEqual(len(pointers), 12)
        for pointer in pointers:
            with self.subTest(pointer=pointer):
                payload = probe.embed_request_marker(probe.base_request(), pointer, marker)
                if pointer == "/temperature":
                    self.assertIn(str(probe.numeric_marker(marker)), json.dumps(payload))
                elif pointer == "/stream":
                    self.assertTrue(payload["stream"] is True)
                else:
                    self.assertIn(marker, json.dumps(payload))

    def test_unknown_request_pointer_raises(self):
        with self.assertRaises(ValueError):
            probe.embed_request_marker(probe.base_request(), "/nope", "M")

    def test_each_response_pointer_carries_marker(self):
        marker = "CD34" * 8
        pointers = [r["pointer"] for r in field_profile.rows() if r["phase"] == "response"]
        self.assertEqual(len(pointers), 9)
        for pointer in pointers:
            with self.subTest(pointer=pointer):
                response = probe.embed_response_marker(probe.base_response(), pointer, marker)
                if pointer == "/choices/0/index":
                    self.assertIn(str(probe.numeric_marker(marker)), json.dumps(response))
                else:
                    self.assertIn(marker, json.dumps(response))

    def test_unknown_response_pointer_raises(self):
        with self.assertRaises(ValueError):
            probe.embed_response_marker(probe.base_response(), "/nope", "M")

    def test_probe_config_satisfies_context_route(self):
        config = probe.probe_gateway_config(9000, 9101)
        validate_route(config["binds"][0]["listeners"][0]["routes"][0])


def fake_obs(*, status, hook_bodies, backend_payloads, client_body, hook_counts, upstream=1):
    return {"http_status": status, "client_body": client_body, "elapsed_ms": 1.0, "snapshot": {"hook_counts": hook_counts, "hook_bodies": hook_bodies, "backend_payloads": backend_payloads, "upstream_count": upstream}}


class DeriveRow(unittest.TestCase):
    def row(self, phase, pointer, obligation="detector_text"):
        return {"phase": phase, "pointer": pointer, "fixture_id": "f", "field_type": "string", "obligation": obligation}

    def test_inspected_request_row(self):
        marker = "A" * 32
        body = {"messages": [{"content": marker}]}
        obs = fake_obs(status=200, hook_bodies={"request": [body], "response": []}, backend_payloads=[{"messages": [{"content": marker}]}], client_body=("{\"x\":\"" + marker + "\"}").encode(), hook_counts={"request": 1, "response": 0})
        derived = probe.derive_row(self.row("request", "/messages/1/content"), marker, obs)
        self.assertEqual(derived["measured_status"], "observed_inspected")
        self.assertTrue(derived["payload_preserved"] is True)
        self.assertFalse(derived["gateway_rejected_before_normalization"] is True)

    def test_forwarded_without_hook(self):
        marker = "B" * 32
        obs = fake_obs(status=200, hook_bodies={"request": [{"messages": []}], "response": []}, backend_payloads=[{"top_unknown": marker}], client_body=b"{}", hook_counts={"request": 1, "response": 0})
        derived = probe.derive_row(self.row("request", "/top_unknown", obligation="reject_unknown"), marker, obs)
        self.assertEqual(derived["measured_status"], "forwarded_uninspected")

    def test_silent_drop_is_unknown_never_rejected(self):
        marker = "C" * 32
        obs = fake_obs(status=200, hook_bodies={"request": [{"messages": []}], "response": []}, backend_payloads=[{"messages": []}], client_body=b"{}", hook_counts={"request": 1, "response": 0})
        derived = probe.derive_row(self.row("request", "/top_unknown", obligation="reject_unknown"), marker, obs)
        self.assertEqual(derived["measured_status"], "unknown")
        self.assertIsNone(derived["gateway_rejection_code"])

    def test_transport_reject_without_code_is_unknown(self):
        marker = "D" * 32
        obs = fake_obs(status=422, hook_bodies={"request": [], "response": []}, backend_payloads=[], client_body=b"{}", hook_counts={"request": 0, "response": 0}, upstream=0)
        derived = probe.derive_row(self.row("request", "/top_unknown", obligation="reject_unknown"), marker, obs)
        self.assertEqual(derived["measured_status"], "unknown")
        self.assertIn("without native rejection code", derived["detail"])

    def test_never_emits_ingress_rejected(self):
        marker = "E" * 32
        bodies = [{"messages": []}]
        for status, hook_counts in ((200, {"request": 1, "response": 0}), (403, {"request": 0, "response": 0}), (500, {"request": 1, "response": 0})):
            obs = fake_obs(status=status, hook_bodies={"request": bodies, "response": []}, backend_payloads=bodies, client_body=b"{}", hook_counts=hook_counts)
            derived = probe.derive_row(self.row("request", "/model", obligation="type_value"), marker, obs)
            self.assertIn(derived["measured_status"], ("observed_inspected", "forwarded_uninspected", "unknown"))

    def test_inspected_response_row(self):
        marker = "F" * 32
        body = {"choices": [{"message": {"content": marker}}]}
        obs = fake_obs(status=200, hook_bodies={"request": [], "response": [body]}, backend_payloads=[], client_body=("prefix " + marker).encode(), hook_counts={"request": 0, "response": 1})
        derived = probe.derive_row(self.row("response", "/choices/0/message/content"), marker, obs)
        self.assertEqual(derived["measured_status"], "observed_inspected")


    def test_response_row_without_backend_call_is_not_inspected(self):
        marker = "G" * 32
        body = {"choices": [{"message": {"content": marker}}]}
        obs = fake_obs(status=200, hook_bodies={"request": [], "response": [body]}, backend_payloads=[], client_body=("prefix " + marker).encode(), hook_counts={"request": 0, "response": 1}, upstream=0)
        derived = probe.derive_row(self.row("response", "/choices/0/message/content"), marker, obs)
        self.assertFalse(derived["backend_observed"] is True)
        self.assertNotEqual(derived["measured_status"], "observed_inspected")


class ControlsCheck(unittest.TestCase):
    def test_controls_pass_and_fail(self):
        req, resp = "R" * 32, "S" * 32
        good = fake_obs(status=200, hook_bodies={"request": [{"messages": [req]}], "response": [[resp]]}, backend_payloads=[{"messages": [req]}], client_body=(req + resp).encode(), hook_counts={"request": 1, "response": 1})
        self.assertTrue(probe.controls_pass(good, req, resp))
        bad_status = copy.deepcopy(good)
        bad_status["http_status"] = 500
        self.assertFalse(probe.controls_pass(bad_status, req, resp))
        bad_counts = copy.deepcopy(good)
        bad_counts["snapshot"]["hook_counts"] = {"request": 0, "response": 1}
        self.assertFalse(probe.controls_pass(bad_counts, req, resp))

    def test_profile_digest_is_stable_hex(self):
        first = probe.profile_digest()
        self.assertEqual(len(first), 64)
        int(first, 16)
        self.assertEqual(first, probe.profile_digest())


if __name__ == "__main__":
    raise SystemExit(unittest.main())
