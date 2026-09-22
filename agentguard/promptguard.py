# Minimal deterministic PromptGuard hook for text-nonstream-v1 measurement.
#
# This is a measurement spy, not a production guard. It strictly validates
# the Gateway webhook envelope, records which synthetic markers reached the
# hook body byte for byte, and allows well-formed envelopes so the probe can
# observe backend and client propagation. It produces no PII, secret, or
# injection verdicts. detector_observed is true only when the exact marker
# bytes for that field are present in the normalized hook body.
# Malformed envelopes are rejected fail-closed with HTTP 403 semantics.
from __future__ import annotations

import json
from typing import Any

ALLOW_REASON = "PROMPTGUARD_ALLOW"
ENVELOPE_REJECT_REASON = "HOOK_ENVELOPE_INVALID"
MAX_REASON_LEN = 512
MAX_BODY_BYTES = 1024 * 1024


class PromptGuardRejected(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PromptGuardRejected("HOOK_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_value):
    raise PromptGuardRejected("HOOK_NON_JSON_CONSTANT")


def parse_envelope(raw: bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BODY_BYTES:
        raise PromptGuardRejected("HOOK_ENVELOPE_INVALID")
    try:
        doc = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PromptGuardRejected("HOOK_ENVELOPE_INVALID") from exc
    if type(doc) is not dict or "body" not in doc:
        raise PromptGuardRejected("HOOK_ENVELOPE_INVALID")
    return doc


def _canonical_text(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return ""


def find_markers(body: Any, markers: dict) -> dict:
    text = _canonical_text(body)
    found = {}
    for fixture_id, marker in markers.items():
        if type(marker) is str and marker and marker in text:
            found[fixture_id] = True
        else:
            found[fixture_id] = False
    return found


def decide(phase: str, envelope: Any, markers: dict):
    if phase not in ("request", "response"):
        raise PromptGuardRejected("HOOK_PHASE_INVALID")
    if type(envelope) is not dict or "body" not in envelope:
        raise PromptGuardRejected("HOOK_ENVELOPE_INVALID")
    observed = find_markers(envelope["body"], markers)
    return True, ALLOW_REASON, observed


def _check_reason(reason: str) -> None:
    if type(reason) is not str or not reason or len(reason) > MAX_REASON_LEN:
        raise PromptGuardRejected("HOOK_REASON_INVALID")


def action_response(*, allow: bool, reason: str) -> bytes:
    _check_reason(reason)
    if allow:
        action = {"reason": reason}
    else:
        action = {"reason": reason, "status_code": 403, "body": "Blocked by PromptGuard measurement hook"}
    try:
        return json.dumps({"action": action}, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PromptGuardRejected("HOOK_ACTION_INVALID") from exc
