# Frozen text-nonstream field profile for native coverage measurement.
#
# PROFILE_ID text-nonstream-v1 fixes the closed field set for the first
# native probe slice: /v1/chat/completions with text messages and a
# non-streaming response. It declares the contract each field must meet in a
# protected deployment. The native probe measures what the Gateway actually
# does and records gaps as findings instead of rewriting the oracle.
#
# This module never claims detector recall, PII or injection capability, or
# G0-COVERAGE PASS. Unknown and out-of-profile fields must be rejected before
# normalization. Silent forwarding or silent drops are measured as
# forwarded_uninspected or unknown, never coerced into ingress_rejected.
from __future__ import annotations

import copy
import re
from typing import Any

PROFILE_ID = "text-nonstream-v1"
PROTOCOL = "openai-chat-completions"
ROUTE_ID = "fixture-completions"

_POINTER_RE = re.compile(r"(?:/(?:[^~/]|~[01])*)+")


def _pointer_ok(value: Any, *, allow_none: bool = False) -> bool:
    if allow_none and value is None:
        return True
    return isinstance(value, str) and bool(value) and _POINTER_RE.fullmatch(value) is not None


# Each row declares the protected-deployment contract. obligation names what
# must be proven for the field. Only text content needs a detector view.
# Everything else needs type, value or structure enforcement.
# normalized_pointer is the required post-normalization location.
# Rejection rows use None.
_ROWS: tuple = (
    {"phase": "request", "pointer": "/model", "field_type": "string",
     "normalized_pointer": "/model", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-model",
     "obligation": "type_value",
     "description": "requested model string must reach hook and backend unchanged"},
    {"phase": "request", "pointer": "/stream", "field_type": "boolean",
     "normalized_pointer": None, "native_enforcement": "reject_before_normalization",
     "lossiness": "rejected", "fixture_id": "req-stream",
     "obligation": "reject_unsupported",
     "description": "stream=true must be rejected before normalization; control uses stream=false"},
    {"phase": "request", "pointer": "/temperature", "field_type": "number",
     "normalized_pointer": "/temperature", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-temperature",
     "obligation": "type_value",
     "description": "numeric metadata must not be silently altered or dropped"},
    {"phase": "request", "pointer": "/messages", "field_type": "array",
     "normalized_pointer": "/messages", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-messages",
     "obligation": "structure",
     "description": "message array structure must be preserved"},
    {"phase": "request", "pointer": "/messages/0/role", "field_type": "string",
     "normalized_pointer": "/messages/0/role", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-msg0-role",
     "obligation": "type_value",
     "description": "system role at index 0 must be distinguished"},
    {"phase": "request", "pointer": "/messages/0/content", "field_type": "string",
     "normalized_pointer": "/messages/0/content", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-msg0-content",
     "obligation": "detector_text",
     "description": "system text at index 0 must enter the detector view"},
    {"phase": "request", "pointer": "/messages/1/role", "field_type": "string",
     "normalized_pointer": "/messages/1/role", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-msg1-role",
     "obligation": "type_value",
     "description": "user role at index 1 must be distinguished"},
    {"phase": "request", "pointer": "/messages/1/content", "field_type": "string",
     "normalized_pointer": "/messages/1/content", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-msg1-content",
     "obligation": "detector_text",
     "description": "user text at index 1 must enter the detector view"},
    {"phase": "request", "pointer": "/messages/2/content", "field_type": "string",
     "normalized_pointer": "/messages/2/content", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "req-msg2-content",
     "obligation": "detector_text",
     "description": "third message proves scanning is not limited to first entries"},
    {"phase": "request", "pointer": "/messages/1/tool_calls", "field_type": "tool_call",
     "normalized_pointer": None, "native_enforcement": "reject_before_normalization",
     "lossiness": "rejected", "fixture_id": "req-tool-calls",
     "obligation": "reject_unsupported",
     "description": "tool calls are outside text-nonstream-v1 and must be rejected"},
    {"phase": "request", "pointer": "/messages/1/content/1", "field_type": "content_part",
     "normalized_pointer": None, "native_enforcement": "reject_before_normalization",
     "lossiness": "rejected", "fixture_id": "req-image-part",
     "obligation": "reject_unsupported",
     "description": "image content parts are outside text-nonstream-v1 and must be rejected"},
    {"phase": "request", "pointer": "/top_unknown", "field_type": "unknown",
     "normalized_pointer": None, "native_enforcement": "reject_before_normalization",
     "lossiness": "rejected", "fixture_id": "req-unknown",
     "obligation": "reject_unknown",
     "description": "unknown top-level request field must be rejected before normalization"},
    {"phase": "response", "pointer": "/id", "field_type": "string",
     "normalized_pointer": "/id", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-id",
     "obligation": "type_value",
     "description": "response id must be preserved"},
    {"phase": "response", "pointer": "/model", "field_type": "string",
     "normalized_pointer": "/model", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-model",
     "obligation": "type_value",
     "description": "response model must be preserved"},
    {"phase": "response", "pointer": "/choices", "field_type": "array",
     "normalized_pointer": "/choices", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-choices",
     "obligation": "structure",
     "description": "choices array structure must be preserved"},
    {"phase": "response", "pointer": "/choices/0/index", "field_type": "number",
     "normalized_pointer": "/choices/0/index", "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-choice0-index",
     "obligation": "type_value",
     "description": "choice index 0 must be distinguished from other choices"},
    {"phase": "response", "pointer": "/choices/0/message/role", "field_type": "string",
     "normalized_pointer": "/choices/0/message/role",
     "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-choice0-role",
     "obligation": "type_value",
     "description": "assistant role at choice 0 must be distinguished"},
    {"phase": "response", "pointer": "/choices/0/message/content", "field_type": "string",
     "normalized_pointer": "/choices/0/message/content",
     "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-choice0-content",
     "obligation": "detector_text",
     "description": "assistant text at choice 0 must enter the detector view"},
    {"phase": "response", "pointer": "/choices/1/message/content", "field_type": "string",
     "normalized_pointer": "/choices/1/message/content",
     "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-choice1-content",
     "obligation": "detector_text",
     "description": "second choice proves scanning is not limited to choice 0"},
    {"phase": "response", "pointer": "/choices/0/finish_reason", "field_type": "string",
     "normalized_pointer": "/choices/0/finish_reason",
     "native_enforcement": "hook_and_egress",
     "lossiness": "none", "fixture_id": "resp-finish-reason",
     "obligation": "type_value",
     "description": "finish reason must be preserved"},
    {"phase": "response", "pointer": "/provider_extension", "field_type": "unknown",
     "normalized_pointer": None, "native_enforcement": "reject_before_normalization",
     "lossiness": "rejected", "fixture_id": "resp-unknown",
     "obligation": "reject_unknown",
     "description": "unknown provider extension must be rejected before normalization"},
)


def rows():
    return copy.deepcopy(list(_ROWS))


def registered_fixture_ids():
    return frozenset(r["fixture_id"] for r in _ROWS)


def validate_profile():
    seen = set()
    phases = set()
    unknown_phases = set()
    for row in _ROWS:
        if set(row) != {"phase", "pointer", "field_type", "normalized_pointer", "native_enforcement", "lossiness", "fixture_id", "obligation", "description"}:
            raise ValueError("FIELD_PROFILE_ROW_SCHEMA_CHANGED")
        if row["phase"] not in ("request", "response"):
            raise ValueError("FIELD_PROFILE_PHASE_INVALID")
        if not _pointer_ok(row["pointer"]):
            raise ValueError("FIELD_PROFILE_POINTER_INVALID")
        if not row["fixture_id"] or row["fixture_id"] in seen:
            raise ValueError("FIELD_PROFILE_FIXTURE_ID_INVALID")
        seen.add(row["fixture_id"])
        phases.add(row["phase"])
        if row["field_type"] == "unknown":
            unknown_phases.add(row["phase"])
            if row["normalized_pointer"] is not None or row["lossiness"] != "rejected" or row["native_enforcement"] != "reject_before_normalization":
                raise ValueError("FIELD_PROFILE_UNKNOWN_CONTRACT_INVALID")
        elif row["normalized_pointer"] is None:
            if row["lossiness"] != "rejected" or row["native_enforcement"] != "reject_before_normalization":
                raise ValueError("FIELD_PROFILE_REJECTION_CONTRACT_INVALID")
        else:
            if not _pointer_ok(row["normalized_pointer"]) or row["lossiness"] != "none" or row["native_enforcement"] != "hook_and_egress":
                raise ValueError("FIELD_PROFILE_INSPECTION_CONTRACT_INVALID")
        if not row["obligation"] or not row["description"]:
            raise ValueError("FIELD_PROFILE_OBLIGATION_MISSING")
    if phases != {"request", "response"}:
        raise ValueError("FIELD_PROFILE_PHASE_COVERAGE_MISSING")
    if unknown_phases != {"request", "response"}:
        raise ValueError("FIELD_PROFILE_UNKNOWN_COVERAGE_MISSING")
    if len(seen) != len(_ROWS):
        raise ValueError("FIELD_PROFILE_DUPLICATE_FIXTURE")
