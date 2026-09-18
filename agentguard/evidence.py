"""Validate trusted E2E evidence before a future compiler may activate a route.

Caller must obtain the artifact hash and expected deployment scope from its
trusted release catalog, NOT from the submitted evidence. This is not a signing
service, full policy compiler, or proof that a handwritten report is genuine.
"""
from __future__ import annotations
import hashlib
import json
import re
from typing import Any

BINDINGS = frozenset({'gateway_image', 'gateway_config', 'compiler', 'adapter'})
GATES = frozenset({'G0-WIRE', 'G0-CONTEXT', 'G0-COVERAGE', 'G0-DEADLINE'})
CONTEXT = frozenset({'original_path', 'original_media_type', 'effective_stream', 'requested_model'})
SCOPE = frozenset({'route_id', 'protocol', 'phase', 'schema_sha256'})


class EvidenceRejected(ValueError):
    pass


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceRejected('DUPLICATE_KEY')
        result[key] = value
    return result


def _constant(_value):
    raise EvidenceRejected('NON_JSON_CONSTANT')


def validate_evidence(raw: bytes, *, bindings: dict[str, str], trusted_artifact_sha256: str,
                      scope: dict[str, str], required_fields: set[str], now: int,
                      max_age_seconds: int = 3600) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
        raise EvidenceRejected('EVIDENCE_MISSING_OR_OVERSIZE')
    if not _sha(trusted_artifact_sha256):
        raise EvidenceRejected('TRUSTED_REFERENCE_MISSING')
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != trusted_artifact_sha256:
        raise EvidenceRejected('ARTIFACT_DIGEST_MISMATCH')
    if not isinstance(bindings, dict) or set(bindings) != BINDINGS or not all(_sha(v) for v in bindings.values()):
        raise EvidenceRejected('INVALID_EXPECTED_BINDINGS')
    if not isinstance(scope, dict) or set(scope) != SCOPE:
        raise EvidenceRejected('INVALID_EXPECTED_SCOPE')
    if not all(isinstance(v, str) and v for v in scope.values()) or not _sha(scope['schema_sha256']):
        raise EvidenceRejected('INVALID_EXPECTED_SCOPE')
    if not isinstance(required_fields, (set, frozenset)) or not required_fields:
        raise EvidenceRejected('EXPECTED_FIELDS_MISSING')
    # This field-level profile excludes the empty document-root pointer.
    if not all(isinstance(p, str) and re.fullmatch(r'(?:/(?:[^~/]|~[01])*)+', p) is not None
               for p in required_fields):
        raise EvidenceRejected('INVALID_EXPECTED_FIELDS')
    if type(now) is not int or now < 0 or type(max_age_seconds) is not int or max_age_seconds <= 0:
        raise EvidenceRejected('INVALID_CLOCK_OR_MAX_AGE')
    try:
        doc = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceRejected('INVALID_EVIDENCE_JSON') from exc
    keys = {'kind', 'bindings', 'scope', 'generated_at', 'expires_at', 'gates',
            'trusted_context', 'field_coverage', 'unknown_fields_rejected'}
    if not isinstance(doc, dict) or set(doc) != keys or doc['kind'] != 'gateway-e2e-evidence/v1':
        raise EvidenceRejected('INVALID_EVIDENCE_SCHEMA')
    if doc['bindings'] != bindings or doc['scope'] != scope:
        raise EvidenceRejected('DEPLOYMENT_BINDING_MISMATCH')
    generated, expires = doc['generated_at'], doc['expires_at']
    if type(generated) is not int or type(expires) is not int:
        raise EvidenceRejected('INVALID_EVIDENCE_TIME')
    if not 0 <= generated <= now < expires or now - generated > max_age_seconds:
        raise EvidenceRejected('STALE_OR_FUTURE_EVIDENCE')
    if not isinstance(doc['gates'], dict) or set(doc['gates']) != GATES:
        raise EvidenceRejected('GATE_EVIDENCE_MISSING')
    if any(value != 'PASS' for value in doc['gates'].values()):
        raise EvidenceRejected('RUNTIME_GATE_NOT_PASSED')
    context = doc['trusted_context']
    if not isinstance(context, list) or any(not isinstance(v, str) for v in context):
        raise EvidenceRejected('TRUSTED_CONTEXT_MISSING')
    if len(context) != len(CONTEXT) or set(context) != CONTEXT:
        raise EvidenceRejected('TRUSTED_CONTEXT_MISSING')
    fields = doc['field_coverage']
    if not isinstance(fields, dict) or set(fields) != required_fields:
        raise EvidenceRejected('FIELD_SCOPE_MISMATCH')
    if any(value not in ('observed_inspected', 'ingress_rejected') for value in fields.values()):
        raise EvidenceRejected('INCOMPLETE_COVERAGE')
    if doc['unknown_fields_rejected'] is not True:
        raise EvidenceRejected('INGRESS_ENVELOPE_UNPROTECTED')
    return {'status': 'EVIDENCE_VALIDATED', 'artifact_sha256': actual_hash,
            'bindings': dict(bindings), 'scope': dict(scope), 'expires_at': expires}
