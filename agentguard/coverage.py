"""Fail-closed external field-coverage and route preflight contracts.

The expected matrix is resolved from a trusted release catalog. A submitted
coverage report never chooses its own field set, deployment digests, or route
scope. This module is a preflight primitive; it does not activate a route or
claim that a native or Compose Gateway coverage run occurred.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


BINDINGS = frozenset({'gateway_image', 'gateway_config', 'compiler', 'adapter'})
PHASES = frozenset({'request', 'response'})
COVERAGE_SCOPE_PHASE = 'both'
SCOPE_KEYS = frozenset({'route_id', 'protocol', 'phase', 'schema_sha256',
                        'route_sha256'})
STATUSES = frozenset({'observed_inspected', 'ingress_rejected',
                      'forwarded_uninspected', 'unknown'})
POSITIVE_STATUSES = frozenset({'observed_inspected', 'ingress_rejected'})
FIELD_TYPES = frozenset({'string', 'boolean', 'number', 'object', 'array',
                         'message', 'content_part', 'tool_call', 'tool_result',
                         'unknown'})
NATIVE_ENFORCEMENTS = frozenset({'hook_and_egress',
                                 'reject_before_normalization'})
INGRESS_REJECTION_CODE = 'AG_COVERAGE_REJECT_BEFORE_NORMALIZATION'
RUNTIME_STATUS_NOT_EVALUATED = 'NOT_EVALUATED'
MATRIX_KIND = 'agentguard-field-coverage-matrix/v1'
EVIDENCE_KIND = 'agentguard-field-coverage-evidence/v1'
MATRIX_KEYS = frozenset({
    'kind', 'bindings', 'scope', 'generated_at', 'expires_at', 'provenance',
    'rows', 'unknown_original_fields_rejected_before_normalization',
})
PROVENANCE_KEYS = frozenset({'source', 'source_revision', 'retrieved_at', 'trusted'})
MATRIX_ROW_KEYS = frozenset({
    'phase', 'pointer', 'field_type', 'normalized_pointer', 'status',
    'native_enforcement', 'lossiness', 'fixture_id', 'artifact_sha256',
})
EVIDENCE_KEYS = frozenset({
    'kind', 'matrix_sha256', 'bindings', 'scope', 'generated_at', 'expires_at',
    'gates', 'runtime_status', 'gateway_evidence', 'rows',
    'unknown_original_fields_rejected_before_normalization',
})
GATEWAY_EVIDENCE_KEYS = frozenset({
    'runner_kind', 'process_listener_owned', 'request_id',
    'log_artifact_sha256', 'observation_artifact_sha256',
})
EVIDENCE_ROW_KEYS = frozenset({
    'phase', 'pointer', 'fixture_id', 'status', 'pre_normalization_present',
    'normalized_pointer', 'hook_observed', 'backend_observed',
    'client_observed', 'native_enforcement', 'lossiness', 'artifact_sha256',
    'gateway_rejected_before_normalization', 'gateway_http_status',
    'gateway_rejection_code', 'gateway_log_sha256', 'detector_observed',
    'detector_evidence_sha256', 'payload_preserved',
    'payload_evidence_sha256',
})


class CoverageRejected(ValueError):
    """Raised when a matrix or report cannot support protected coverage."""


def _sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _revision(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40,64}', value) is not None


def _pointer(value: Any, *, allow_none: bool = False) -> bool:
    """Validate a non-empty JSON Pointer used by a field-level row.

    The field matrix excludes the document-root pointer ``""``. ``"/"``
    remains valid and addresses a member whose name is empty.
    """
    if allow_none and value is None:
        return True
    return (isinstance(value, str) and value
            and re.fullmatch(r'(?:/(?:[^~/]|~[01])*)+', value) is not None)


def canonical_bytes(document: dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for a trusted matrix or route digest."""
    if type(document) is not dict:
        raise CoverageRejected('CANONICAL_DOCUMENT_NOT_OBJECT')
    try:
        return json.dumps(document, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, UnicodeError, ValueError, RecursionError) as exc:
        raise CoverageRejected('CANONICAL_DOCUMENT_INVALID') from exc


def matrix_sha256(matrix: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(matrix)).hexdigest()


def route_sha256(route: dict[str, Any]) -> str:
    """Digest the actual validated route, including backend and hook targets."""
    return hashlib.sha256(canonical_bytes(route)).hexdigest()


def deployment_config_sha256(config: dict[str, Any]) -> str:
    """Digest the complete deployed Gateway config, including its route wrapper."""
    return hashlib.sha256(canonical_bytes(config)).hexdigest()


def gateway_evidence_sha256(evidence: dict[str, Any]) -> str:
    """Digest the gateway metadata supplied by a trusted runner/catalog."""
    return hashlib.sha256(canonical_bytes(evidence)).hexdigest()


def _deployed_route(config: Any) -> dict[str, Any]:
    """Resolve the single route selected by the closed deployment profile."""
    if type(config) is not dict or set(config) != {'binds'}:
        raise CoverageRejected('COVERAGE_DEPLOYMENT_CONFIG_INVALID')
    binds = config['binds']
    if type(binds) is not list or len(binds) != 1:
        raise CoverageRejected('COVERAGE_DEPLOYMENT_CONFIG_INVALID')
    bind = binds[0]
    if (type(bind) is not dict or set(bind) != {'port', 'listeners'}
            or type(bind['port']) is not int or isinstance(bind['port'], bool)
            or not 1 <= bind['port'] <= 65535):
        raise CoverageRejected('COVERAGE_DEPLOYMENT_CONFIG_INVALID')
    listeners = bind['listeners']
    if type(listeners) is not list or len(listeners) != 1:
        raise CoverageRejected('COVERAGE_DEPLOYMENT_CONFIG_INVALID')
    listener = listeners[0]
    if type(listener) is not dict or set(listener) != {'routes'}:
        raise CoverageRejected('COVERAGE_DEPLOYMENT_CONFIG_INVALID')
    routes = listener['routes']
    if type(routes) is not list or len(routes) != 1 or type(routes[0]) is not dict:
        raise CoverageRejected('COVERAGE_DEPLOYMENT_CONFIG_INVALID')
    return routes[0]


def _validate_bindings(value: Any, expected: dict[str, str]) -> None:
    if (type(expected) is not dict or set(expected) != BINDINGS
            or any(not _sha(v) for v in expected.values())):
        raise CoverageRejected('MATRIX_EXPECTED_BINDINGS_INVALID')
    if (type(value) is not dict or set(value) != BINDINGS
            or any(not _sha(v) for v in value.values()) or value != expected):
        raise CoverageRejected('MATRIX_DEPLOYMENT_BINDING_MISMATCH')


def _validate_scope(value: Any, expected: dict[str, str]) -> None:
    if (type(expected) is not dict or set(expected) != SCOPE_KEYS
            or any(not isinstance(v, str) or not v for v in expected.values())
            or not _sha(expected['schema_sha256'])
            or not _sha(expected['route_sha256'])
            or expected['phase'] != COVERAGE_SCOPE_PHASE):
        raise CoverageRejected('MATRIX_EXPECTED_SCOPE_INVALID')
    if (type(value) is not dict or set(value) != SCOPE_KEYS
            or any(not isinstance(v, str) or not v for v in value.values())
            or not _sha(value['schema_sha256'])
            or not _sha(value['route_sha256'])
            or value['phase'] != COVERAGE_SCOPE_PHASE):
        raise CoverageRejected('MATRIX_SCOPE_INVALID')
    if value != expected:
        raise CoverageRejected('MATRIX_SCOPE_MISMATCH')


def _validate_time(generated: Any, expires: Any, *, now: int,
                   max_age_seconds: int) -> None:
    if (type(generated) is not int or type(expires) is not int
            or type(now) is not int or type(max_age_seconds) is not int
            or now < 0 or max_age_seconds <= 0):
        raise CoverageRejected('MATRIX_TIME_INVALID')
    if not 0 <= generated <= now < expires or now - generated > max_age_seconds:
        raise CoverageRejected('MATRIX_STALE_OR_FUTURE')


def _validate_provenance(value: Any, *, generated: int, now: int) -> None:
    if type(value) is not dict or set(value) != PROVENANCE_KEYS:
        raise CoverageRejected('MATRIX_PROVENANCE_INVALID')
    if (not isinstance(value['source'], str) or not value['source']
            or not _revision(value['source_revision'])
            or type(value['retrieved_at']) is not int
            or value['trusted'] is not True
            or not generated <= value['retrieved_at'] <= now):
        raise CoverageRejected('MATRIX_PROVENANCE_INVALID')


def _validate_gateway_evidence(value: Any) -> None:
    if type(value) is not dict or set(value) != GATEWAY_EVIDENCE_KEYS:
        raise CoverageRejected('COVERAGE_GATEWAY_EVIDENCE_SCHEMA_INVALID')
    if (not isinstance(value['runner_kind'], str)
            or value['runner_kind'] not in {'native_gateway', 'compose_gateway'}):
        raise CoverageRejected('COVERAGE_GATEWAY_RUNNER_INVALID')
    if value['process_listener_owned'] is not True:
        raise CoverageRejected('COVERAGE_GATEWAY_PROCESS_UNVERIFIED')
    if (not isinstance(value['request_id'], str) or not value['request_id']
            or len(value['request_id']) > 256):
        raise CoverageRejected('COVERAGE_GATEWAY_REQUEST_ID_INVALID')
    if not _sha(value['log_artifact_sha256']):
        raise CoverageRejected('COVERAGE_GATEWAY_LOG_ARTIFACT_INVALID')
    if not _sha(value['observation_artifact_sha256']):
        raise CoverageRejected('COVERAGE_GATEWAY_OBSERVATION_ARTIFACT_INVALID')


def _validate_matrix_row(row: Any) -> tuple[str, str]:
    if type(row) is not dict or set(row) != MATRIX_ROW_KEYS:
        raise CoverageRejected('MATRIX_ROW_SCHEMA_INVALID')
    phase, pointer = row['phase'], row['pointer']
    if not isinstance(phase, str) or phase not in PHASES or not _pointer(pointer):
        raise CoverageRejected('MATRIX_ROW_ID_INVALID')
    if not isinstance(row['field_type'], str) or row['field_type'] not in FIELD_TYPES:
        raise CoverageRejected('MATRIX_FIELD_TYPE_INVALID')
    if not _pointer(row['normalized_pointer'], allow_none=True):
        raise CoverageRejected('MATRIX_NORMALIZED_POINTER_INVALID')
    if not isinstance(row['status'], str) or row['status'] not in STATUSES:
        raise CoverageRejected('MATRIX_STATUS_INVALID')
    if (not isinstance(row['native_enforcement'], str)
            or row['native_enforcement'] not in NATIVE_ENFORCEMENTS):
        raise CoverageRejected('MATRIX_NATIVE_ENFORCEMENT_INVALID')
    if not isinstance(row['fixture_id'], str) or not row['fixture_id']:
        raise CoverageRejected('MATRIX_FIXTURE_ID_INVALID')
    if not _sha(row['artifact_sha256']):
        raise CoverageRejected('MATRIX_ARTIFACT_DIGEST_INVALID')
    if row['status'] == 'forwarded_uninspected':
        raise CoverageRejected('MATRIX_FORWARDED_UNINSPECTED')
    if row['status'] == 'unknown':
        raise CoverageRejected('MATRIX_UNKNOWN_FIELD')
    if row['status'] == 'observed_inspected':
        if (row['normalized_pointer'] is None
                or row['native_enforcement'] != 'hook_and_egress'
                or row['lossiness'] != 'none'
                or row['field_type'] == 'unknown'):
            raise CoverageRejected('MATRIX_NORMALIZATION_LOSS')
    else:
        if (row['normalized_pointer'] is not None
                or row['native_enforcement'] != 'reject_before_normalization'
                or row['lossiness'] != 'rejected'):
            raise CoverageRejected('MATRIX_REJECTION_CONTRACT_INVALID')
        if row['field_type'] == 'unknown' and row['status'] != 'ingress_rejected':
            raise CoverageRejected('MATRIX_UNKNOWN_FIELD_NOT_REJECTED')
    return phase, pointer


def _unknown_rejection_contract(rows: list[dict[str, Any]]) -> bool:
    return ({row['phase'] for row in rows
             if row['field_type'] == 'unknown'
             and row['status'] == 'ingress_rejected'} == set(PHASES))


def validate_matrix(matrix: dict[str, Any], *, expected_bindings: dict[str, str],
                    expected_scope: dict[str, str], trusted_matrix_sha256: str,
                    now: int, max_age_seconds: int = 3600) -> dict[str, Any]:
    """Validate the immutable expected matrix supplied by the release catalog."""
    if type(matrix) is not dict or set(matrix) != MATRIX_KEYS:
        raise CoverageRejected('MATRIX_SCHEMA_INVALID')
    if matrix['kind'] != MATRIX_KIND:
        raise CoverageRejected('MATRIX_KIND_INVALID')
    if not _sha(trusted_matrix_sha256) or matrix_sha256(matrix) != trusted_matrix_sha256:
        raise CoverageRejected('MATRIX_REFERENCE_MISMATCH')
    _validate_bindings(matrix['bindings'], expected_bindings)
    _validate_scope(matrix['scope'], expected_scope)
    _validate_time(matrix['generated_at'], matrix['expires_at'], now=now,
                   max_age_seconds=max_age_seconds)
    _validate_provenance(matrix['provenance'], generated=matrix['generated_at'], now=now)
    rows = matrix['rows']
    if type(rows) is not list or not rows or len(rows) > 10000:
        raise CoverageRejected('MATRIX_ROWS_INVALID')
    identities = []
    for row in rows:
        identities.append(_validate_matrix_row(row))
    if len(set(identities)) != len(identities):
        raise CoverageRejected('MATRIX_DUPLICATE_ROW')
    normalized_identities = [
        (row['phase'], row['normalized_pointer'])
        for row in rows
        if row['status'] == 'observed_inspected'
    ]
    if len(set(normalized_identities)) != len(normalized_identities):
        raise CoverageRejected('MATRIX_NORMALIZED_POINTER_COLLISION')
    if {phase for phase, _ in identities} != set(PHASES):
        raise CoverageRejected('MATRIX_PHASE_COVERAGE_MISSING')
    unknown_rejected = _unknown_rejection_contract(rows)
    if matrix['unknown_original_fields_rejected_before_normalization'] is not unknown_rejected:
        raise CoverageRejected('MATRIX_UNKNOWN_INGRESS_UNPROTECTED')
    if not unknown_rejected:
        raise CoverageRejected('MATRIX_UNKNOWN_FIELD_COVERAGE_MISSING')
    return {
        'status': 'FIELD_MATRIX_VALIDATED',
        'matrix_sha256': trusted_matrix_sha256,
        'row_count': len(rows),
        'required_fields': frozenset(identities),
        'runtime_status': RUNTIME_STATUS_NOT_EVALUATED,
    }


def _strict_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise CoverageRejected('COVERAGE_ARTIFACT_MISSING_OR_OVERSIZE')

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CoverageRejected('COVERAGE_DUPLICATE_KEY')
            result[key] = value
        return result

    def constant(_value):
        raise CoverageRejected('COVERAGE_NON_JSON_CONSTANT')

    try:
        value = json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CoverageRejected('COVERAGE_INVALID_JSON') from exc
    if type(value) is not dict:
        raise CoverageRejected('COVERAGE_SCHEMA_INVALID')
    return value


def _validate_gateway_observation(row: dict[str, Any]) -> None:
    if type(row['gateway_rejected_before_normalization']) is not bool:
        raise CoverageRejected('COVERAGE_GATEWAY_REJECTION_OBSERVATION_INVALID')
    if (type(row['gateway_http_status']) is not int
            or not 100 <= row['gateway_http_status'] <= 599):
        raise CoverageRejected('COVERAGE_GATEWAY_HTTP_STATUS_INVALID')
    if not _sha(row['gateway_log_sha256']):
        raise CoverageRejected('COVERAGE_GATEWAY_LOG_DIGEST_MISSING')
    if row['status'] == 'ingress_rejected':
        if (row['gateway_rejected_before_normalization'] is not True
                or not 400 <= row['gateway_http_status'] <= 599
                or row['gateway_rejection_code'] != INGRESS_REJECTION_CODE):
            raise CoverageRejected('COVERAGE_NATIVE_REJECTION_EVIDENCE_MISSING')
    elif row['status'] == 'observed_inspected':
        if (row['gateway_rejected_before_normalization'] is not False
                or not 200 <= row['gateway_http_status'] <= 299
                or row['gateway_rejection_code'] is not None):
            raise CoverageRejected('COVERAGE_NATIVE_INSPECTION_EVIDENCE_INVALID')
    else:
        raise CoverageRejected('COVERAGE_STATUS_INVALID')


def _validate_evidence_row(row: Any, expected: dict[str, Any],
                           gateway_log_artifact_sha256: str,
                           observation_artifact_sha256: str) -> None:
    if type(row) is not dict or set(row) != EVIDENCE_ROW_KEYS:
        raise CoverageRejected('COVERAGE_ROW_SCHEMA_INVALID')
    if not isinstance(row.get('phase'), str) or not isinstance(row.get('pointer'), str):
        raise CoverageRejected('COVERAGE_ROW_ID_INVALID')
    identity = (row['phase'], row['pointer'])
    if identity != (expected['phase'], expected['pointer']):
        raise CoverageRejected('COVERAGE_ROW_ID_MISMATCH')
    if row['fixture_id'] != expected['fixture_id']:
        raise CoverageRejected('COVERAGE_FIXTURE_MISMATCH')
    if row['artifact_sha256'] != expected['artifact_sha256']:
        raise CoverageRejected('COVERAGE_ARTIFACT_MISMATCH')
    if row['status'] != expected['status']:
        raise CoverageRejected('COVERAGE_STATUS_MISMATCH')
    if row['native_enforcement'] != expected['native_enforcement']:
        raise CoverageRejected('COVERAGE_NATIVE_ENFORCEMENT_MISMATCH')
    if row['lossiness'] != expected['lossiness']:
        raise CoverageRejected('COVERAGE_LOSSINESS_MISMATCH')
    if row['gateway_log_sha256'] != gateway_log_artifact_sha256:
        raise CoverageRejected('COVERAGE_GATEWAY_LOG_BINDING_MISMATCH')
    if type(row['pre_normalization_present']) is not bool:
        raise CoverageRejected('COVERAGE_PRE_NORMALIZATION_OBSERVATION_INVALID')
    if row['pre_normalization_present'] is not True:
        raise CoverageRejected('COVERAGE_PRE_NORMALIZATION_MISSING')
    if (type(row['hook_observed']) is not bool
            or type(row['backend_observed']) is not bool
            or type(row['client_observed']) is not bool):
        raise CoverageRejected('COVERAGE_OBSERVATION_INVALID')
    if type(row['detector_observed']) is not bool:
        raise CoverageRejected('COVERAGE_DETECTOR_OBSERVATION_INVALID')
    if row['payload_preserved'] is not None and type(row['payload_preserved']) is not bool:
        raise CoverageRejected('COVERAGE_PAYLOAD_PRESERVATION_INVALID')
    if (row['detector_evidence_sha256'] is not None
            and not _sha(row['detector_evidence_sha256'])):
        raise CoverageRejected('COVERAGE_DETECTOR_EVIDENCE_INVALID')
    if (row['payload_evidence_sha256'] is not None
            and not _sha(row['payload_evidence_sha256'])):
        raise CoverageRejected('COVERAGE_PAYLOAD_EVIDENCE_INVALID')
    if row['detector_evidence_sha256'] not in (None, observation_artifact_sha256):
        raise CoverageRejected('COVERAGE_DETECTOR_EVIDENCE_BINDING_MISMATCH')
    if row['payload_evidence_sha256'] not in (None, observation_artifact_sha256):
        raise CoverageRejected('COVERAGE_PAYLOAD_EVIDENCE_BINDING_MISMATCH')
    _validate_gateway_observation(row)
    if row['status'] == 'observed_inspected':
        if (row['normalized_pointer'] != expected['normalized_pointer']
                or row['hook_observed'] is not True
                or row['backend_observed'] is not True
                or row['client_observed'] is not True
                or row['native_enforcement'] != 'hook_and_egress'
                or row['lossiness'] != 'none'
                or row['detector_observed'] is not True
                or row['detector_evidence_sha256'] != observation_artifact_sha256
                or row['payload_preserved'] is not True
                or row['payload_evidence_sha256'] != observation_artifact_sha256):
            raise CoverageRejected('COVERAGE_NORMALIZATION_LOSS')
    elif (row['normalized_pointer'] is not None
          or row['hook_observed'] is not False
          or row['backend_observed'] is not False
          or row['client_observed'] is not True
          or row['native_enforcement'] != 'reject_before_normalization'
          or row['lossiness'] != 'rejected'
          or row['detector_observed'] is not False
          or row['detector_evidence_sha256'] is not None
          or row['payload_preserved'] is not None
          or row['payload_evidence_sha256'] is not None):
        raise CoverageRejected('COVERAGE_INGRESS_REJECTION_CONTRACT_INVALID')


def validate_coverage_evidence(raw: bytes, *, expected_matrix: dict[str, Any],
                               trusted_matrix_sha256: str,
                               trusted_artifact_sha256: str,
                               trusted_gateway_log_sha256: str,
                               trusted_gateway_evidence_sha256: str,
                               expected_bindings: dict[str, str],
                               expected_scope: dict[str, str], now: int,
                               max_age_seconds: int = 3600) -> dict[str, Any]:
    """Validate preflight observations against a trusted external matrix.

    This function intentionally accepts only the NOT_EVALUATED runtime state.
    A native or Compose runner must produce a separate, independently
    collected artifact before G0-COVERAGE can be reported as PASS.
    """
    matrix_result = validate_matrix(
        expected_matrix,
        expected_bindings=expected_bindings,
        expected_scope=expected_scope,
        trusted_matrix_sha256=trusted_matrix_sha256,
        now=now,
        max_age_seconds=max_age_seconds,
    )
    if not _sha(trusted_artifact_sha256):
        raise CoverageRejected('COVERAGE_REFERENCE_MISSING')
    if (not _sha(trusted_gateway_log_sha256)
            or not _sha(trusted_gateway_evidence_sha256)):
        raise CoverageRejected('COVERAGE_GATEWAY_REFERENCE_MISSING')
    if type(raw) is not bytes or not 0 < len(raw) <= 4 * 1024 * 1024:
        raise CoverageRejected('COVERAGE_ARTIFACT_MISSING_OR_OVERSIZE')
    if hashlib.sha256(raw).hexdigest() != trusted_artifact_sha256:
        raise CoverageRejected('COVERAGE_ARTIFACT_DIGEST_MISMATCH')
    doc = _strict_json(raw)
    if set(doc) != EVIDENCE_KEYS or doc['kind'] != EVIDENCE_KIND:
        raise CoverageRejected('COVERAGE_SCHEMA_INVALID')
    if doc['matrix_sha256'] != trusted_matrix_sha256:
        raise CoverageRejected('COVERAGE_MATRIX_MISMATCH')
    _validate_bindings(doc['bindings'], expected_bindings)
    _validate_scope(doc['scope'], expected_scope)
    _validate_time(doc['generated_at'], doc['expires_at'], now=now,
                   max_age_seconds=max_age_seconds)
    _validate_gateway_evidence(doc['gateway_evidence'])
    if gateway_evidence_sha256(doc['gateway_evidence']) != trusted_gateway_evidence_sha256:
        raise CoverageRejected('COVERAGE_GATEWAY_EVIDENCE_REFERENCE_MISMATCH')
    if doc['gateway_evidence']['log_artifact_sha256'] != trusted_gateway_log_sha256:
        raise CoverageRejected('COVERAGE_GATEWAY_LOG_REFERENCE_MISMATCH')
    if doc['runtime_status'] != RUNTIME_STATUS_NOT_EVALUATED:
        raise CoverageRejected('COVERAGE_RUNTIME_STATUS_INVALID')
    if doc['gates'] != {'G0-COVERAGE': RUNTIME_STATUS_NOT_EVALUATED}:
        raise CoverageRejected('COVERAGE_GATE_NOT_EVALUATED')
    rows = doc['rows']
    if type(rows) is not list or not rows:
        raise CoverageRejected('COVERAGE_ROWS_INVALID')
    unknown_rejected = _unknown_rejection_contract(expected_matrix['rows'])
    if doc['unknown_original_fields_rejected_before_normalization'] is not unknown_rejected:
        raise CoverageRejected('COVERAGE_UNKNOWN_INGRESS_UNPROTECTED')
    expected_rows = {(r['phase'], r['pointer']): r for r in expected_matrix['rows']}
    if len(rows) != len(expected_rows):
        raise CoverageRejected('COVERAGE_ROW_SET_MISMATCH')
    seen = set()
    for row in rows:
        if type(row) is not dict:
            raise CoverageRejected('COVERAGE_ROW_SCHEMA_INVALID')
        if (not isinstance(row.get('phase'), str)
                or not isinstance(row.get('pointer'), str)):
            raise CoverageRejected('COVERAGE_ROW_ID_INVALID')
        identity = (row.get('phase'), row.get('pointer'))
        if identity in seen:
            raise CoverageRejected('COVERAGE_DUPLICATE_ROW')
        expected = expected_rows.get(identity)
        if expected is None:
            raise CoverageRejected('COVERAGE_UNEXPECTED_ROW')
        _validate_evidence_row(row, expected,
                               doc['gateway_evidence']['log_artifact_sha256'],
                               doc['gateway_evidence']['observation_artifact_sha256'])
        seen.add(identity)
    if seen != set(expected_rows):
        raise CoverageRejected('COVERAGE_ROW_SET_MISMATCH')
    return {
        'status': 'COVERAGE_PREFLIGHT_VALIDATED',
        'runtime_status': RUNTIME_STATUS_NOT_EVALUATED,
        'artifact_sha256': trusted_artifact_sha256,
        'matrix_sha256': matrix_result['matrix_sha256'],
        'row_count': len(rows),
    }


def validate_coverage_route(route: dict[str, Any], *, deployment_config: dict[str, Any],
                            coverage_raw: bytes,
                            coverage_artifact_sha256: str,
                            expected_matrix: dict[str, Any],
                            trusted_matrix_sha256: str,
                            trusted_gateway_log_sha256: str,
                            trusted_gateway_evidence_sha256: str,
                            expected_bindings: dict[str, str],
                            expected_scope: dict[str, str], now: int,
                            max_age_seconds: int = 3600) -> dict[str, Any]:
    """Run context and coverage preflight without activating a route."""
    from agentguard.context import validate_route

    actual_route = _deployed_route(deployment_config)
    try:
        route_matches = canonical_bytes(route) == canonical_bytes(actual_route)
    except CoverageRejected as exc:
        raise CoverageRejected('COVERAGE_ROUTE_SELECTION_MISMATCH') from exc
    if not route_matches:
        raise CoverageRejected('COVERAGE_ROUTE_SELECTION_MISMATCH')
    _validate_bindings(expected_bindings, expected_bindings)
    if expected_bindings.get('gateway_config') != deployment_config_sha256(deployment_config):
        raise CoverageRejected('COVERAGE_DEPLOYMENT_BINDING_MISMATCH')
    try:
        validate_route(actual_route)
    except ValueError as exc:
        raise CoverageRejected('COVERAGE_ROUTE_UNVERIFIED') from exc
    actual_route_sha256 = route_sha256(actual_route)
    if (type(expected_scope) is not dict
            or expected_scope.get('route_sha256') != actual_route_sha256):
        raise CoverageRejected('COVERAGE_ROUTE_SCOPE_MISMATCH')
    coverage = validate_coverage_evidence(
        coverage_raw,
        expected_matrix=expected_matrix,
        trusted_matrix_sha256=trusted_matrix_sha256,
        trusted_artifact_sha256=coverage_artifact_sha256,
        trusted_gateway_log_sha256=trusted_gateway_log_sha256,
        trusted_gateway_evidence_sha256=trusted_gateway_evidence_sha256,
        expected_bindings=expected_bindings,
        expected_scope=expected_scope,
        now=now,
        max_age_seconds=max_age_seconds,
    )
    return {
        'status': 'COVERAGE_ROUTE_PREFLIGHTED',
        'runtime_status': RUNTIME_STATUS_NOT_EVALUATED,
        'coverage': coverage,
    }
