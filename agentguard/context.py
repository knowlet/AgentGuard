"""P0 trusted-header contract, not authentication or a complete policy compiler.

Only call decide() behind a Gateway whose reserved-header expressions passed
validate_config(). Never expose this adapter directly to an untrusted client.
"""
from __future__ import annotations

HEADER_EXPRESSIONS = {
    'x-ag-original-path': 'request.path',
    'x-ag-original-media-type': 'request.headers["content-type"]',
    'x-ag-effective-stream': 'has(llmRequest.stream) ? string(llmRequest.stream) : "false"',
    'x-ag-requested-model': 'llmRequest.model',
}


def validate_config(headers: dict) -> None:
    if type(headers) is not dict or set(headers) != set(HEADER_EXPRESSIONS) or any(headers[k] != v for k, v in HEADER_EXPRESSIONS.items()):
        raise ValueError('CONTEXT_MAPPING_UNVERIFIED: route must not activate')


def decide(headers) -> tuple[bool, str, dict]:
    context = {}
    for key in HEADER_EXPRESSIONS:
        values = headers.get_all(key, [])
        if len(values) != 1 or not values[0] or len(values[0]) > 512:
            return False, 'CONTEXT_UNAVAILABLE', {}
        context[key] = values[0]
    if context['x-ag-original-path'] != '/v1/chat/completions':
        return False, 'ENDPOINT_DENIED', context
    if context['x-ag-original-media-type'].split(';', 1)[0].strip().lower() != 'application/json':
        return False, 'MEDIA_TYPE_DENIED', context
    if context['x-ag-effective-stream'] not in ('true', 'false'):
        return False, 'CONTEXT_UNAVAILABLE', context
    if context['x-ag-effective-stream'] == 'true':
        return False, 'STREAMING_DENIED', context
    if context['x-ag-requested-model'] != 'fixture':
        return False, 'MODEL_DENIED', context
    return True, 'CONTEXT_ALLOW', context


def validate_route(route: dict) -> None:
    """A closed, narrow profile: transformations/model overrides invalidate original context."""
    try:
        if set(route) != {'backends', 'policies'} or len(route['backends']) != 1:
            raise ValueError('unsupported route shape')
        backend = route['backends'][0]
        ai = backend['ai']
        if set(backend) != {'ai'} or set(ai) != {'name', 'hostOverride', 'provider'}:
            raise ValueError('unsupported backend shape')
        if ai['provider'] != {'openAI': {}}:
            raise ValueError('provider overrides destroy original requested_model')
        policies = route['policies']
        if set(policies) != {'ai'} or set(policies['ai']) != {'promptGuard'}:
            raise ValueError('unverified transformations')
        guards = policies['ai']['promptGuard']
        if set(guards) != {'request', 'response'}:
            raise ValueError('missing phase')
        for phase in ('request', 'response'):
            if len(guards[phase]) != 1 or set(guards[phase][0]) != {'webhook'}:
                raise ValueError('unverified guard chain')
            hook = guards[phase][0]['webhook']
            if set(hook) != {'target', 'headers', 'failureMode'} or hook['failureMode'] != 'failClosed':
                raise ValueError('unverified hook shape')
            validate_config(hook['headers'])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ValueError('CONTEXT_ROUTE_UNVERIFIED: route must not activate') from exc
