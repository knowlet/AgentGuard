"""Guard-deadline budget model. Not a latency SLO and not a policy decision.

v1.5.0 inserts a 10-second ``BackendRequestTimeout`` for webhook backends [S25],
so the guard's own budget plus a transport reserve plus a safety margin has to fit
inside that effective value. This module only covers the deterministic part:

* refuse a declaration whose stages, reserve or margin do not fit; and
* keep the runtime classification honest, so a Gateway-side timeout or a hang is
  an availability fault and never a guard decision, and a guard-side overrun is a
  fail-closed ``GUARD_DEADLINE_EXCEEDED`` result rather than a policy deny.

It does not measure detector latency, queue depth, backpressure or cancellation.
"""
from __future__ import annotations

GATEWAY_WEBHOOK_TIMEOUT_MS = 10000
MIN_SAFETY_MARGIN_MS = 1000
BUDGET_STAGES = ('queue', 'parse', 'detector', 'adjudication', 'serialization', 'audit')
DECLARED_BUDGET_MS = {'queue': 200, 'parse': 100, 'detector': 800,
                      'adjudication': 150, 'serialization': 100, 'audit': 150}
TRANSPORT_RESERVE_MS = 500
SAFETY_MARGIN_MS = 1000
GUARD_DEADLINE_EXCEEDED = 'GUARD_DEADLINE_EXCEEDED'


def guard_budget_ms(budget: dict) -> int:
    return sum(budget.values())


def validate_budget(budget: dict, transport_reserve_ms: int, safety_margin_ms: int,
                    timeout_ms: int = GATEWAY_WEBHOOK_TIMEOUT_MS) -> int:
    """Return the guard budget, or raise: budget + reserve + margin < timeout."""
    if type(budget) is not dict or set(budget) != set(BUDGET_STAGES):
        raise ValueError('DEADLINE_STAGES_UNVERIFIED')
    if any(type(value) is not int or value < 0 for value in budget.values()):
        raise ValueError('DEADLINE_STAGE_INVALID')
    if type(transport_reserve_ms) is not int or transport_reserve_ms <= 0:
        raise ValueError('DEADLINE_RESERVE_INVALID')
    if type(safety_margin_ms) is not int or safety_margin_ms < MIN_SAFETY_MARGIN_MS:
        raise ValueError('DEADLINE_MARGIN_TOO_SMALL')
    if type(timeout_ms) is not int or timeout_ms <= 0:
        raise ValueError('DEADLINE_TIMEOUT_INVALID')
    if guard_budget_ms(budget) + transport_reserve_ms + safety_margin_ms >= timeout_ms:
        raise ValueError('DEADLINE_BUDGET_EXCEEDED')
    return guard_budget_ms(budget)


DECLARED_GUARD_BUDGET_MS = validate_budget(DECLARED_BUDGET_MS, TRANSPORT_RESERVE_MS, SAFETY_MARGIN_MS)


def over_budget(stage_ms: int, budget_ms: int = DECLARED_GUARD_BUDGET_MS) -> bool:
    """An adapter compares its own consumed stage time against the guard budget.

    The comparison is strict: spending exactly the budget is still inside it.
    """
    if type(stage_ms) is not int or stage_ms < 0 or type(budget_ms) is not int or budget_ms < 0:
        raise ValueError('DEADLINE_STAGE_INVALID')
    return stage_ms > budget_ms
