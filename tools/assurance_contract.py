#!/usr/bin/env python3
"""Review helpers, NOT a deployed guard or evidence of Gateway E2E protection.

The strict wire probe supports allow/reject only. Masking is intentionally
unsupported until the pinned provider-specific schema is verified.
Statistics assume independent, pre-registered binary origin-group outcomes.
"""
from __future__ import annotations

import argparse
import json
import math
from statistics import NormalDist
from typing import Any


def wilson_interval(events: int, trials: int, confidence: float = 0.95) -> tuple[float, float]:
    if type(events) is not int or type(trials) is not int:
        raise ValueError("counts must be integers, not booleans")
    if trials <= 0 or not 0 <= events <= trials:
        raise ValueError("require 0 <= events <= trials and trials > 0")
    if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 < confidence < 1:
        raise ValueError("confidence must be finite and between zero and one")
    # Lower-tail inversion avoids rounding (1 + confidence) / 2 to 1.
    # Reject confidences whose lower tail itself cannot be represented.
    tail = (1.0 - confidence) / 2.0
    if not 0.0 < tail < 0.5:
        raise ValueError("confidence is outside the representable quantile range")
    z = -NormalDist().inv_cdf(tail)
    p = events / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    # Exact endpoints prevent roundoff from making recall=1 pass at finite n.
    lower = 0.0 if events == 0 else max(0.0, center - radius)
    upper = 1.0 if events == trials else min(1.0, center + radius)
    return lower, upper


def rate_gate(events: int, trials: int, *, metric: str, threshold: float,
              confidence: float = 0.95) -> dict[str, Any]:
    if metric not in {"fpr", "recall"}:
        raise ValueError("metric must be fpr or recall")
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("threshold must be finite and between zero and one")
    lower, upper = wilson_interval(events, trials, confidence)
    passed = upper <= threshold if metric == "fpr" else lower >= threshold
    return {"metric": metric, "events": events, "trials": trials,
            "estimate": events / trials, "lower": lower, "upper": upper,
            "confidence": confidence, "method": "wilson_two_sided",
            "status": "PASS" if passed else "FAIL", "scope": "single_rate_only"}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"non-JSON constant: {value}")


def validate_nonmask_action(raw: str) -> str:
    """Validate a deliberately restricted canonical subset, not upstream Serde."""
    obj = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(obj, dict) or set(obj) != {"action"}:
        raise ValueError("require exactly one action field")
    action = obj["action"]
    if not isinstance(action, dict):
        raise ValueError("action must be an object")
    reason = action.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("explicit nonempty reason required")
    keys = set(action)
    if keys == {"reason"}:
        return "allow"
    if keys == {"reason", "status_code", "body"}:
        if type(action["status_code"]) is not int or not 400 <= action["status_code"] <= 599:
            raise ValueError("reject status_code must be integer 400..599")
        if not isinstance(action["body"], str):
            raise ValueError("reject body must be a string")
        return "deny"
    raise ValueError("noncanonical or unsupported action; masking is not implemented")


def serialize_nonmask_decision(effect: str, reason: str, *, body: str = "Request blocked",
                               status_code: int = 403) -> str:
    if effect == "allow":
        action = {"reason": reason}
    elif effect == "deny":
        action = {"reason": reason, "status_code": status_code, "body": body}
    else:
        raise ValueError("only allow/deny are implemented")
    raw = json.dumps({"action": action}, ensure_ascii=False, allow_nan=False)
    observed = validate_nonmask_action(raw)
    if observed != effect or json.loads(raw)["action"] != action:
        raise ValueError("round-trip changed decision semantics")
    return raw


def attack_accounting(*, successes: int, policy_blocks: int, normal_failures: int,
                      availability_only: int, unknown: int,
                      availability_faults: int | None = None) -> dict[str, Any]:
    counts = (successes, policy_blocks, normal_failures, availability_only, unknown)
    if any(type(c) is not int or c < 0 for c in counts):
        raise ValueError("counts must be nonnegative integers")
    valid = sum(counts)
    if availability_faults is not None:
        if type(availability_faults) is not int or not availability_only <= availability_faults <= valid:
            raise ValueError("require availability_only <= availability_faults <= valid")
    resolved = successes + policy_blocks + normal_failures
    return {"valid": valid, "resolved": resolved,
            "observed_end_to_end_success": successes / valid if valid else None,
            "resolved_asr": successes / resolved if resolved else None,
            "availability_only_fraction": availability_only / valid if valid else None,
            "unknown_fraction": unknown / valid if valid else None,
            "availability_faults": availability_faults,
            "availability_fault_fraction": availability_faults / valid if availability_faults is not None and valid else None,
            "availability_evidence": "COMPLETE" if availability_faults is not None else "MISSING",
            "unresolved_bounds": [successes / valid, (successes + availability_only + unknown) / valid] if valid else None,
            "status": "NOT_ESTIMABLE" if not resolved else "DESCRIPTIVE_ONLY"}



def summarize_trials(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """Account pre-labelled outcomes; caller supplies the external success oracle.

    The availability flag is mandatory even for S (successful attack) outcomes.
    This helper does not infer policy efficacy from HTTP codes or timeouts.
    """
    counts = dict.fromkeys(("S", "B", "N", "I", "U"), 0)
    faults = 0
    seen: set[str] = set()
    for trial in trials:
        if not isinstance(trial, dict) or set(trial) != {"id", "outcome", "availability_fault"}:
            raise ValueError("require id, outcome, availability_fault")
        trial_id = trial["id"]
        if not isinstance(trial_id, str) or not trial_id or trial_id in seen:
            raise ValueError("trial IDs must be nonempty and unique")
        seen.add(trial_id)
        outcome = trial["outcome"]
        if not isinstance(outcome, str) or outcome not in counts:
            raise ValueError("invalid outcome")
        fault = trial["availability_fault"]
        if type(fault) is not bool or (outcome == "I" and not fault):
            raise ValueError("require explicit fault boolean; I always has a fault")
        counts[outcome] += 1
        faults += int(fault)
    return attack_accounting(successes=counts["S"], policy_blocks=counts["B"],
                             normal_failures=counts["N"], availability_only=counts["I"],
                             unknown=counts["U"], availability_faults=faults)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stats", action="store_true", help="print single-rate examples, not release results")
    args = parser.parse_args()
    if not args.stats:
        parser.error("choose --stats")
    rows = [rate_gate(k, n, metric="fpr", threshold=.02) for k, n in [(10, 500), (9, 500), (5, 500), (8, 800)]]
    rows.append(rate_gate(485, 500, metric="recall", threshold=.95))
    print(json.dumps({"kind": "CALCULATED_EXAMPLES_NOT_BENCHMARKS", "rows": rows}, indent=2))


if __name__ == "__main__":
    main()
