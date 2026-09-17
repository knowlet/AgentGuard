#!/usr/bin/env python3
"""Fixed-n planning for ONE Wilson rate gate, not a product release evaluator.

Run from the repository root: python -m tools.plan_statistics --help
Independent binary origin-group outcomes are assumed. Freeze assumptions,
confidence, candidate n grid, estimand and stopping rule BEFORE collecting data.
The binomial power calculation is numerical, not a coverage guarantee for Wilson.
"""
from __future__ import annotations

import argparse
import json
import math
from typing import Any

from tools.assurance_contract import rate_gate


def _integer(value: int, name: str, minimum: int = 0) -> None:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


def _probability(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite probability")
    if not math.isfinite(value) or not 0 < value < 1:
        raise ValueError(f"{name} must lie strictly between 0 and 1")


def binomial_cdf(k: int, n: int, p: float) -> float:
    """Finite binomial sum using log probabilities; no scipy runtime dependency."""
    _integer(n, "n", 1)
    if type(k) is not int or not -1 <= k <= n:
        raise ValueError("k must be an integer in -1..n")
    _probability(p, "p")
    if k == -1:
        return 0.0
    if k == n:
        return 1.0
    # Sum the smaller number of terms; bound roundoff at the probability limits.
    if k > n // 2:
        return max(0.0, min(1.0, 1.0 - binomial_cdf(n - k - 1, n, 1.0 - p)))
    log_p, log_q = math.log(p), math.log1p(-p)
    log_factorial = math.lgamma(n + 1)
    total = math.fsum(math.exp(log_factorial - math.lgamma(j + 1)
                             - math.lgamma(n - j + 1)
                             + j * log_p + (n - j) * log_q)
                      for j in range(k + 1))
    return min(1.0, max(0.0, total))


def acceptable_errors(n: int, *, metric: str, threshold: float,
                      confidence: float = .95) -> int:
    """Largest false-positive/miss count whose CI passes; -1 means none."""
    _integer(n, "n", 1)
    if metric not in {"fpr", "recall"}:
        raise ValueError("metric must be fpr or recall")
    _probability(threshold, "threshold")
    _probability(confidence, "confidence")
    # Acceptance is monotone in error count, not necessarily in n (discreteness).
    lo, hi = -1, n + 1
    while hi - lo > 1:
        errors = (lo + hi) // 2
        events = errors if metric == "fpr" else n - errors
        result = rate_gate(events, n, metric=metric, threshold=threshold,
                           confidence=confidence)
        if result["status"] == "PASS":
            lo = errors
        else:
            hi = errors
    return lo


def fixed_n_power(n: int, *, metric: str, threshold: float, expected_rate: float,
                  confidence: float = .95) -> dict[str, Any]:
    _probability(expected_rate, "expected_rate")
    max_errors = acceptable_errors(n, metric=metric, threshold=threshold,
                                   confidence=confidence)
    error_probability = expected_rate if metric == "fpr" else 1 - expected_rate
    return {"n": n, "max_acceptable_errors": max_errors,
            "passing_probability": binomial_cdf(max_errors, n, error_probability)}


def plan(*, metric: str, threshold: float, expected_rate: float, target_power: float,
         confidence: float = .95, min_groups: int = 100, max_groups: int = 5000,
         step: int = 100) -> dict[str, Any]:
    _probability(target_power, "target_power")
    for name, value in (("min_groups", min_groups), ("max_groups", max_groups), ("step", step)):
        _integer(value, name, 1)
    if max_groups < min_groups or max_groups > 100000:
        raise ValueError("require min_groups <= max_groups <= 100000")
    rows = []
    selected = None
    for n in range(min_groups, max_groups + 1, step):
        row = fixed_n_power(n, metric=metric, threshold=threshold,
                            expected_rate=expected_rate, confidence=confidence)
        rows.append(row)
        if row["passing_probability"] >= target_power:
            selected = n
            break
    return {"kind": "FIXED_N_PLANNING_NOT_BENCHMARK", "scope": "single_rate_only",
            "method": "wilson_two_sided", "confidence": confidence,
            "metric": metric, "threshold": threshold, "expected_rate": expected_rate,
            "target_power": target_power,
            "registered_grid": {"min": min_groups, "max": max_groups, "step": step},
            "planned_n": selected, "status": "FOUND" if selected is not None else "NOT_FOUND",
            "candidate_rows": rows,
            "limitations": ["Independent preregistered binary origin groups required",
                            "No optional stopping or observed-data sample-size adaptation",
                            "No multiplicity or joint-release-power calculation",
                            "No runtime, availability, coverage or utility evidence"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metric", required=True, choices=("fpr", "recall"))
    parser.add_argument("--threshold", required=True, type=float)
    parser.add_argument("--expected-rate", required=True, type=float)
    parser.add_argument("--power", required=True, type=float)
    parser.add_argument("--confidence", type=float, default=.95)
    parser.add_argument("--min-groups", type=int, default=100)
    parser.add_argument("--max-groups", type=int, default=5000)
    parser.add_argument("--step", type=int, default=100)
    args = parser.parse_args()
    try:
        result = plan(metric=args.metric, threshold=args.threshold, expected_rate=args.expected_rate,
                      target_power=args.power, confidence=args.confidence,
                      min_groups=args.min_groups, max_groups=args.max_groups, step=args.step)
    except (ValueError, ArithmeticError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0 if result["status"] == "FOUND" else 1


if __name__ == "__main__":
    raise SystemExit(main())
