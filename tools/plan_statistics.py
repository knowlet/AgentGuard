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


def _probability(value: float, name: str, *, inclusive: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite probability")
    valid_range = 0 <= value <= 1 if inclusive else 0 < value < 1
    if not math.isfinite(value) or not valid_range:
        raise ValueError(f"{name} is outside its probability range")


_BETA_ITERATIONS = 4096
_BETA_TOLERANCE = 1e-14
_BETA_DENOMINATOR_FLOOR = 1e-300


def _beta_continued_fraction(a: float, b: float, x: float) -> float:
    """Incomplete-beta fraction by modified Lentz, not one step per term."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    # First denominator 1 + d1, with d1 = -(a+b)x/(a+1).
    d = 1.0 - qab * x / qap
    if abs(d) < _BETA_DENOMINATOR_FLOOR:
        d = _BETA_DENOMINATOR_FLOOR
    d = 1.0 / d
    h = d
    for m in range(1, _BETA_ITERATIONS + 1):
        twice = 2 * m
        numerators = (
            m * (b - m) * x / ((qam + twice) * (a + twice)),
            -(a + m) * (qab + m) * x / ((a + twice) * (qap + twice)),
        )
        for numerator in numerators:
            d = 1.0 + numerator * d
            if abs(d) < _BETA_DENOMINATOR_FLOOR:
                d = _BETA_DENOMINATOR_FLOOR
            c = 1.0 + numerator / c
            if abs(c) < _BETA_DENOMINATOR_FLOOR:
                c = _BETA_DENOMINATOR_FLOOR
            d = 1.0 / d
            delta = c * d
            h *= delta
        if abs(delta - 1.0) < _BETA_TOLERANCE:
            return h
    raise ArithmeticError("binomial CDF continued fraction did not converge")


def _regularized_incomplete_beta(a: float, b: float, x: float, log_x: float,
                                 log_one_minus_x: float) -> float:
    """I_x(a, b) = x^a (1-x)^b / (a B(a, b)) times its continued fraction."""
    fraction = _beta_continued_fraction(a, b, x)
    log_beta = math.fsum((math.lgamma(a), math.lgamma(b), -math.lgamma(a + b)))
    prefactor = math.exp(math.fsum((a * log_x, b * log_one_minus_x, -log_beta)))
    return prefactor * fraction / a


def binomial_cdf(k: int, n: int, p: float) -> float:
    """Closed-form binomial CDF. No scipy runtime dependency.

    P(X <= k) = I_{1-p}(n-k, k+1). The fraction is taken on the side below
    its mean, so a tiny lower tail is computed directly instead of as
    1 minus a near-one upper tail.
    """
    _integer(n, "n", 1)
    if type(k) is not int or not -1 <= k <= n:
        raise ValueError("k must be an integer in -1..n")
    _probability(p, "p")
    if k == -1:
        return 0.0
    if k == n:
        return 1.0
    log_p, log_q = math.log(p), math.log1p(-p)
    if (1.0 - p) < (n - k + 1) / (n + 2.0):
        probability = _regularized_incomplete_beta(n - k, k + 1, 1.0 - p, log_q, log_p)
    else:
        probability = 1.0 - _regularized_incomplete_beta(k + 1, n - k, p, log_p, log_q)
    return min(1.0, max(0.0, probability))


def acceptable_errors(n: int, *, metric: str, threshold: float,
                      confidence: float = .95) -> int:
    """Largest false-positive/miss count whose CI passes; -1 means none."""
    _integer(n, "n", 1)
    if metric not in {"fpr", "recall"}:
        raise ValueError("metric must be fpr or recall")
    _probability(threshold, "threshold", inclusive=True)
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
    if metric == "fpr":
        power = binomial_cdf(max_errors, n, expected_rate)
    elif 1.0 - expected_rate < 1.0:
        power = binomial_cdf(max_errors, n, 1.0 - expected_rate)
    else:
        # Avoid passing a rounded endpoint probability into binomial_cdf.
        boundary = n - max_errors - 1
        power = 1.0 - binomial_cdf(boundary, n, expected_rate) if boundary < n else 0.0
    return {"n": n, "max_acceptable_errors": max_errors,
            "passing_probability": power}


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
