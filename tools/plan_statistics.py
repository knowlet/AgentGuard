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
from fractions import Fraction
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


def _beta_iteration_limit(a: float, b: float) -> int:
    """Near the mean the fraction needs on the order of sqrt(a + b) steps."""
    return max(_BETA_ITERATIONS, math.ceil(16 * math.sqrt(a + b)))


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
    for m in range(1, _beta_iteration_limit(a, b) + 1):
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


_HALF_LOG_TWO_PI = 0.5 * math.log(2.0 * math.pi)


def _stirling_remainder(x: float) -> float:
    """lgamma(x) - ((x - 1/2) log x - x + log(2 pi)/2), for x >= 10."""
    inverse = 1.0 / x
    inverse_squared = inverse * inverse
    return inverse * (1.0 / 12 - inverse_squared * (
        1.0 / 360 - inverse_squared * (1.0 / 1260 - inverse_squared / 1680)))


def _log_beta(a: float, b: float) -> float:
    """log B(a, b) without subtracting two huge lgamma values.

    lgamma(a) - lgamma(a + b) loses every significant digit when a is huge and
    b is small (lgamma(1e16) is about 3.6e17, so its rounding error alone is
    tens of units). Write that difference through Stirling's series instead.
    """
    small, large = min(a, b), max(a, b)
    if large < 10:
        return math.fsum((math.lgamma(a), math.lgamma(b), -math.lgamma(a + b)))
    total = large + small
    large_minus_total = math.fsum((
        -small * math.log(total),
        -(large - 0.5) * math.log1p(small / large),
        small,
        _stirling_remainder(large),
        -_stirling_remainder(total),
    ))
    return math.lgamma(small) + large_minus_total


def _log_beta_prefactor(a: float, b: float, log_x: float, log_one_minus_x: float,
                        excess: float) -> float:
    """log(x^a (1-x)^b / B(a, b)), with excess = x (a + b) - a.

    For large a and b, a log x, b log(1-x) and log B(a, b) are each of order
    a + b, so adding them leaves an absolute error of order (a + b) * 2**-52
    in the exponent. Expanding around the mean x0 = a / (a + b) instead keeps
    every term small: a log(x/x0) + b log((1-x)/(1-x0)) plus Stirling's
    closed form for x0^a (1-x0)^b / B(a, b).
    """
    if min(a, b) < 10:
        return math.fsum((a * log_x, b * log_one_minus_x, -_log_beta(a, b)))
    total = a + b
    if abs(excess) <= 0.5 * min(a, b):
        # Near the mean x/x0 = 1 + excess/a and (1-x)/(1-x0) = 1 - excess/b.
        log_ratios = (a * math.log1p(excess / a), b * math.log1p(-excess / b))
    else:
        # Far tail: the ratios are not near 1 and the exponent is large anyway.
        log_total = math.log(total)
        log_ratios = (a * (log_x - math.log(a) + log_total),
                      b * (log_one_minus_x - math.log(b) + log_total))
    return math.fsum((
        *log_ratios,
        0.5 * (math.log(a) + math.log(b) - math.log(total)),
        -_HALF_LOG_TWO_PI,
        -_stirling_remainder(a),
        -_stirling_remainder(b),
        _stirling_remainder(total),
    ))


def _regularized_incomplete_beta(a: float, b: float, x: float, log_x: float,
                                 log_one_minus_x: float, excess: float) -> float:
    """I_x(a, b) = x^a (1-x)^b / (a B(a, b)) times its continued fraction."""
    fraction = _beta_continued_fraction(a, b, x)
    prefactor = math.exp(_log_beta_prefactor(a, b, log_x, log_one_minus_x, excess))
    return prefactor * fraction / a


def binomial_cdf(k: int, n: int, p: float) -> float:
    """Closed-form binomial CDF. No scipy runtime dependency.

    P(X <= k) = I_{1-p}(n-k, k+1). The fraction is evaluated directly when
    1-p < (n-k+1)/(n+2), the point where its continued fraction converges
    fastest, and otherwise as 1 - I_p(k+1, n-k); a tiny lower tail is
    therefore computed directly instead of as 1 minus a near-one upper tail.
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
    if k == 0:
        # P(X = 0) = (1 - p)^n exactly; 1 - p itself would round for tiny p.
        return math.exp(n * log_q)
    if (1.0 - p) < (n - k + 1) / (n + 2.0):
        # excess = (1-p)(n+1) - (n-k) = (k+1) - p(n+1), exact then rounded once.
        excess = float((k + 1) - Fraction(p) * (n + 1))
        probability = _regularized_incomplete_beta(n - k, k + 1, 1.0 - p, log_q, log_p,
                                                   excess)
    else:
        excess = float(Fraction(p) * (n + 1) - (k + 1))
        probability = 1.0 - _regularized_incomplete_beta(k + 1, n - k, p, log_p, log_q,
                                                         excess)
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
