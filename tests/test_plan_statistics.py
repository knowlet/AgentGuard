import json
import math
from decimal import Decimal, localcontext
import subprocess
import sys
import unittest
from pathlib import Path

from tools.assurance_contract import rate_gate
from tools.plan_statistics import acceptable_errors, binomial_cdf, fixed_n_power, plan

ROOT = Path(__file__).resolve().parents[1]


def _direct_binomial_sum(k: int, n: int, p: float) -> float:
    """Term-by-term log-space sum, the reference the closed form must match."""
    log_p, log_q = math.log(p), math.log1p(-p)
    log_n = math.lgamma(n + 1)
    total = math.fsum(math.exp(log_n - math.lgamma(j + 1) - math.lgamma(n - j + 1)
                               + j * log_p + (n - j) * log_q)
                      for j in range(k + 1))
    return min(1.0, max(0.0, total))


def _decimal_binomial_cdf(k: int, n: int, p: float) -> float:
    """Exact-enough reference: every term in 60-digit decimal arithmetic."""
    with localcontext() as context:
        context.prec = 60
        probability = Decimal.from_float(p)
        complement = 1 - probability
        term = complement ** n
        total = term
        for j in range(k):
            term = term * (n - j) / (j + 1) * probability / complement
            total += term
        return float(total)


class StatisticalPlanning(unittest.TestCase):
    def test_small_lower_tails_do_not_lose_precision_to_complement(self):
        for n, k, p in ((100, 60, .99), (100, 90, .999),
                        (30, 20, .99), (100, 70, .9),
                        (100, 59, .6), (100, 60, .6), (100, 61, .6)):
            with self.subTest(n=n, k=k, p=p), localcontext() as context:
                context.prec = 100
                probability = Decimal.from_float(p)
                expected = float(sum(
                    Decimal(math.comb(n, j)) * probability**j
                    * (1 - probability)**(n - j)
                    for j in range(k + 1)
                ))
                actual = binomial_cdf(k, n, p)
                self.assertGreater(actual, 0)
                self.assertTrue(math.isclose(actual, expected, rel_tol=1e-11,
                                             abs_tol=0), (actual, expected))

    def test_unbalanced_huge_parameters_keep_the_beta_normalization(self):
        # P(X = 0) = (1 - p)^n; with n p = 1 that is e^-1, not ~1.
        self.assertTrue(math.isclose(binomial_cdf(0, 10**16, 1e-16), math.exp(-1),
                                     rel_tol=1e-9))
        for k in (1, 2, 5):
            with self.subTest(k=k):
                # Poisson(1) limit of Binomial(10**16, 1e-16), exact to ~1e-15.
                expected = math.exp(-1) * math.fsum(1 / math.factorial(j)
                                                    for j in range(k + 1))
                self.assertTrue(math.isclose(binomial_cdf(k, 10**16, 1e-16), expected,
                                             rel_tol=1e-6), k)

    def test_huge_near_mean_input_converges_to_the_symmetric_identity(self):
        n = 100_000_000_000
        # P(X <= n/2) = 1/2 + P(X = n/2)/2 for p = 1/2; Stirling with its 1/(4n)
        # correction gives P(X = n/2) to far better than the tolerance here.
        center = math.sqrt(2 / (math.pi * n)) * (1 - 1 / (4 * n))
        actual = binomial_cdf(n // 2, n, 0.5)
        self.assertTrue(math.isclose(actual, 0.5 + 0.5 * center, rel_tol=0.0,
                                     abs_tol=1e-10), actual)

    def test_large_near_mean_inputs_match_decimal_reference(self):
        for k, n, p in ((5_000, 10_000, 0.5), (49_900, 100_000, 0.5),
                        (29_950, 100_000, 0.3), (70_100, 100_000, 0.7)):
            with self.subTest(k=k, n=n, p=p):
                expected = _decimal_binomial_cdf(k, n, p)
                self.assertTrue(math.isclose(binomial_cdf(k, n, p), expected,
                                             rel_tol=1e-11), expected)

    def test_plan_does_not_accept_roundoff_as_passing_probability(self):
        result = plan(metric="fpr", threshold=.8, expected_rate=.99,
                      target_power=1e-15, min_groups=100, max_groups=100)
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertIsNone(result["planned_n"])
        self.assertLess(result["candidate_rows"][0]["passing_probability"], 1e-15)

    def test_closed_form_matches_direct_sum_on_small_inputs(self):
        cases = [(n, k, p)
                 for n in (1, 3, 10, 30)
                 for k in range(n)
                 for p in (.01, .2, .5, .9, .99)]
        cases.extend(((100, 60, .99), (100, 90, .999), (30, 20, .99),
                      (100, 70, .9), (100, 59, .6), (100, 60, .6), (100, 61, .6)))
        for n, k, p in cases:
            with self.subTest(n=n, k=k, p=p):
                reference = _direct_binomial_sum(k, n, p)
                actual = binomial_cdf(k, n, p)
                self.assertTrue(math.isclose(actual, reference, rel_tol=1e-12, abs_tol=0.0),
                                (actual, reference))

    def test_large_grid_closed_form_evaluates_far_fewer_terms_than_direct_sum(self):
        # Twenty below-mean cutoffs with k > n/2. The direct sum calls lgamma
        # twice per term; the closed form uses a handful per candidate.
        # Counting calls stays deterministic across machines.
        cases = []
        for index in range(20):
            n = 2000 + 2000 * index
            p = .999
            k = min(n - 1, math.floor(n * p) - 1)
            self.assertGreater(k, n // 2)
            self.assertLess(k, n * p)
            cases.append((k, n, p))
        actual = binomial_cdf(*cases[0])
        # The lgamma-based direct sum is itself off by ~1e-12 at this size.
        reference = _decimal_binomial_cdf(*cases[0])
        self.assertTrue(math.isclose(actual, reference, rel_tol=1e-12, abs_tol=0.0),
                        (actual, reference))
        calls = 0
        original = math.lgamma

        def counted(value: float) -> float:
            nonlocal calls
            calls += 1
            return original(value)

        math.lgamma = counted
        try:
            for k, n, p in cases:
                probability = binomial_cdf(k, n, p)
                self.assertTrue(math.isfinite(probability))
                self.assertGreaterEqual(probability, 0.0)
                self.assertLessEqual(probability, 1.0)
        finally:
            math.lgamma = original
        direct_terms = sum(k + 1 for k, _n, _p in cases)
        self.assertGreater(calls, 0)
        self.assertLess(calls, direct_terms // 20)

    def test_binomial_sum_against_small_exact_enumeration(self):
        for n in (1, 3, 10, 30):
            for k in range(-1, n + 1):
                for p in (.01, .2, .5, .9):
                    expected = sum(math.comb(n, j) * p**j * (1-p)**(n-j)
                                   for j in range(k+1))
                    self.assertAlmostEqual(binomial_cdf(k, n, p), expected, places=12)

    def test_acceptance_boundary(self):
        for metric, threshold in (("fpr", .02), ("recall", .95)):
            for n in (10, 100, 500, 800, 1000):
                k = acceptable_errors(n, metric=metric, threshold=threshold)
                if k >= 0:
                    events = k if metric == "fpr" else n-k
                    self.assertEqual(rate_gate(events, n, metric=metric, threshold=threshold)["status"], "PASS")
                if k < n:
                    events = k+1 if metric == "fpr" else n-k-1
                    self.assertEqual(rate_gate(events, n, metric=metric, threshold=threshold)["status"], "FAIL")

    def test_power_is_not_point_estimate_acceptance(self):
        row = fixed_n_power(800, metric="fpr", threshold=.02, expected_rate=.01)
        self.assertEqual(row["max_acceptable_errors"], 8)
        self.assertAlmostEqual(row["passing_probability"], .5925485164009194, places=10)
        self.assertLess(row["passing_probability"], .8)

    def test_fpr_registered_grid_plan(self):
        for power, n in ((.8, 1300), (.9, 1600)):
            result = plan(metric="fpr", threshold=.02, expected_rate=.01, target_power=power)
            self.assertEqual(result["planned_n"], n)
            self.assertTrue(all(r["passing_probability"] < power for r in result["candidate_rows"][:-1]))
            self.assertGreaterEqual(result["candidate_rows"][-1]["passing_probability"], power)

    def test_power_need_not_be_monotone_in_sample_size(self):
        p1600 = fixed_n_power(1600, metric="fpr", threshold=.02, expected_rate=.01)["passing_probability"]
        p1700 = fixed_n_power(1700, metric="fpr", threshold=.02, expected_rate=.01)["passing_probability"]
        self.assertGreater(p1600, p1700)

    def test_recall_counts_misses(self):
        row = fixed_n_power(500, metric="recall", threshold=.95, expected_rate=.97)
        self.assertEqual(row["max_acceptable_errors"], 15)
        self.assertAlmostEqual(row["passing_probability"], .5680974954490838, places=10)

    def test_insufficient_budget_is_not_found(self):
        result = plan(metric="fpr", threshold=.02, expected_rate=.01,
                      target_power=.8, max_groups=500)
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertIsNone(result["planned_n"])

    def test_stricter_confidence_does_not_increase_error_budget(self):
        normal = acceptable_errors(800, metric="fpr", threshold=.02, confidence=.95)
        stricter = acceptable_errors(800, metric="fpr", threshold=.02, confidence=.99)
        self.assertLessEqual(stricter, normal)

    def test_invalid_inputs(self):
        base = dict(metric="fpr", threshold=.02, expected_rate=.01, target_power=.8)
        for change in ({"metric":"asr"}, {"threshold":True}, {"expected_rate":float("nan")},
                       {"target_power":1}, {"step":0}, {"min_groups":True},
                       {"max_groups":99}, {"max_groups":100001}, {"confidence":0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan(**(base | change))
        for pair in ((-2, 10), (11, 10), (True, 10), (0, 0)):
            with self.assertRaises(ValueError):
                binomial_cdf(*pair, .1)

    def test_cli_nonzero_when_no_plan(self):
        command = [sys.executable, "-m", "tools.plan_statistics", "--metric", "fpr",
                   "--threshold", ".02", "--expected-rate", ".01", "--power", ".8"]
        ok = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["planned_n"], 1300)
        fail = subprocess.run(command + ["--max-groups", "500"], cwd=ROOT,
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(fail.returncode, 1)
        self.assertEqual(json.loads(fail.stdout)["status"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
