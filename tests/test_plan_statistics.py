import json
import math
import subprocess
import sys
import unittest
from pathlib import Path

from tools.assurance_contract import rate_gate
from tools.plan_statistics import acceptable_errors, binomial_cdf, fixed_n_power, plan

ROOT = Path(__file__).resolve().parents[1]


class StatisticalPlanning(unittest.TestCase):
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
