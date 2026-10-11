#!/usr/bin/env python3
"""Tests for analyze.py on hand-written data with known answers.

Run: python3 loadtest/live/test_analyze.py
"""
import csv
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze  # noqa: E402

START = 1_000_000  # wall-clock second of the scenario start
HEADER = ["metric_name", "timestamp", "metric_value", "extra_tags"]


def k6_rows(step, n_ok, n_fail, latency_ms, phase="hold", cls="503"):
    """journey_* rows for one step, all at a second inside that step."""
    ts = START + step * 15 + 10
    rows = []
    for _ in range(n_ok):
        tags = f"journey=refresh&step={step}&phase={phase}"
        rows.append(["journey_ms", ts, latency_ms, tags])
        rows.append(["journey_ok", ts, 1, tags])
    for _ in range(n_fail):
        tags = f"journey=refresh&step={step}&phase={phase}"
        rows.append(["journey_ms", ts, latency_ms, tags])
        rows.append(["journey_ok", ts, 0, tags])
        rows.append(["journey_fail", ts, 1, f"{tags}&cls={cls}"])
    return rows


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        # Ramp: 10/s + 10/s per step, 3 steps of 5 s ramp + 10 s hold.
        rows = []
        rows += k6_rows(0, 100, 0, 5.0)  # healthy
        rows += k6_rows(1, 196, 4, 80.0)  # 2% errors, p99 80 ms
        rows += k6_rows(2, 100, 200, 900.0)  # collapse
        rows += k6_rows(1, 0, 50, 1.0, phase="ramp")  # ramp seconds: ignored
        rows.append(["dropped_iterations", START + 15 + 10, 3, ""])
        self.raw = os.path.join(self.dir, "raw.csv")
        with open(self.raw, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(HEADER)
            w.writerows(rows)
        self.summary = os.path.join(self.dir, "summary.json")
        with open(self.summary, "w") as f:
            json.dump({"started_at": START * 1000}, f)
        self.sampler = os.path.join(self.dir, "sampler.csv")
        with open(self.sampler, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                ["ts", "alive", "pid", "cpu_ticks", "clk_tck", "rss_kb", "threads", "fds",
                 "mem_available_kb", "disk_writes", "disk_write_sectors", "load1"]
            )
            # Step 0 hold: 150 ticks/s at 100 ticks/s = 150% CPU, 20 writes/s.
            for i, sec in enumerate(range(START + 5, START + 15)):
                w.writerow([sec, 1, 7, 150 * i, 100, 2048 + i, 9, 30, 4_000_000, 20 * i, 0, 1.0])
            # Step 2 hold: the process is gone.
            for sec in range(START + 35, START + 45):
                w.writerow([sec, 0, "", "", 100, "", "", "", 4_000_000, 0, 0, 1.0])

    def run_analyze(self, budget):
        args = analyze.argparse.Namespace(
            raw=self.raw, summary=self.summary, sampler=self.sampler, journey="refresh",
            start_rate=10, step_rate=10, steps=3, hold_s=10, ramp_s=5, budget_ms=budget,
            out=os.path.join(self.dir, "out.json"),
        )
        return analyze.analyze(args)

    def test_hold_rows_rates_and_errors(self):
        r = self.run_analyze(budget=100)
        s0, s1, s2 = r["steps"]
        self.assertEqual(s0["offered_rps"], 10)
        self.assertEqual(s0["ok_rps"], 10.0)
        self.assertEqual(s0["error_ratio"], 0.0)
        # The 50 failures tagged "ramp" in step 1 are not counted.
        self.assertEqual(s1["completed_rps"], 20.0)
        self.assertEqual(s1["error_ratio"], 0.02)
        self.assertEqual(s1["fail_classes"], {"503": 4})
        self.assertEqual(s1["dropped"], 3)
        self.assertAlmostEqual(s2["error_ratio"], 200 / 300, places=4)

    def test_percentiles_are_nearest_rank(self):
        self.assertEqual(analyze.percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(analyze.percentile([1, 2, 3, 4], 99), 4)
        self.assertIsNone(analyze.percentile([], 99))

    def test_knees(self):
        r = self.run_analyze(budget=100)
        self.assertEqual(r["error_knee_rps"], 20)
        self.assertEqual(r["collapse_rps"], 30)
        self.assertEqual(r["latency_knee_rps"], 30)  # step 2: p99 900 ms
        self.assertEqual(r["sustained_rps"], 10)
        r = self.run_analyze(budget=50)
        self.assertEqual(r["latency_knee_rps"], 20)

    def test_two_generators_add_up(self):
        # A second generator with the same rows: every step doubles, rates add.
        raw2 = os.path.join(self.dir, "raw2.csv")
        with open(self.raw) as src, open(raw2, "w") as dst:
            dst.write(src.read())
        args = analyze.argparse.Namespace(
            raw=[self.raw, raw2], summary=[self.summary, self.summary], sampler=None,
            gen_sampler=[], journey="refresh", start_rate=10, step_rate=10, steps=3,
            hold_s=10, ramp_s=5, budget_ms=100, out=os.path.join(self.dir, "out2.json"),
        )
        r = analyze.analyze(args)
        s0, s1 = r["steps"][0], r["steps"][1]
        self.assertEqual(s0["ok_rps"], 20.0)
        self.assertEqual(s1["completed_rps"], 40.0)
        self.assertEqual(s1["error_ratio"], 0.02)
        self.assertEqual(s1["fail_classes"], {"503": 8})
        self.assertEqual(s1["dropped"], 6)

    def test_server_columns(self):
        r = self.run_analyze(budget=100)
        s0 = r["steps"][0]
        self.assertEqual(s0["server_cpu_pct_mean"], 150.0)
        self.assertEqual(s0["disk_write_iops_mean"], 20.0)
        self.assertTrue(s0["server_alive"])
        self.assertFalse(r["steps"][2]["server_alive"])


if __name__ == "__main__":
    unittest.main()
