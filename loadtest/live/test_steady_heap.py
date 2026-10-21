#!/usr/bin/env python3
"""Tests for steady_heap.py on generated runs with known slopes.

Run: python3 loadtest/live/test_steady_heap.py
"""
import contextlib
import io
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import steady_heap  # noqa: E402

MIB = 2**20
T0 = 1_800_000_000
CAP = 20_000
BLOCK = 32 * MIB
RATE = 120.0


def run(d, minutes=215, leak=0.0, overhead=0.0, fill_min=40, ok_rate=0.999, rate_frac=1.0,
        wobble_mib=0.0, seed=1):
    """Writes a run's metrics.txt and k6-summary.json to d.

    Scrapes every 5 s from T0, where the load starts. The hot tier and the block cache fill
    linearly until fill_min, then stay at their limits, and the hot tier evicts from then on.
    The SST readers grow with the stored data, and the memtable fills and flushes every
    200 s, so a 10-minute bin holds whole cycles. `allocated` is a base plus all of these (the memtable at 1.5 times its gauge),
    plus `leak` bytes per journey, plus noise. `resident` is `allocated` plus a fixed
    overhead, plus `overhead` bytes per journey. wobble_mib adds a square wave with a
    20-minute period from minute 80, which leaves the slope near zero and the bound wide.
    """
    rng = random.Random(seed)
    rate = RATE * rate_frac
    lines = []
    for i in range(minutes * 12 + 1):
        t = i * 5
        m = t / 60
        full = min(1.0, m / fill_min)
        entries = CAP * full
        evictions = max(0.0, (m - fill_min) * 60 * 100)
        hot = entries * 300
        block = BLOCK * full
        sst = MIB + 0.2 * MIB * m / 60
        memtable = 8 * MIB * ((t % 200) / 200)
        wobble = 0.0
        if wobble_mib and m >= 80:
            wobble = wobble_mib * MIB * (1 if int((m - 80) // 10) % 2 == 0 else -1)
        allocated = (60 * MIB + hot + block + sst + 1.5 * memtable + leak * rate * t
                     + wobble + rng.gauss(0, 0.5 * MIB))
        resident = allocated + 20 * MIB + overhead * rate * t + rng.gauss(0, 0.5 * MIB)
        ts = T0 + t
        for name, value in (
            ("hearth_allocator_allocated_bytes", allocated),
            ("hearth_allocator_resident_bytes", resident),
            ("hearth_storage_hot_tier_entries", entries),
            ("hearth_storage_hot_tier_evictions_total", evictions),
            ("hearth_storage_hot_tier_bytes", hot),
            ("hearth_storage_block_cache_bytes", block),
            ("hearth_storage_sst_reader_bytes", sst),
            ('hearth_storage_memtable_bytes{state="active"}', memtable),
            ('hearth_storage_memtable_bytes{state="flushing"}', 0),
        ):
            lines.append(f"{ts} {name} {value:.6e}\n")
    with open(f"{d}/metrics.txt", "w") as f:
        f.writelines(lines)
    with open(f"{d}/k6-summary.json", "w") as f:
        json.dump({"journeys": int(rate * minutes * 60), "ok_rate": ok_rate,
                   "started_at": T0 * 1000}, f)


def judge(d, *extra):
    """Runs steady_heap.main on d with the test's limits; returns (exit code, output)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = steady_heap.main([
            "--hot-tier-capacity", str(CAP), "--block-cache-bytes", str(BLOCK),
            "--duration-s", str(215 * 60), "--target-rate", str(RATE), *extra, d])
    return code, out.getvalue()


class SteadyHeapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_flat_run_passes(self):
        run(self.d)
        code, out = judge(self.d)
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: PASS", out)
        self.assertIn("steady from minute 80", out)

    def test_a_live_heap_leak_fails(self):
        run(self.d, leak=10.0)
        code, out = judge(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: FAIL", out)
        self.assertRegex(out, r"unexplained live heap: \+(9|10|11)\.\d B/journey")

    def test_a_growing_allocator_overhead_fails(self):
        run(self.d, overhead=10.0)
        code, out = judge(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: FAIL", out)
        self.assertRegex(out, r"allocator overhead: \+(9|10|11)\.\d B/journey")

    def test_a_leak_below_the_mark_passes(self):
        run(self.d, leak=1.0)
        code, out = judge(self.d)
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: PASS", out)

    def test_a_wide_bound_is_inconclusive(self):
        run(self.d, wobble_mib=10.0)
        code, out = judge(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: INCONCLUSIVE", out)

    def test_caches_that_never_fill_are_inconclusive(self):
        run(self.d, fill_min=150)
        code, out = judge(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: INCONCLUSIVE", out)
        self.assertIn("no steady state by minute 120", out)

    def test_a_late_steady_state_starts_the_window_later(self):
        run(self.d, fill_min=100)
        code, out = judge(self.d)
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r"steady from minute 10[0-9]")

    def test_a_run_shorter_than_the_window_is_inconclusive(self):
        run(self.d, minutes=150)
        code, out = judge(self.d, "--duration-s", str(150 * 60))
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: INCONCLUSIVE", out)
        self.assertIn("ends before the measurement window", out)

    def test_failed_journeys_make_the_run_invalid(self):
        run(self.d, ok_rate=0.95)
        code, out = judge(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: INVALID", out)

    def test_a_low_journey_rate_makes_the_run_invalid(self):
        run(self.d, rate_frac=0.8)
        code, out = judge(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("VERDICT: INVALID", out)


if __name__ == "__main__":
    unittest.main()
