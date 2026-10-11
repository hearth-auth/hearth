#!/usr/bin/env python3
"""Tests for memory.py on generated soak data with known slopes.

Run: python3 loadtest/live/test_memory.py
"""
import contextlib
import csv
import io
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import memory  # noqa: E402

MIB = 2**20
T0 = 1_800_000_000
FLUSH_EVERY_S = 360
MEMTABLE_PEAK = 64 * MIB


def soak(d, hours, leak_mib_h, sst_mib_h, anon=True, gauge=True, seed=1):
    """Writes a soak's sampler.csv and metrics.txt to d.

    The memtable fills for FLUSH_EVERY_S, then a flush empties it. RssAnon is a base, plus
    1.5 times the memtable, plus the SST readers' heap (10 MiB + sst_mib_h per hour), plus
    a leak of leak_mib_h per hour, plus noise.
    """
    rnd = random.Random(seed)

    def memtable(t):
        return MEMTABLE_PEAK * (t % FLUSH_EVERY_S) / FLUSH_EVERY_S

    def sst(t):
        return 10 * MIB + sst_mib_h * MIB * t / 3600

    end = int(hours * 3600)
    with open(f"{d}/sampler.csv", "w", newline="") as f:
        w = csv.writer(f)
        cols = ["ts", "alive", "rss_kb", "mem_available_kb"]
        w.writerow(cols + (["rss_anon_kb", "rss_file_kb"] if anon else []))
        for t in range(0, end, 10):
            a = 400 * MIB + 1.5 * memtable(t) + sst(t) + leak_mib_h * MIB * t / 3600
            a += rnd.uniform(-3, 3) * MIB
            file = 100 * MIB + 50 * MIB * t / 3600
            row = [T0 + t, 1, int((a + file) / 1024), 3_000_000]
            w.writerow(row + ([int(a / 1024), int(file / 1024)] if anon else []))
    with open(f"{d}/metrics.txt", "w") as f:
        for t in range(0, end, 30):
            f.write(f'{T0 + t} hearth_storage_memtable_bytes{{state="active"}} {memtable(t):.0f}\n')
            if gauge:
                f.write(f"{T0 + t} hearth_storage_sst_reader_bytes {sst(t):.0f}\n")


def report(d, *flags):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        memory.main([*flags, d])
    return out.getvalue()


def slope_of(text, label):
    for line in text.splitlines():
        if line.strip().startswith(f"{label}:"):
            return float(line.split(":")[1].split("MiB/h")[0])
    raise AssertionError(f"no line for {label} in:\n{text}")


class Fit(unittest.TestCase):
    def test_a_straight_line_has_its_slope_and_no_spread(self):
        slope, half = memory.fit([(x, 3 + 2 * x) for x in range(5)])
        self.assertAlmostEqual(slope, 2)
        self.assertAlmostEqual(half, 0)

    def test_two_points_give_no_bound(self):
        self.assertEqual(memory.fit([(0, 1), (1, 3)]), (2, None))

    def test_the_bound_uses_student_t(self):
        # Residuals +1, -1, -1, +1 around y = x: s = 2 / sqrt(2), sxx = 5, t(2) = 4.303.
        _, half = memory.fit([(0, 1), (1, 0), (2, 1), (3, 4)])
        _, half_line = memory.fit([(0, 0), (1, 1), (2, 2), (3, 3)])
        self.assertAlmostEqual(half_line, 0)
        slope, _ = memory.fit([(0, 1), (1, 0), (2, 1), (3, 4)])
        resid = sum((y - (sum([1, 0, 1, 4]) / 4) - slope * (x - 1.5)) ** 2
                    for x, y in [(0, 1), (1, 0), (2, 1), (3, 4)])
        self.assertAlmostEqual(half, 4.303 * (resid / 2 / 5) ** 0.5)


class Flushes(unittest.TestCase):
    def test_a_drop_to_under_half_of_a_full_memtable_is_a_flush(self):
        g = {0: {"memtable_bytes": 10 * MIB}, 1: {"memtable_bytes": 1 * MIB},
             2: {"memtable_bytes": 6 * MIB}, 3: {"memtable_bytes": 5 * MIB}}
        self.assertEqual(memory.flushes(g), [1])

    def test_a_drop_from_an_almost_empty_memtable_is_not(self):
        g = {0: {"memtable_bytes": 0.5 * MIB}, 1: {"memtable_bytes": 0}}
        self.assertEqual(memory.flushes(g), [])


class FlatnessTest(unittest.TestCase):
    def test_growth_that_follows_the_sst_readers_passes(self):
        with tempfile.TemporaryDirectory() as d:
            soak(d, hours=8, leak_mib_h=0, sst_mib_h=6)
            text = report(d)
        self.assertAlmostEqual(slope_of(text, "floor"), 6, delta=0.5)
        self.assertAlmostEqual(slope_of(text, "SST reader heap"), 6, delta=0.01)
        self.assertAlmostEqual(slope_of(text, "floor - SST reader heap"), 0, delta=0.5)
        self.assertIn("PASS", text)
        self.assertIn("6 bins of 60 min", text)

    def test_a_leak_of_5_mib_an_hour_fails(self):
        with tempfile.TemporaryDirectory() as d:
            soak(d, hours=8, leak_mib_h=5, sst_mib_h=6)
            text = report(d)
        self.assertAlmostEqual(slope_of(text, "floor - SST reader heap"), 5, delta=0.5)
        self.assertIn("FAIL", text)

    def test_the_floor_is_the_memory_after_a_flush(self):
        # 1.5 x 64 MiB of memtable sits on top of the floor just before each flush;
        # 10 s after a flush, 2.7 MiB of it is back.
        with tempfile.TemporaryDirectory() as d:
            soak(d, hours=4, leak_mib_h=0, sst_mib_h=0)
            text = report(d, "--warmup-min", "60", "--bin-min", "30")
        rows = [line for line in text.splitlines() if line.startswith("  1.2")]
        self.assertEqual(len(rows), 1, text)
        floor = float(rows[0].split("|")[1].replace(",", ""))
        # 410 MiB at a flush, +-3 of noise; never the 96 MiB of a full memtable on top.
        self.assertAlmostEqual(floor, 410, delta=3)

    def test_without_the_gauge_the_floor_itself_is_judged(self):
        with tempfile.TemporaryDirectory() as d:
            soak(d, hours=8, leak_mib_h=0, sst_mib_h=6, gauge=False)
            text = report(d)
        self.assertIn("FAIL", text)
        self.assertIn("no SST reader gauge", text)

    def test_without_rss_anon_it_says_it_used_rss(self):
        with tempfile.TemporaryDirectory() as d:
            soak(d, hours=8, leak_mib_h=0, sst_mib_h=0, anon=False)
            text = report(d)
        self.assertIn("floor of RSS (no RssAnon column)", text)

    def test_too_few_whole_bins_give_no_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            soak(d, hours=4, leak_mib_h=0, sst_mib_h=0)
            text = report(d)
        self.assertIn("too few whole bins", text)
        self.assertNotIn("PASS", text)


class MallocInfo(unittest.TestCase):
    def test_the_totals_after_the_last_heap_are_read(self):
        xml = """warning: 38 ../sysdeps/unix/sysv/linux/x86_64/syscall.S: No such file
<malloc version="1">
<heap nr="0"><sizes></sizes>
<total type="fast" count="1" size="99"/>
<system type="current" size="1"/>
</heap>
<total type="fast" count="3" size="1048576"/>
<total type="rest" count="147356" size="2097152"/>
<total type="mmap" count="1" size="4194304"/>
<system type="current" size="10485760"/>
<system type="max" size="20971520"/>
</malloc>
"""
        with tempfile.TemporaryDirectory() as d:
            with open(f"{d}/m59.malloc_info.xml", "w") as f:
                f.write(xml)
            self.assertEqual(memory.malloc_info(d), [(59, 10.0, 3.0, 4.0)])


if __name__ == "__main__":
    unittest.main()
