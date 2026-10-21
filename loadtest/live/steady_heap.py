"""Whether the server's heap stops growing at a steady state (#445).

Usage: steady_heap.py --hot-tier-capacity N --block-cache-bytes B --duration-s S [options] <run dir>

The weekly steady-state memory test runs the server with small cache limits and short
lifetimes, so every cache reaches its limit and the cleanup sweep deletes rows as fast as
the load creates them. A run dir holds `metrics.txt` (lines "<unix ts> <metric line>", one
scrape every few seconds) and `k6-summary.json` (k6/stress.js SUMMARY_OUT: journeys,
ok_rate, and started_at in milliseconds, the start of the load).

1. Validity. k6's ok_rate must be at least --min-ok-rate, and the achieved rate
   (journeys / --duration-s) at least --min-rate-frac of --target-rate. Else INVALID.
2. Steady state. The first scrape after --min-warmup-min from the start of the load where
   the hot tier holds 95 % of --hot-tier-capacity and evicted entries in the 10 minutes
   before, and the block cache holds 90 % of --block-cache-bytes or grew less than 1 MiB
   in those 10 minutes (a small store may never fill it). None by --max-warmup-min:
   INCONCLUSIVE.
3. The measurement window is the --measure-min after the steady state. A run that ends
   before the window ends: INCONCLUSIVE.
4. Two values per scrape:
   - The unexplained live heap: hearth_allocator_allocated_bytes minus the heap that the
     storage gauges report (hot tier, block cache, SST readers and memtables). A leak, or a
     structure that grows without a gauge, shows here.
   - The allocator overhead: hearth_allocator_resident_bytes minus
     hearth_allocator_allocated_bytes.
   Each value is averaged per --bin-min bin. A least-squares line through the bin means
   gives the slope and its 95 % half-width (memory.fit, Student's t). Divided by the
   achieved rate, the slope is in bytes per journey.
5. Per value: PASS when slope + half-width < --max-bytes-per-journey, FAIL when the slope
   itself is at or above it, else INCONCLUSIVE. The run gets the worst verdict, in the
   order INVALID, FAIL, INCONCLUSIVE, PASS. The exit status is 0 on PASS, else 1.
"""
import argparse
import bisect
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memory import fit  # noqa: E402

MIB = 2**20
ALLOCATED = "hearth_allocator_allocated_bytes"
RESIDENT = "hearth_allocator_resident_bytes"
ENTRIES = "hearth_storage_hot_tier_entries"
EVICTIONS = "hearth_storage_hot_tier_evictions_total"
BLOCK_CACHE = "hearth_storage_block_cache_bytes"
# The heap that the storage gauges report; the unexplained live heap excludes it.
GAUGED = (
    "hearth_storage_hot_tier_bytes",
    BLOCK_CACHE,
    "hearth_storage_sst_reader_bytes",
    'hearth_storage_memtable_bytes{state="active"}',
    'hearth_storage_memtable_bytes{state="flushing"}',
)
NEEDED = (ALLOCATED, RESIDENT, ENTRIES, EVICTIONS) + GAUGED
ORDER = ("PASS", "INCONCLUSIVE", "FAIL", "INVALID")


def read_scrapes(d):
    """The complete scrapes in metrics.txt, as a sorted list of (ts, {metric: value})."""
    by_ts = {}
    with open(f"{d}/metrics.txt") as f:
        for line in f:
            parts = line.split()
            if len(parts) != 3 or parts[1] not in NEEDED:
                continue
            by_ts.setdefault(int(parts[0]), {})[parts[1]] = float(parts[2])
    return sorted((ts, m) for ts, m in by_ts.items() if all(k in m for k in NEEDED))


def steady_start(scrapes, t0, args):
    """The ts of the first scrape in the warm-up range where every cache is full, or None."""
    times = [ts for ts, _ in scrapes]
    lo, hi = t0 + args.min_warmup_min * 60, t0 + args.max_warmup_min * 60
    for ts, m in scrapes:
        if ts < lo or ts > hi:
            continue
        before = bisect.bisect_right(times, ts - 600) - 1
        if before < 0:
            continue
        then = scrapes[before][1]
        evicting = m[EVICTIONS] > then[EVICTIONS]
        block_done = (m[BLOCK_CACHE] >= 0.9 * args.block_cache_bytes
                      or m[BLOCK_CACHE] - then[BLOCK_CACHE] < MIB)
        if m[ENTRIES] >= 0.95 * args.hot_tier_capacity and evicting and block_done:
            return ts
    return None


def judge(name, points, start, rate, args):
    """Prints one value's slope per journey and returns its verdict."""
    bins = {}
    for ts, value in points:
        bins.setdefault(int((ts - start) // (args.bin_min * 60)), []).append(value)
    means = [((k + 0.5) * args.bin_min * 60, statistics.mean(v)) for k, v in sorted(bins.items())]
    slope, half = fit(means)
    per_j, half_j = slope / rate, half / rate
    mark = args.max_bytes_per_journey
    verdict = "PASS" if per_j + half_j < mark else "FAIL" if per_j >= mark else "INCONCLUSIVE"
    print(f"{name}: {per_j:+.1f} B/journey ({slope * 3600 / MIB:+.2f} MiB/h; 95 % bound "
          f"{per_j + half_j:+.1f}; mark < {mark:g}) {verdict}")
    return verdict


def run(d, args):
    """Judges one run dir and returns its verdict."""
    with open(f"{d}/k6-summary.json") as f:
        summary = json.load(f)
    t0 = summary["started_at"] // 1000
    rate = summary["journeys"] / args.duration_s
    print(f"run: {d}")
    print(f"load: {summary['journeys']:,} journeys in {args.duration_s / 60:.0f} min = "
          f"{rate:.1f}/s (target {args.target_rate:g}/s), ok rate {summary['ok_rate']:.2%}")
    if summary["ok_rate"] < args.min_ok_rate or rate < args.min_rate_frac * args.target_rate:
        print(f"the load is not the planned load (ok rate below {args.min_ok_rate:.0%} or "
              f"rate below {args.min_rate_frac:.0%} of the target)")
        return "INVALID"
    scrapes = read_scrapes(d)
    if not scrapes:
        print("metrics.txt has no complete scrape (allocator and storage gauges)")
        return "INVALID"
    start = steady_start(scrapes, t0, args)
    if start is None:
        print(f"no steady state by minute {args.max_warmup_min:g}: the caches are not full")
        return "INCONCLUSIVE"
    m = dict(scrapes)[start]
    print(f"steady from minute {(start - t0) / 60:.0f} (hot tier {m[ENTRIES]:,.0f} of "
          f"{args.hot_tier_capacity:,} entries, evicting; block cache "
          f"{m[BLOCK_CACHE] / MIB:.1f} of {args.block_cache_bytes / MIB:.1f} MiB, full or flat)")
    end = start + args.measure_min * 60
    if scrapes[-1][0] < end:
        print(f"the run ends before the measurement window: minute "
              f"{(scrapes[-1][0] - t0) / 60:.0f}, window to minute {(end - t0) / 60:.0f}")
        return "INCONCLUSIVE"
    window = [(ts, s) for ts, s in scrapes if start <= ts < end]
    print(f"window: minutes {(start - t0) / 60:.0f}-{(end - t0) / 60:.0f}, "
          f"{args.measure_min // args.bin_min:g} bins of {args.bin_min:g} min")
    unexplained = [(ts, s[ALLOCATED] - sum(s[g] for g in GAUGED)) for ts, s in window]
    overhead = [(ts, s[RESIDENT] - s[ALLOCATED]) for ts, s in window]
    verdicts = [judge("unexplained live heap", unexplained, start, rate, args),
                judge("allocator overhead", overhead, start, rate, args)]
    return max(verdicts, key=ORDER.index)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--hot-tier-capacity", type=int, required=True)
    p.add_argument("--block-cache-bytes", type=int, required=True)
    p.add_argument("--duration-s", type=int, required=True, help="length of the k6 load")
    p.add_argument("--target-rate", type=float, default=120.0, help="journeys per second")
    p.add_argument("--min-rate-frac", type=float, default=0.95)
    p.add_argument("--min-ok-rate", type=float, default=0.99)
    p.add_argument("--min-warmup-min", type=float, default=80)
    p.add_argument("--max-warmup-min", type=float, default=120)
    p.add_argument("--measure-min", type=float, default=90)
    p.add_argument("--bin-min", type=float, default=10)
    p.add_argument("--max-bytes-per-journey", type=float, default=3.0)
    p.add_argument("run_dir")
    args = p.parse_args(argv)
    verdict = run(args.run_dir, args)
    print(f"VERDICT: {verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
