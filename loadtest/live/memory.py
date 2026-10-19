"""Server memory over a live soak, and whether it stays flat (#445).

Usage: memory.py [--warmup-min M] [--bin-min B] [--max-slope S] <run dir>...

A run dir holds `sampler.csv` or `sampler.csv.gz` (one row per second: ts, alive, rss_kb,
mem_available_kb and, from 2026-10-11, rss_anon_kb and rss_file_kb), optionally
`metrics-storage.txt` or `metrics.txt` (either may be gzipped; lines
"<unix ts> <metric> <value>") and `m<minute>.malloc_info.xml`. Minute 0 is the first
sampler row, which is the Hearth restart, about 1.5 minutes before k6 starts the load.

Per run it prints:
1. RSS, RssAnon and RssFile at fixed minutes, the RSS trend, and MemAvailable. RssAnon
   is the heap and the other private memory: the part a leak grows. RssFile is the mapped
   SST files, which the kernel drops when it needs the memory.
2. The storage gauges at fixed minutes.
3. glibc's heap at each malloc_info minute: the arenas' size, the free memory inside them,
   and the memory in use.
4. The flatness test. The "floor" is the lowest RssAnon between two memtable flushes: just
   after a flush, when the memtable is empty and the freed heap was just returned. From it
   the test subtracts the SST readers' own heap (hearth_storage_sst_reader_bytes: block
   indexes and Bloom filters, which grow with the stored data, not with time), and the
   caches' memory (hearth_storage_hot_tier_bytes and hearth_storage_block_cache_bytes: each
   cache stops at its capacity, but the default caches do not fill in a day). A run without
   the cache gauges (releases before them) subtracts the SST readers only. After the
   warm-up, it fits a least-squares line to the means of that value per bin (default one
   hour). One-second samples are not independent; bin means nearly are, so the 95 % upper
   bound of the slope uses Student's t over the bin means. PASS: the upper bound is below
   --max-slope (MiB/h).
"""
import argparse
import csv
import gzip
import math
import os
import re
import statistics

SHORT_MINUTES = (3, 15, 30, 45, 57)
SHORT_GAUGE_MINUTES = (4, 16, 28, 40, 48, 59, 61)
MEMTABLE = 'hearth_storage_memtable_bytes{state="active"}'
GAUGES = {
    "hearth_storage_hot_tier_entries": "hot_tier_entries",
    MEMTABLE: "memtable_bytes",
    "hearth_storage_sst_files": "sst_files",
    "hearth_storage_hot_tier_evictions_total": "hot_tier_evictions",
    "hearth_storage_sst_reader_bytes": "sst_reader_bytes",
    "hearth_storage_hot_tier_bytes": "hot_tier_bytes",
    "hearth_storage_block_cache_bytes": "block_cache_bytes",
}
# Two-sided 95 % Student's t, by degrees of freedom; 1.96 above 30.
T95 = (None, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
       2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
       2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042)
MIB = 2**20


def opener(d, *names):
    for name in names:
        for p in (f"{d}/{name}", f"{d}/{name}.gz"):
            if os.path.exists(p):
                return gzip.open(p, "rt") if p.endswith(".gz") else open(p)
    return None


def fit(points):
    """Least-squares slope of (x, y) points and its 95 % half-width (None below 3 points)."""
    xs = [x for x, _ in points]
    ys = [y for _, y in points]
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in points) / sxx
    n = len(points)
    if n < 3:
        return slope, None
    resid = sum((y - my - slope * (x - mx)) ** 2 for x, y in points)
    se = math.sqrt(resid / (n - 2) / sxx)
    t = T95[n - 2] if n - 2 < len(T95) else 1.96
    return slope, t * se


def read_sampler(d):
    """[(minute, rss_mib, anon_mib or None, file_mib or None, mem_available_mib)], t0."""
    with opener(d, "sampler.csv") as f:
        rows = [
            r for r in csv.DictReader(f)
            if r["alive"] == "1" and r["rss_kb"] and r["mem_available_kb"]
        ]
    t0 = float(rows[0]["ts"])

    def mib(r, k):
        v = r.get(k)
        return int(v) / 1024 if v else None

    return [
        ((float(r["ts"]) - t0) / 60, mib(r, "rss_kb"), mib(r, "rss_anon_kb"),
         mib(r, "rss_file_kb"), mib(r, "mem_available_kb"))
        for r in rows
    ], t0


def read_gauges(d, t0):
    """{minute: {gauge: value}}, from the scraped metrics."""
    f = opener(d, "metrics-storage.txt", "metrics.txt")
    if f is None:
        return {}
    series = {}
    with f:
        for line in f:
            p = line.split()
            if len(p) == 3 and p[1] in GAUGES:
                series.setdefault((int(p[0]) - t0) / 60, {})[GAUGES[p[1]]] = float(p[2])
    return series


def flushes(gauges):
    """Minutes at which the active memtable dropped to under half (a flush)."""
    out, prev = [], None
    for m in sorted(gauges):
        v = gauges[m].get("memtable_bytes")
        if v is None:
            continue
        if prev is not None and prev > MIB and v < prev / 2:
            out.append(m)
        prev = v
    return out


def floors(pts, cuts):
    """The lowest RssAnon (RSS without the column) between consecutive cuts: (minute, MiB)."""
    out, i = [], 0
    for a, b in zip(cuts, cuts[1:]):
        # The scrape that saw the drop is up to 5 s after the flush.
        a -= 5 / 60
        while i < len(pts) and pts[i][0] < a:
            i += 1
        j, best = i, None
        while j < len(pts) and pts[j][0] < b - 5 / 60:
            p = pts[j]
            v = p[2] if p[2] is not None else p[1]
            if best is None or v < best[1]:
                best = (p[0], v)
            j += 1
        if best is not None:
            out.append(best)
    return out


def malloc_info(d):
    """[(minute, arena MiB, free MiB, mmap MiB)] from m<minute>.malloc_info.xml."""
    out = []
    for name in os.listdir(d):
        m = re.fullmatch(r"m(\d+)\.malloc_info\.xml", name)
        if not m:
            continue
        with open(f"{d}/{name}") as f:
            text = f.read()
        tail = text[text.rfind("</heap>"):]
        v = {
            k: int(x) for k, x in re.findall(
                r'<(?:total|system) type="(fast|rest|mmap|current)" (?:count="\d+" )?size="(\d+)"',
                tail)
        }
        if "current" in v:
            out.append((int(m.group(1)), v["current"] / MIB,
                        (v.get("fast", 0) + v.get("rest", 0)) / MIB, v.get("mmap", 0) / MIB))
    return sorted(out)


def run(d, warmup, bin_min, max_slope):
    pts, t0 = read_sampler(d)
    end = pts[-1][0]
    long_run = end > 90
    minutes = tuple(range(60, int(end) + 1, 60)) or (int(end),) if long_run else SHORT_MINUTES
    has_anon = pts[-1][2] is not None

    def at(m):
        return min(pts, key=lambda p: abs(p[0] - m))

    print(f"## {d}")
    print("RSS MiB at minute " + " / ".join(map(str, minutes)) + ": "
          + " / ".join(f"{at(m)[1]:,.0f}" for m in minutes))
    if has_anon:
        print("RssAnon MiB: " + " / ".join(f"{at(m)[2]:,.0f}" for m in minutes))
        print("RssFile MiB: " + " / ".join(f"{at(m)[3]:,.0f}" for m in minutes))
    a, b = (warmup, end) if long_run else (30, 58)
    rss = fit([(p[0] / 60, p[1]) for p in pts if a <= p[0] < b])[0]
    print(f"RSS trend, minutes {a:.0f}-{b:.0f}: {rss:+,.0f} MiB/h")
    peak = max(pts, key=lambda p: p[1])
    print(f"RSS peak: {peak[1]:,.0f} MiB at minute {peak[0]:.1f}")
    ma = [p[4] for p in pts]
    print(f"MemAvailable MiB: start {ma[0]:,.0f}, end {ma[-1]:,.0f}, lowest {min(ma):,.0f}")

    gauges = read_gauges(d, t0)
    if gauges:
        gm = sorted(gauges)
        print("minute | RSS MiB | hot-tier entries | memtable MiB | SST files | hot-tier evictions"
              " | SST reader MiB | hot-tier MiB | block-cache MiB")
        for m in (minutes if long_run else SHORT_GAUGE_MINUTES):
            g = gauges[min(gm, key=lambda t: abs(t - m))]
            print(
                f"{m} | {at(m)[1]:,.0f} | {g.get('hot_tier_entries', math.nan):,.0f}"
                f" | {g.get('memtable_bytes', 0) / MIB:.0f} | {g.get('sst_files', math.nan):.0f}"
                f" | {g.get('hot_tier_evictions', math.nan):.0f}"
                f" | {g.get('sst_reader_bytes', math.nan) / MIB:.1f}"
                f" | {g.get('hot_tier_bytes', math.nan) / MIB:.1f}"
                f" | {g.get('block_cache_bytes', math.nan) / MIB:.1f}"
            )

    mi = malloc_info(d)
    if mi:
        print("malloc_info minute | arenas MiB | free in arenas MiB | mmap MiB | in use MiB")
        for m, arena, free, mmap in mi:
            print(f"{m} | {arena:,.0f} | {free:,.0f} | {mmap:,.0f} | {arena - free + mmap:,.0f}")

    flat_test(pts, gauges, end, has_anon, warmup, bin_min, max_slope)


def flat_test(pts, gauges, end, has_anon, warmup, bin_min, max_slope):
    cuts = flushes(gauges)
    how = f"{len(cuts)} memtable flushes"
    if len(cuts) < 3:
        how = f"only {len(cuts)} memtable flushes, so 5-minute windows"
        cuts = [m for m in range(0, int(end) + 1, 5)]
    fl = [f for f in floors(pts, cuts) if f[0] >= warmup]
    gm = sorted(gauges)
    have_sst = any("sst_reader_bytes" in g for g in gauges.values())
    have_caches = any("hot_tier_bytes" in g or "block_cache_bytes" in g for g in gauges.values())

    def near(m):
        return gauges[min(gm, key=lambda t: abs(t - m))]

    def sst(m):
        return near(m).get("sst_reader_bytes", 0) / MIB if have_sst else 0.0

    def caches(m):
        if not have_caches:
            return 0.0
        g = near(m)
        return (g.get("hot_tier_bytes", 0) + g.get("block_cache_bytes", 0)) / MIB

    bins = {}
    for m, v in fl:
        k = int((m - warmup) // bin_min)
        # Whole bins only; the last sample may come up to a minute before the end.
        if warmup + (k + 1) * bin_min <= end + 1:
            bins.setdefault(k, []).append((m, v, sst(m), caches(m)))
    what = "RssAnon" if has_anon else "RSS (no RssAnon column)"
    print(f"Flatness test: floor of {what} after minute {warmup:g}, {how}, "
          f"{len(bins)} bins of {bin_min:g} min")
    if len(bins) < 3:
        print("  too few whole bins for a slope: run longer or use a shorter --bin-min")
        return
    # Each bin sits at the mean time of its floors, which need not be its middle.
    rows = [
        (statistics.mean(r[0] for r in b) / 60, statistics.mean(r[1] for r in b),
         statistics.mean(r[2] for r in b), statistics.mean(r[3] for r in b))
        for b in (bins[k] for k in sorted(bins))
    ]
    judged = "floor - SST reader heap - caches" if have_caches else "floor - SST reader heap"
    print("  hour | floor MiB | SST reader MiB"
          + (" | caches MiB | floor - SST reader - caches MiB" if have_caches
             else " | floor - SST reader MiB"))
    for x, v, s, c in rows:
        print(f"  {x:.2f} | {v:,.1f} | {s:,.1f}"
              + (f" | {c:,.1f}" if have_caches else "") + f" | {v - s - c:,.1f}")
    series = [("floor", lambda r: r[1])]
    if have_sst:
        series.append(("SST reader heap", lambda r: r[2]))
    if have_caches:
        series.append(("caches", lambda r: r[3]))
    if have_sst or have_caches:
        series.append((judged, lambda r: r[1] - r[2] - r[3]))
    for label, pick in series:
        slope, half = fit([(r[0], pick(r)) for r in rows])
        print(f"  {label}: {slope:+.2f} MiB/h (95 % bound {slope - half:+.2f} .. {slope + half:+.2f})")
    slope, half = fit([(r[0], r[1] - r[2] - r[3]) for r in rows])
    verdict = "PASS" if slope + half < max_slope else "FAIL"
    if not have_sst and not have_caches:
        note = " (no SST reader gauge: the floor itself)"
    elif not have_caches:
        note = " (no cache gauges: the caches are judged with the rest)"
    else:
        note = ""
    print(f"  {verdict}: upper bound {slope + half:+.2f} MiB/h against {max_slope:g} MiB/h"
          + note)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--warmup-min", type=float, default=120,
                    help="minutes left out at the start (caches fill): 120")
    ap.add_argument("--bin-min", type=float, default=60, help="bin length in minutes: 60")
    ap.add_argument("--max-slope", type=float, default=2.0,
                    help="pass mark for the slope's upper bound, MiB/h: 2")
    ap.add_argument("dirs", nargs="+")
    args = ap.parse_args(argv)
    for d in args.dirs:
        run(d, args.warmup_min, args.bin_min, args.max_slope)


if __name__ == "__main__":
    main()
