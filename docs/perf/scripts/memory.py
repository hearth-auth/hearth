"""Server memory over a live soak: RSS at fixed minutes, the RSS trend (least-squares
slope) over a window, MemAvailable, and the storage gauges (hot-tier entries, memtable
bytes, SST files) at the same minutes.

Usage: memory.py <run dir>...

A run dir holds `sampler.csv` or `sampler.csv.gz` (one row per second: ts, alive,
cpu_ticks, rss_kb, mem_available_kb, ...) and, optionally, `metrics-storage.txt[.gz]`
(lines "<unix ts> <metric> <value>"). Minute 0 is the first sampler row, which is the
Hearth restart, about 1.5 minutes before k6 starts the load.
"""
import csv
import gzip
import os
import statistics
import sys

MINUTES = (3, 15, 30, 45, 57)
GAUGE_MINUTES = (4, 16, 28, 40, 48, 59, 61)
GAUGES = {
    "hearth_storage_hot_tier_entries": "hot_tier_entries",
    'hearth_storage_memtable_bytes{state="active"}': "memtable_bytes",
    "hearth_storage_sst_files": "sst_files",
    "hearth_storage_hot_tier_evictions_total": "hot_tier_evictions",
}


def opener(d, name):
    for p in (f"{d}/{name}", f"{d}/{name}.gz"):
        if os.path.exists(p):
            return gzip.open(p, "rt") if p.endswith(".gz") else open(p)
    return None


def slope_mib_per_h(points, a, b):
    w = [(m, r) for m, r, _ in points if a <= m < b]
    xs = [m for m, _ in w]
    ys = [r for _, r in w]
    mx, my = statistics.mean(xs), statistics.mean(ys)
    return 60 * sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)


def run(d):
    rows = [
        r for r in csv.DictReader(opener(d, "sampler.csv"))
        if r["alive"] == "1" and r["rss_kb"] and r["mem_available_kb"]
    ]
    t0 = float(rows[0]["ts"])
    pts = [
        ((float(r["ts"]) - t0) / 60, int(r["rss_kb"]) / 1024, int(r["mem_available_kb"]) / 1024)
        for r in rows
    ]

    def at(m):
        return min(pts, key=lambda p: abs(p[0] - m))

    print(f"## {d}")
    print("RSS MiB at minute " + " / ".join(map(str, MINUTES)) + ": "
          + " / ".join(f"{at(m)[1]:,.0f}" for m in MINUTES))
    print(f"RSS trend, minutes 30-58: {slope_mib_per_h(pts, 30, 58):+,.0f} MiB/h")
    peak = max(pts, key=lambda p: p[1])
    print(f"RSS peak: {peak[1]:,.0f} MiB at minute {peak[0]:.1f}")
    ma = [p[2] for p in pts]
    print(f"MemAvailable MiB: start {ma[0]:,.0f}, end {ma[-1]:,.0f}, lowest {min(ma):,.0f}")

    f = opener(d, "metrics-storage.txt")
    if f is None:
        return
    series = {}
    for line in f:
        p = line.split()
        if len(p) == 3 and p[1] in GAUGES:
            series.setdefault(int(p[0]), {})[GAUGES[p[1]]] = float(p[2])
    ts = sorted(series)
    print("minute | RSS MiB | hot-tier entries | memtable MiB | SST files | hot-tier evictions")
    for m in GAUGE_MINUTES:
        k = min(ts, key=lambda t: abs(t - (t0 + 60 * m)))
        g = series[k]
        print(
            f"{m} | {at(m)[1]:,.0f} | {g.get('hot_tier_entries', float('nan')):,.0f}"
            f" | {g.get('memtable_bytes', 0) / 2**20:.0f} | {g.get('sst_files', float('nan')):.0f}"
            f" | {g.get('hot_tier_evictions', float('nan')):.0f}"
        )


for d in sys.argv[1:]:
    run(d)
