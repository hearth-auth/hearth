"""Per-step table of a live ramp or soak: completed journeys/s per type, failures,
p50/p99, HTTP req/s, dropped iterations, server CPU (of 200%), k6 CPU per generator
(of 400%) and the generator idle % from vmstat. Only the hold phase of each step counts.

Usage: ramps.py <run dir>...

A run dir holds the k6 raw CSVs (`raw-g1.csv.gz`, `raw-g2.csv.gz`), `params.env`, and
the samplers (`sampler.csv`, `gen-sampler-g{1,2}.csv`, `vmstat-gen{1,2}-<dir>.txt`, each
optionally gzipped). The raw CSVs are not committed (about 500 MB per round).
"""
import csv, gzip, sys, collections, datetime, os


def opener(path):
    """Opens `path`, or `path.gz` when only the gzipped copy exists. None if neither does."""
    if os.path.exists(path):
        return open(path)
    if os.path.exists(path + ".gz"):
        return gzip.open(path + ".gz", "rt")
    return None


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    return xs[max(0, min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1)))))]


def tags(s):
    return dict(kv.split("=", 1) for kv in s.split("&") if "=" in kv)


def params(d):
    out = {}
    for line in open(f"{d}/params.env"):
        if "=" in line:
            k, v = line.strip().split("=", 1)
            out[k] = v
    return out


def cpu(path, a, b):
    """CPU % of one process over [a, b] from a sampler CSV (cpu_ticks, clk_tck)."""
    f = opener(path)
    if f is None:
        return float("nan"), float("nan")
    rows = [r for r in csv.DictReader(f) if r.get("alive") == "1" and r["cpu_ticks"] and r["rss_kb"]]
    w = [r for r in rows if a <= float(r["ts"]) <= b + 1]
    if len(w) < 2:
        return float("nan"), float("nan")
    t = float(w[-1]["ts"]) - float(w[0]["ts"])
    c = (int(w[-1]["cpu_ticks"]) - int(w[0]["cpu_ticks"])) / int(w[0]["clk_tck"])
    rss = max(int(r["rss_kb"]) for r in w) / 1024
    return 100 * c / t, rss


def vmstat_idle(path, a, b):
    """Lowest idle % and mean idle % over [a, b] (vmstat -n -t, UTC timestamps)."""
    f = opener(path)
    if f is None:
        return float("nan"), float("nan")
    head, vals = None, []
    for line in f:
        f = line.split()
        if "id" in f and "us" in f:
            head = f
            continue
        if not head or len(f) < len(head) or not f[0].isdigit():
            continue
        try:
            ts = datetime.datetime.strptime(f[-2] + " " + f[-1], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        ts = ts.replace(tzinfo=datetime.timezone.utc).timestamp()
        if a <= ts <= b:
            vals.append(int(f[head.index("id")]))
    if not vals:
        return float("nan"), float("nan")
    return min(vals), sum(vals) / len(vals)


def run(d):
    p = params(d)
    start, step = int(p["START_RATE"]), int(p["STEP_RATE"])
    jms = collections.defaultdict(list)
    jok = collections.Counter()
    req = collections.Counter()
    fail = collections.Counter()
    win = collections.defaultdict(lambda: [10**12, 0])
    dropped = []
    for g in ("g1", "g2"):
        with gzip.open(f"{d}/raw-{g}.csv.gz", "rt") as f:
            for r in csv.DictReader(f):
                m = r["metric_name"]
                if m == "dropped_iterations":
                    dropped.append((int(r["timestamp"]), float(r["metric_value"])))
                    continue
                t = tags(r["extra_tags"])
                if t.get("phase") != "hold":
                    continue
                st = int(t.get("step", -1))
                ts = int(r["timestamp"])
                if m == "journey_ms":
                    jms[(st, t["journey"])].append(float(r["metric_value"]))
                    win[st][0] = min(win[st][0], ts)
                    win[st][1] = max(win[st][1], ts)
                elif m == "journey_ok":
                    jok[(st, t["journey"], r["metric_value"].startswith("1"))] += 1
                elif m == "http_reqs":
                    req[st] += 1
                    if r["status"] and not r["status"].startswith(("2", "3")):
                        fail[(st, r["name"], r["status"] or "err")] += 1
                    elif not r["status"]:
                        fail[(st, r["name"], "neterr")] += 1
    journeys = sorted({j for (_, j) in jms})
    print(f"## {d}  ({p['JOURNEY']} {start}/s +{step}/s x{p['STEPS']}, hold {p['HOLD_S']} s)")
    for st in sorted(win):
        a, b = win[st]
        dur = b - a + 1
        tot = sum(jok[(st, j, True)] for j in journeys)
        bad = sum(jok[(st, j, False)] for j in journeys)
        drop = sum(v for ts, v in dropped if a <= ts <= b)
        scpu, srss = cpu(f"{d}/sampler.csv", a, b)
        g1, _ = cpu(f"{d}/gen-sampler-g1.csv", a, b)
        g2, _ = cpu(f"{d}/gen-sampler-g2.csv", a, b)
        i1 = vmstat_idle(f"{d}/vmstat-gen1-{os.path.basename(d.rstrip('/'))}.txt", a, b)
        i2 = vmstat_idle(f"{d}/vmstat-gen2-{os.path.basename(d.rstrip('/'))}.txt", a, b)
        errpct = 100 * bad / max(1, tot + bad)
        print(
            f"offered {start + step * st:6d}/s ({dur} s): ok {tot / dur:8.1f}/s  fail {bad:6d} ({errpct:.2f}%)"
            f"  dropped {drop:6.0f}  HTTP {req[st] / dur:8.1f}/s  server CPU {scpu:5.0f}%  RSS {srss:5.0f} MiB"
            f"  k6 CPU g1 {g1:4.0f}% g2 {g2:4.0f}%  gen idle min/mean g1 {i1[0]}/{i1[1]:.0f} g2 {i2[0]}/{i2[1]:.0f}"
        )
        for j in journeys:
            ms = jms[(st, j)]
            print(
                f"   {j:13s} {jok[(st, j, True)] / dur:8.1f}/s ok  fail {jok[(st, j, False)]:6d}"
                f"  p50 {pct(ms, 50):8.1f} ms  p99 {pct(ms, 99):8.1f} ms"
            )
        f = {f"{n}:{c}": v for (s, n, c), v in fail.items() if s == st}
        if f:
            print("   non-2xx/3xx:", dict(sorted(f.items(), key=lambda kv: -kv[1])[:6]))


for d in sys.argv[1:]:
    run(d)
