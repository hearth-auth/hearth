#!/usr/bin/env python3
"""Per-step analysis of one live stress ramp.

Inputs:
  --raw       k6 CSV output (.csv or .csv.gz) of stress.js
  --summary   stress.js summary JSON (SUMMARY_OUT); gives the start time
  --sampler   server sampler CSV (sampler.sh), optional
  --gen-sampler generator sampler CSV (sampler.sh following k6), optional:
              shows whether the generator, not the server, ran out of CPU
  --start-rate/--step-rate/--steps/--hold-s/--ramp-s  the ramp, as passed to stress.js
  --budget-ms the p99 latency budget for this journey
  --out       report JSON path; a Markdown table goes to stdout

Only the hold period of each step is measured; the ramp-up seconds between
steps are left out. A step's latency is the journey latency (journey_ms),
which for a login is the sum of its four requests.

Definitions (per step):
  offered      the arrival rate the generator was asked to deliver (/s)
  completed    journeys that finished in the hold window, per second
  ok           journeys that succeeded, per second
  error_ratio  failed / finished journeys
  dropped      iterations k6 could not start because every VU was busy:
               the server was too slow to keep up with the offered rate
Knees:
  latency_knee  first step whose p99 exceeds --budget-ms
  error_knee    first step whose error ratio exceeds 1%
  collapse      first step whose error ratio exceeds 50%, or where the
                server process was gone
  sustained     highest offered rate with error ratio <= 1%, p99 within
                budget, and dropped <= 1% of offered
"""
import argparse
import csv
import gzip
import json
import math
import sys
from collections import defaultdict

ERROR_KNEE = 0.01
COLLAPSE = 0.50
DROPPED_LIMIT = 0.01


def percentile(sorted_values, p):
    """Nearest-rank percentile of an ascending list; None when empty."""
    if not sorted_values:
        return None
    rank = max(1, math.ceil(p / 100.0 * len(sorted_values)))
    return sorted_values[rank - 1]


def parse_tags(extra):
    tags = {}
    for pair in (extra or "").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            tags[k] = v
    return tags


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", newline="")
    return open(path, newline="")


def step_of(ts, start_s, step_s, steps, ramp_s):
    """(step, phase) of a wall-clock second, or (None, None) outside the ramp."""
    elapsed = ts - start_s
    if elapsed < 0:
        return None, None
    step = int(elapsed // step_s)
    if step >= steps:
        return None, None
    phase = "ramp" if elapsed - step * step_s < ramp_s else "hold"
    return step, phase


def read_k6(sources, args):
    """Per-step journey latencies, outcomes, failure classes and drops.

    `sources` is a list of (raw CSV path, scenario start in epoch seconds),
    one per generator; the steps of all generators are added together.
    """
    lat = defaultdict(list)
    ok = defaultdict(int)
    failed = defaultdict(int)
    classes = defaultdict(lambda: defaultdict(int))
    dropped = defaultdict(int)
    step_s = args.ramp_s + args.hold_s
    for path, start_s in sources:
        _read_k6_file(path, start_s, step_s, args, lat, ok, failed, classes, dropped)
    return lat, ok, failed, classes, dropped


def _read_k6_file(path, start_s, step_s, args, lat, ok, failed, classes, dropped):
    with open_text(path) as f:
        for row in csv.DictReader(f):
            name = row["metric_name"]
            if name not in ("journey_ms", "journey_ok", "journey_fail", "dropped_iterations"):
                continue
            tags = parse_tags(row.get("extra_tags"))
            if name == "dropped_iterations":
                step, phase = step_of(int(row["timestamp"]), start_s, step_s, args.steps, args.ramp_s)
                if phase == "hold":
                    dropped[step] += int(float(row["metric_value"]))
                continue
            if tags.get("phase") != "hold" or "step" not in tags:
                continue
            step = int(tags["step"])
            value = float(row["metric_value"])
            if name == "journey_ms":
                lat[step].append(value)
            elif name == "journey_ok":
                if value >= 1.0:
                    ok[step] += 1
                else:
                    failed[step] += 1
            else:
                classes[step][tags.get("cls", "?")] += int(value)


def read_sampler(path, start_s, args):
    """Per-step server CPU %, peak RSS, minimum MemAvailable, write IOPS, liveness."""
    out = defaultdict(lambda: {"cpu": [], "rss_kb": [], "mem_avail_kb": [], "w_iops": [], "alive": []})
    step_s = args.ramp_s + args.hold_s
    prev = None
    with open_text(path) as f:
        for row in csv.DictReader(f):
            ts = float(row["ts"])
            cur = {
                "ts": ts,
                "ticks": int(row["cpu_ticks"]) if row["cpu_ticks"] else None,
                "writes": int(row["disk_writes"]),
            }
            step, phase = step_of(int(ts), start_s, step_s, args.steps, args.ramp_s)
            if phase == "hold":
                s = out[step]
                s["alive"].append(int(row["alive"]))
                if row["rss_kb"]:
                    s["rss_kb"].append(int(row["rss_kb"]))
                s["mem_avail_kb"].append(int(row["mem_available_kb"]))
                if prev is not None and cur["ts"] > prev["ts"]:
                    dt = cur["ts"] - prev["ts"]
                    if cur["ticks"] is not None and prev["ticks"] is not None:
                        s["cpu"].append(100.0 * (cur["ticks"] - prev["ticks"]) / int(row["clk_tck"]) / dt)
                    s["w_iops"].append((cur["writes"] - prev["writes"]) / dt)
            prev = cur
    return out


def mean(xs):
    return sum(xs) / len(xs) if xs else None


def as_list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def analyze(args):
    raws, summaries = as_list(args.raw), as_list(args.summary)
    if len(summaries) not in (1, len(raws)):
        sys.exit("analyze: give one --summary, or one per --raw")
    starts = []
    for path in summaries:
        with open(path) as f:
            started_at = json.load(f).get("started_at")
        if started_at is None:
            sys.exit(f"analyze: the ramp never started (setup failed); see {path}")
        starts.append(started_at // 1000)
    if len(starts) == 1:
        starts = starts * len(raws)
    # The samplers are placed in steps from the earliest generator's start.
    start_s = min(starts)
    lat, ok, failed, classes, dropped = read_k6(list(zip(raws, starts)), args)
    server = read_sampler(args.sampler, start_s, args) if args.sampler else {}
    gens = [read_sampler(p, start_s, args) for p in as_list(getattr(args, "gen_sampler", None))]

    rows = []
    for step in range(args.steps):
        offered = args.start_rate + step * args.step_rate
        values = sorted(lat.get(step, []))
        finished = ok.get(step, 0) + failed.get(step, 0)
        if finished == 0 and step not in server:
            continue
        row = {
            "step": step,
            "offered_rps": offered,
            "completed_rps": round(finished / args.hold_s, 1),
            "ok_rps": round(ok.get(step, 0) / args.hold_s, 1),
            "error_ratio": round(failed.get(step, 0) / finished, 4) if finished else None,
            "fail_classes": dict(classes.get(step, {})),
            "dropped": dropped.get(step, 0),
            "dropped_ratio": round(dropped.get(step, 0) / (offered * args.hold_s), 4) if offered else 0,
            "p50_ms": percentile(values, 50),
            "p90_ms": percentile(values, 90),
            "p99_ms": percentile(values, 99),
            "p999_ms": percentile(values, 99.9),
            "max_ms": values[-1] if values else None,
        }
        s = server.get(step)
        if s:
            row.update(
                {
                    "server_cpu_pct_mean": round(mean(s["cpu"]), 1) if s["cpu"] else None,
                    "server_cpu_pct_max": round(max(s["cpu"]), 1) if s["cpu"] else None,
                    "server_rss_mb_max": round(max(s["rss_kb"]) / 1024, 1) if s["rss_kb"] else None,
                    "mem_available_mb_min": round(min(s["mem_avail_kb"]) / 1024, 1),
                    "disk_write_iops_mean": round(mean(s["w_iops"]), 1) if s["w_iops"] else None,
                    "server_alive": min(s["alive"]) == 1 if s["alive"] else None,
                }
            )
        # The busiest generator decides whether the load generation was the limit.
        gen_cpu = [round(mean(g[step]["cpu"]), 1) for g in gens if g.get(step) and g[step]["cpu"]]
        if gen_cpu:
            row["generator_cpu_pct_mean"] = max(gen_cpu)
            row["generator_cpu_pct_by_generator"] = gen_cpu
        rows.append(row)

    def first(pred):
        return next((r["offered_rps"] for r in rows if pred(r)), None)

    knees = {
        "latency_knee_rps": first(lambda r: r["p99_ms"] is not None and r["p99_ms"] > args.budget_ms),
        "error_knee_rps": first(lambda r: r["error_ratio"] is not None and r["error_ratio"] > ERROR_KNEE),
        "collapse_rps": first(
            lambda r: (r["error_ratio"] is not None and r["error_ratio"] > COLLAPSE)
            or r.get("server_alive") is False
        ),
    }
    healthy = [
        r
        for r in rows
        if r["error_ratio"] is not None
        and r["error_ratio"] <= ERROR_KNEE
        and r["p99_ms"] is not None
        and r["p99_ms"] <= args.budget_ms
        and r["dropped_ratio"] <= DROPPED_LIMIT
    ]
    knees["sustained_rps"] = max((r["offered_rps"] for r in healthy), default=None)
    knees["sustained_ok_rps"] = max((r["ok_rps"] for r in healthy), default=None)
    return {
        "journey": args.journey,
        "budget_p99_ms": args.budget_ms,
        "ramp": {
            "start_rps": args.start_rate,
            "step_rps": args.step_rate,
            "steps": args.steps,
            "hold_s": args.hold_s,
            "ramp_s": args.ramp_s,
        },
        "steps": rows,
        **knees,
    }


def fmt(v, nd=1):
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def markdown(report):
    lines = [
        f"### {report['journey']} (p99 budget {report['budget_p99_ms']} ms)",
        "",
        f"Sustained: **{fmt(report['sustained_rps'])} offered/s** "
        f"({fmt(report['sustained_ok_rps'])} ok/s). Latency knee: {fmt(report['latency_knee_rps'])}/s. "
        f"Error knee: {fmt(report['error_knee_rps'])}/s. Collapse: {fmt(report['collapse_rps'])}/s.",
        "",
        "| offered/s | ok/s | errors | dropped | p50 ms | p99 ms | p99.9 ms | max ms | CPU % | RSS MB | free MB | write IOPS | gen CPU % |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in report["steps"]:
        err = "–" if r["error_ratio"] is None else f"{100 * r['error_ratio']:.2f}%"
        lines.append(
            f"| {r['offered_rps']} | {fmt(r['ok_rps'])} | {err} | {r['dropped']} | {fmt(r['p50_ms'], 2)} | "
            f"{fmt(r['p99_ms'], 2)} | {fmt(r['p999_ms'], 2)} | {fmt(r['max_ms'], 0)} | "
            f"{fmt(r.get('server_cpu_pct_mean'))} | {fmt(r.get('server_rss_mb_max'))} | "
            f"{fmt(r.get('mem_available_mb_min'), 0)} | {fmt(r.get('disk_write_iops_mean'), 0)} | "
            f"{fmt(r.get('generator_cpu_pct_mean'))} |"
        )
    classes = defaultdict(int)
    for r in report["steps"]:
        for k, v in r["fail_classes"].items():
            classes[k] += v
    if classes:
        lines += ["", "Failure classes: " + ", ".join(f"`{k}` × {v}" for k, v in sorted(classes.items()))]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--raw", required=True, nargs="+", help="k6 CSV, one per generator")
    p.add_argument("--summary", required=True, nargs="+", help="one, or one per --raw")
    p.add_argument("--sampler")
    p.add_argument("--gen-sampler", nargs="*", help="one per generator")
    p.add_argument("--journey", required=True)
    p.add_argument("--start-rate", type=int, required=True)
    p.add_argument("--step-rate", type=int, required=True)
    p.add_argument("--steps", type=int, required=True)
    p.add_argument("--hold-s", type=int, default=60)
    p.add_argument("--ramp-s", type=int, default=5)
    p.add_argument("--budget-ms", type=float, required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    report = analyze(args)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    sys.stdout.write(markdown(report))


if __name__ == "__main__":
    main()
