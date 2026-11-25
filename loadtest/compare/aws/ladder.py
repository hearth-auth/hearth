"""The step ladder of the same-hardware comparison (#913): the rates of each phase, the
verdict of each step, the clean rate of a journey, and the rule that picks the second
product of size 2. compare.sh calls the command line below; test_ladder.py tests it.

The method, fixed in #913 before any run (one rule changed since: the last one below):

- Start rates: login 2/s; the mix 5/s; refresh, client credentials and user create 25/s;
  userinfo, introspect and admin lookup (and the cold read) 100/s.
- Coarse phase: the rate doubles at each step, at most 8 steps, until the first failing
  step. Fine phase: 3 more steps, evenly spaced between the last clean coarse step and
  the first failing one. The clean rate is the highest clean step of both phases; a
  journey whose 8th coarse step is clean reports "at least" that rate.
- Each phase is one k6 run after a restore, a cache drop and a restart, and starts with
  one warm-up minute at the phase's first rate (step 0, never judged).
- A step is clean when no journey was dropped, errors stay below 0.1 %, the p99 is
  within the journey's budget (cloud.sh collect's), and the server stayed alive.
- Every failed journey is an error, for every product: a 429 or 503 counts, whether it
  is a product's queue-full 503 or a password-hash (KDF) shed such as Hearth's
  `login_submit:503`. Changed on 2026-11-24, after the first Hearth ramp: until then
  Hearth's login sheds did not count, a rule no other product had.

Commands (JSON on stdout):
  ladder.py coarse <journey>                       the coarse rates (/s)
  ladder.py fine <last_clean> <first_fail>         the fine rates (/s)
  ladder.py rates-pm <generators> <rate>...        each rate as total journeys per
                                                   minute, a multiple of <generators>
  ladder.py judge <product> <report.json> <ran> <rate>...
                                                   the verdict of each judged step;
                                                   steps after <ran> (the step the
                                                   run was stopped at; -1: none)
                                                   did not run
  ladder.py live <product> <journey> <now> <start_at> <hold_s> <metrics.json>...
                                                   during a run: {"stop": step} for
                                                   the first finished step that
                                                   fails for sure, else null
  ladder.py ran <verdicts.json>                    the number of the phase's steps that
                                                   ran (0: none, and the journey fails)
  ladder.py journey <product> <journey> <coarse.json> [<fine.json>]
                                                   the journey's result from the two
                                                   phases' report.json
  ladder.py next <product> <coarse.json>           {"fine": [...]} or {"fine": null}
  ladder.py fastest <results.json>                 the fastest other product
  ladder.py seed-minutes <estimate_minutes>        a seed instance's lifetime
judge, live and next take <product> but do not use it: every product gets the same rule.
"""
import json
import math
import sys

START_RATES = {
    "login": 2,
    "mix": 5,
    "refresh": 25,
    "client_credentials": 25,
    "create_user": 25,
    "userinfo": 100,
    "introspect": 100,
    "admin_lookup": 100,
}
# cloud.sh collect's budgets (p99, ms).
BUDGET_MS = {
    "introspect": 50,
    "userinfo": 50,
    "admin_lookup": 50,
    "refresh": 100,
    "create_user": 100,
    "client_credentials": 100,
    "login": 1000,
    "mix": 1000,
}
# The 8 journeys whose clean rates decide the fastest product (#913 journeys 1 to 8).
JOURNEYS = ["login", "refresh", "client_credentials", "userinfo", "introspect",
            "admin_lookup", "create_user", "mix"]
COARSE_STEPS = 8
FINE_STEPS = 3
ERROR_LIMIT = 0.001
# The busiest generator's k6 above this CPU % (of 400 on a c7i.xlarge) means the
# generators, not the server, may have set the limit: the result is flagged.
GENERATOR_BOUND_PCT = 300


def coarse_rates(journey, steps=COARSE_STEPS):
    """The coarse phase: start, 2 x start, 4 x start, ... (journeys/s)."""
    start = START_RATES[journey]
    return [start * 2**k for k in range(steps)]


def fine_rates(last_clean, first_fail, steps=FINE_STEPS):
    """`steps` rates evenly spaced strictly between the last clean coarse rate (0 when
    the first coarse step failed) and the first failing one."""
    lo = last_clean or 0
    if not first_fail > lo:
        raise ValueError(f"the failing rate {first_fail} is not above the clean rate {lo}")
    return [round(lo + (first_fail - lo) * k / (steps + 1), 4) for k in range(1, steps + 1)]


def rates_pm(generators, rates):
    """Each rate (/s) as total journeys per minute, rounded to a multiple of the
    generator count (stress.js RATES_PM splits it evenly); at least one per generator."""
    out = []
    for r in rates:
        per_gen = max(1, round(r * 60 / generators))
        out.append(per_gen * generators)
    return out


def judge_step(row, budget_ms):
    """(clean, reasons) of one analyze.py step row. Every failed journey is an error."""
    reasons = []
    finished = row.get("finished")
    if finished is None:
        # A report from before the counts: rebuild them from the rates.
        finished = round((row.get("completed_rps") or 0) * row.get("hold_s", 60))
    errors = row.get("failed")
    if errors is None:
        errors = round((row.get("error_ratio") or 0) * finished)
    if finished == 0:
        reasons.append("no journey finished")
    elif errors / finished >= ERROR_LIMIT:
        reasons.append(f"errors {errors / finished:.2%}")
    if row.get("dropped", 0) > 0:
        reasons.append(f"{row['dropped']} dropped")
    p99 = row.get("p99_ms")
    if p99 is None or p99 > budget_ms:
        reasons.append(f"p99 {p99} ms > {budget_ms} ms")
    if row.get("server_alive") is False:
        reasons.append("server died")
    return (not reasons, reasons)


def judge(journey, report, rates, ran=-1):
    """The verdict of each judged step of a phase: step i + 1 of the report is rates[i]
    (step 0 is the warm-up minute). A step with no row, or after `ran` when the driver
    stopped the run at step `ran` (-1: it ran to its end), did not run. Judging stops
    at the first failing step: the steps after it do not count. The rule is the same
    for every product."""
    budget = BUDGET_MS[journey]
    rows = {r["step"]: r for r in report.get("steps", []) if ran < 0 or r["step"] <= ran}
    out = []
    for i, rate in enumerate(rates):
        row = rows.get(i + 1)
        if row is None:
            out.append({"rate": rate, "clean": None, "reasons": ["not run"]})
            break
        clean, reasons = judge_step(row, budget)
        out.append({
            "rate": rate,
            "clean": clean,
            "reasons": reasons,
            "p99_ms": row.get("p99_ms"),
            "error_ratio": row.get("error_ratio"),
            "fail_classes": row.get("fail_classes"),
            "dropped": row.get("dropped"),
            "server_cpu_pct_mean": row.get("server_cpu_pct_mean"),
            "server_rss_mb_max": row.get("server_rss_mb_max"),
            "disk_write_iops_mean": row.get("disk_write_iops_mean"),
            "disk_write_mbps_mean": row.get("disk_write_mbps_mean"),
            "generator_cpu_pct_mean": row.get("generator_cpu_pct_mean"),
        })
        if not clean:
            break
    return out


# A live stop needs a step that fails for sure: its p95 (k6's REST API has no p99)
# above the budget, or 1 % of its journeys failed (ten times the clean limit). A step
# that fails only on its p99 or a few errors runs on; the judge (above) decides after
# the run, and the steps after its first failing one do not count.
LIVE_ERROR_LIMIT = 0.01
RAMP_S = 5


def live_stop(journey, metrics, now, start_at, hold_s=60, ramp_s=RAMP_S):
    """The first judged step (>= 1) that has finished and fails for sure on any
    generator, or None. `metrics` is one k6 /v1/metrics answer per generator. The rule
    is the same for every product and journey."""
    budget = BUDGET_MS[journey]
    step_s = ramp_s + hold_s
    finished = int((now - start_at) // step_s)  # steps 0 .. finished-1 are over
    for step in range(1, finished):
        for m in metrics:
            by_id = {d["id"]: d["attributes"]["sample"] for d in m.get("data", [])}
            lat = by_id.get(f"journey_ms{{step:{step},phase:hold}}", {})
            ok = by_id.get(f"journey_ok{{step:{step},phase:hold}}", {})
            if (lat.get("p(95)") or 0) > budget:
                return step
            if ok.get("rate") is not None and ok["rate"] < 1 - LIVE_ERROR_LIMIT:
                return step
    return None


def steps_run(verdicts):
    """The number of a phase's steps that ran, clean or not. 0: k6 never ran a step (it did
    not start, say), and compare.sh fails the journey rather than report a clean rate of 0."""
    return sum(1 for v in verdicts if v["clean"] is not None)


def next_phase(verdicts):
    """After the coarse phase: the fine rates, or None (the 8th step was clean, or the
    coarse run ended before a failing step: then the coarse phase must go on)."""
    fail = next((v for v in verdicts if v["clean"] is False), None)
    if fail is None:
        return None
    clean = [v["rate"] for v in verdicts if v["clean"]]
    return fine_rates(clean[-1] if clean else 0, fail["rate"])


def resume_from(journey, verdicts):
    """The coarse rates still to run when a coarse run ended before its first failing
    step and before the 8th step (a lost run, a generator restart): [] when none."""
    if any(v["clean"] is False for v in verdicts):
        return []
    done = [v["rate"] for v in verdicts if v["clean"]]
    return [r for r in coarse_rates(journey) if r not in done]


def journey_result(product, journey, coarse, fine=None):
    """The result of one journey from the verdicts of its two phases."""
    steps = coarse + (fine or [])
    clean = [v for v in steps if v["clean"]]
    best = max(clean, key=lambda v: v["rate"]) if clean else None
    coarse_clean = [v for v in coarse if v["clean"]]
    at_least = len(coarse_clean) == COARSE_STEPS
    # Monotonic: no clean step above a failing one.
    fails = [v["rate"] for v in steps if v["clean"] is False]
    non_monotonic = bool(best and fails and best["rate"] > min(fails))
    gen_bound = bool(best and (best.get("generator_cpu_pct_mean") or 0) > GENERATOR_BOUND_PCT)
    return {
        "product": product,
        "journey": journey,
        "clean_rate": best["rate"] if best else 0,
        "at_least": at_least,
        "p99_ms": best.get("p99_ms") if best else None,
        "server_cpu_pct_mean": best.get("server_cpu_pct_mean") if best else None,
        "server_rss_mb_max": best.get("server_rss_mb_max") if best else None,
        "disk_write_iops_mean": best.get("disk_write_iops_mean") if best else None,
        "disk_write_mbps_mean": best.get("disk_write_mbps_mean") if best else None,
        "flags": [f for f, on in (("non-monotonic", non_monotonic),
                                  ("generator-bound", gen_bound)) if on],
        "steps": steps,
    }


def geomean(xs):
    """Geometric mean; 0 when any value is 0 or missing."""
    if not xs or any(not x or x <= 0 for x in xs):
        return 0.0
    return math.exp(sum(math.log(x) for x in xs) / len(xs))


def fastest(results, exclude="hearth"):
    """The product other than `exclude` with the highest geometric mean of clean rates
    over the 8 journeys at size 1 (#913's rule for the second product of size 2).
    `results` maps product -> journey -> clean rate (a missing journey counts as 0).
    A product with a 0 has geometric mean 0; ties go to the product with more clean
    journeys, then to the higher geometric mean over its clean journeys, then by name."""
    ranked = []
    for product, by_journey in results.items():
        if product == exclude:
            continue
        rates = [by_journey.get(j) or 0 for j in JOURNEYS]
        nonzero = [r for r in rates if r > 0]
        ranked.append((geomean(rates), len(nonzero), geomean(nonzero), product))
    if not ranked:
        raise ValueError("no product besides " + exclude)
    ranked.sort(key=lambda t: (-t[0], -t[1], -t[2], t[3]))
    g, n, g_nz, product = ranked[0]
    return {"product": product, "geomean": round(g, 3), "clean_journeys": n,
            "ranking": [{"product": p, "geomean": round(a, 3), "clean_journeys": b}
                        for a, b, _, p in ranked]}


def seed_minutes(estimate_minutes, cap=960):
    """A seed instance's lifetime (#913): its estimate plus 50 %, at most 16 h."""
    if estimate_minutes <= 0:
        raise ValueError("the seed estimate must be positive")
    return min(math.ceil(estimate_minutes * 1.5), cap)


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    a = argv[2:]
    if cmd == "coarse":
        out = coarse_rates(a[0])
    elif cmd == "fine":
        out = fine_rates(float(a[0]), float(a[1]))
    elif cmd == "rates-pm":
        out = rates_pm(int(a[0]), [float(x) for x in a[1:]])
    elif cmd == "judge":
        # a[0] is the product: compare.sh names it, the rule does not use it.
        report = json.load(open(a[1]))
        out = judge(report["journey"], report, [float(x) for x in a[3:]], int(a[2]))
    elif cmd == "live":
        metrics = []
        for path in a[5:]:
            try:
                metrics.append(json.load(open(path)))
            except (OSError, ValueError):
                pass  # a generator whose k6 has ended or not started
        # a[0] is the product, unused like judge's.
        out = {"stop": live_stop(a[1], metrics, float(a[2]), float(a[3]), int(a[4]))}
    elif cmd == "ran":
        out = steps_run(json.load(open(a[0])))
    elif cmd == "next":
        out = {"fine": next_phase(json.load(open(a[1])))}
    elif cmd == "resume":
        out = resume_from(a[0], json.load(open(a[1])))
    elif cmd == "journey":
        coarse = json.load(open(a[2]))
        fine = json.load(open(a[3])) if len(a) > 3 else None
        out = journey_result(a[0], a[1], coarse, fine)
    elif cmd == "fastest":
        out = fastest(json.load(open(a[0])))
    elif cmd == "seed-minutes":
        out = seed_minutes(float(a[0]))
    else:
        sys.exit(__doc__)
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
