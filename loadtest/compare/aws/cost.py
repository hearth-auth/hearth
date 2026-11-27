"""The running cost of a #913 session: a ledger of what compare.sh started, priced
with prices.json (on-demand us-east-1, with sources). Conservative: an instance
counts from before its `up` until after its `down` has confirmed the termination,
with its public IPv4 address and its root volume; a data volume from its creation
until its deletion; a snapshot for a whole month (AWS bills snapshot storage by the
GB-month, prorated, but a kept snapshot keeps costing until it is deleted).

The ledger is one JSON object per line:
  {"kind": "instance", "id": ..., "type": "c7i.large", "disk_gb": 30, "start": t, "end": t|null}
  {"kind": "volume", "id": ..., "gb": 20, "start": t, "end": t|null}
  {"kind": "snapshot", "id": ..., "gb": 12, "start": t, "end": t|null}
  {"kind": "data_out", "bytes": n}
t is epoch seconds; an open entry (end null) counts until `now`.

Commands:
  cost.py start <ledger> <kind> <id> <type-or-gb> [disk_gb]   open an entry (now)
  cost.py end <ledger> <id>                               close it (now)
  cost.py data-out <ledger> <bytes>                       results fetched
  cost.py total <ledger> [carried...]                     {"total": ..., "session": ..., "carried":
                                                          {<ledger>: ...}, "items": [...]}
  cost.py check <ledger> <stop_at> [carried...]           exit 3 when total >= stop_at
  cost.py estimate <plan.json>                            the plan's hours and cost per part,
                                                          its wall clock and AWS logins
  cost.py brief <plan.json>                               the same in a few lines, and
                                                          the wall clock by MAX_VCPU
  cost.py part <plan.json> <part id>                      "<hours> <vcpus> <usd>"
  cost.py remaining <parts file> <plan.json> [id]         the estimate still to come of the
                                                          parts running (but part <id>)
  cost.py after <plan.json>                               "<part id> <the ids it comes after>..."
                                                          per part, in plan order
LOGIN_WINDOW_H, LOGIN_MARGIN_MIN and MAX_VCPU override the plan's login window,
margin and vCPU limit.

A session after another one (the variants after 913a: variants-plan.json's
base_session) keeps its own ledger and carries the other's: the carried ledgers
of `total` and `check` add their totals, so the stop and the cap count what the
comparison spent in all. `brief` prints a carried total from CARRIED_USD
(CARRIED_FROM says where it comes from), else the plan's base_spent_usd.
"""
import fcntl
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def load_prices(path=None):
    with open(path or os.path.join(HERE, "prices.json")) as f:
        return json.load(f)


def read_ledger(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def fold(entries):
    """Entries by id, the later line winning field by field (an `end` closes)."""
    out, order = {}, []
    for e in entries:
        key = e.get("id") or f"_{len(order)}"
        if key not in out:
            out[key] = {}
            order.append(key)
        out[key].update(e)
    return [out[k] for k in order]


def hours(entry, now):
    end = entry.get("end") or now
    return max(0.0, end - entry["start"]) / 3600


def instance_hours_billed(h):
    """EC2 Linux on-demand bills per second with a 60 s minimum."""
    return max(h, 60 / 3600)


def item_cost(e, prices, now):
    month = prices["hours_per_month"]
    kind = e["kind"]
    if kind == "instance":
        h = instance_hours_billed(hours(e, now))
        rate = prices["instance_hour"].get(e["type"])
        if rate is None:
            raise KeyError(f"no price for instance type {e['type']} in prices.json")
        return h * (rate + prices["public_ipv4_hour"]) + e.get("disk_gb", 0) * prices["gp3_gb_month"] * h / month
    if kind == "volume":
        return e["gb"] * prices["gp3_gb_month"] * hours(e, now) / month
    if kind == "snapshot":
        # A whole month: deleting it early saves the rest, but the ledger does not
        # count on that.
        return e["gb"] * prices["snapshot_gb_month"] * max(hours(e, now), month) / month
    if kind == "data_out":
        return e["bytes"] / 1e9 * prices["data_out_gb"]
    raise ValueError(f"unknown ledger kind {kind}")


def total(entries, prices, now=None):
    now = time.time() if now is None else now
    items = []
    for e in fold(entries):
        items.append({**e, "cost": round(item_cost(e, prices, now), 4)})
    return {"total": round(sum(i["cost"] for i in items), 4), "items": items}


def carried_total(paths, prices, now):
    """The totals of the ledgers a session carries, by path."""
    return {p: total(read_ledger(p), prices, now)["total"] for p in paths}


def append(path, entry):
    """One line, under an exclusive lock: several parts write the ledger at once."""
    with open(path, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(entry) + "\n")
        f.flush()


def estimate(plan, prices):
    """Hours and cost of each part of a plan: {"parts": [{"name", "hours",
    "instances": {"c7i.large": 1, ...}, "disk_gb": 30, "volume_gb": 0,
    "snapshot_gb": 0, "data_out_gb": 0}]}. Disk is per instance; a snapshot counts
    one month."""
    month = prices["hours_per_month"]
    out = []
    for p in plan["parts"]:
        h = p["hours"]
        inst = sum(n * (prices["instance_hour"][t] + prices["public_ipv4_hour"]) for t, n in p["instances"].items())
        n = sum(p["instances"].values())
        disk = n * p.get("disk_gb", 30) * prices["gp3_gb_month"] / month
        vol = p.get("volume_gb", 0) * prices["gp3_gb_month"] / month
        cost = (h * (inst + disk + vol) + p.get("snapshot_gb", 0) * prices["snapshot_gb_month"]
                + p.get("data_out_gb", 0) * prices["data_out_gb"])
        out.append({"name": p["name"], "hours": h, "per_hour": round(inst + disk + vol, 4),
                    "cost": round(cost, 2)})
    return {"parts": out, "total": round(sum(p["cost"] for p in out), 2),
            "hours": round(sum(p["hours"] for p in out), 2)}


def part_vcpu(part, plan):
    """The vCPUs of a part's instances (what counts toward the EC2 quota)."""
    return sum(n * plan["vcpu"][t] for t, n in part["instances"].items())


def depends_on(part, other):
    """Whether `part` comes after `other` ("s1:*" is every s1 part)."""
    for a in part.get("after", []):
        if a == other["id"] or (a.endswith(":*") and other["id"].startswith(a[:-1])):
            return True
    return False


def after(plan):
    """Each part with an id, in plan order, with the ids of the parts it comes after
    ("s1:*" expanded): compare.sh session starts a part once they are all done, and
    skips it once one of them has failed or was skipped."""
    parts = [p for p in plan["parts"] if p.get("id")]
    return [(p["id"], [o["id"] for o in parts if depends_on(p, o)]) for p in parts]


def schedule(plan, window_h, margin_h, max_vcpu):
    """The session's wall clock and its AWS logins, as compare.sh session runs the
    plan: every part starts as soon as the parts it comes after ("after") are done,
    its vCPUs fit under max_vcpu with the parts running, and its hours plus the
    teardown margin end inside the current login's window. Parts that could start
    together start in plan order. When nothing runs and nothing can start, the
    session has stopped for a new login, which starts then."""
    parts = [p for p in plan["parts"] if p["hours"] > 0]
    for p in parts:
        if p["hours"] + margin_h > window_h:
            raise ValueError(f"{p['name']}: {p['hours']} h plus the margin does not fit a {window_h} h login")
        if part_vcpu(p, plan) > max_vcpu:
            raise ValueError(f"{p['name']}: {part_vcpu(p, plan)} vCPUs is more than MAX_VCPU {max_vcpu}")
    pending, running, done = list(parts), {}, set()
    logins = [{"start_h": 0.0, "parts": []}]
    t, used, peak = 0.0, 0, 0
    while pending or running:
        for p in list(pending):
            deps = [o["id"] for o in parts if depends_on(p, o)]
            v = part_vcpu(p, plan)
            if (all(d in done for d in deps) and used + v <= max_vcpu
                    and t + p["hours"] + margin_h <= logins[-1]["start_h"] + window_h):
                running[p["id"]] = (t + p["hours"], v)
                used += v
                peak = max(peak, used)
                pending.remove(p)
                logins[-1]["parts"].append(p["name"])
        if running:
            t = min(end for end, _ in running.values())
            for i, (end, v) in list(running.items()):
                if end <= t:
                    del running[i]
                    done.add(i)
                    used -= v
        elif pending:
            logins.append({"start_h": t, "parts": []})
    for i in logins:
        i["start_h"] = round(i["start_h"], 2)
    return {"wall_clock_h": round(t, 2), "logins": len(logins), "max_vcpu": max_vcpu, "peak_vcpu": peak,
            "login_window_h": window_h, "margin_h": margin_h, "per_login": logins}


def login_settings(plan):
    """The login window and the teardown margin (hours): LOGIN_WINDOW_H and
    LOGIN_MARGIN_MIN, else the plan's "login"."""
    lg = plan.get("login", {})
    window = float(os.environ.get("LOGIN_WINDOW_H") or lg.get("window_h", 11.5))
    margin = float(os.environ.get("LOGIN_MARGIN_MIN") or lg.get("margin_min", 15)) / 60
    return window, margin


def max_vcpu(plan):
    return int(os.environ.get("MAX_VCPU") or plan.get("max_vcpu", 32))


def brief(plan, prices):
    """compare.sh plan's summary lines."""
    e = estimate(plan, prices)
    window, margin = login_settings(plan)
    lines = [f"cost: about ${e['total']} (stop at ${plan['stop_usd']}, a part that would pass "
             f"${plan['cap_usd']} does not start); {e['hours']} instance-set hours"]
    if plan.get("base_session"):
        if os.environ.get("CARRIED_USD"):
            carried = float(os.environ["CARRIED_USD"])
            source = os.environ.get("CARRIED_FROM") or f"session {plan['base_session']}"
        else:
            carried = plan["base_spent_usd"]
            source = (f"session {plan['base_session']} at its end, from the plan: its ledger is not "
                      "on this machine")
        left = round(plan["cap_usd"] - carried, 2)
        lines += [f"carried: ${carried:.2f} ({source}); the stop and the cap count it",
                  f"this session may spend ${left:.2f} of the ${plan['cap_usd']} cap; this plan: about "
                  f"${e['total']} ({'fits' if e['total'] <= left else 'DOES NOT FIT'})"]
    lines += [f"  {p['name']}: about ${p['cost']} ({p['hours']} h)" for p in e["parts"]]
    try:
        s = schedule(plan, window, margin, max_vcpu(plan))
    except ValueError as err:
        return "\n".join(lines + [f"the plan does not fit: {err}"])
    lines += [f"wall clock: about {s['wall_clock_h']} h with MAX_VCPU {s['max_vcpu']} (the parts in parallel; "
              f"at most {s['peak_vcpu']} vCPUs at once)",
              f"aws logins: {s['logins']} (a login lasts {s['login_window_h']} h; a part starts only if it "
              f"ends {round(s['margin_h'] * 60)} min before)"]
    for n, i in enumerate(s["per_login"], 1):
        lines.append(f"  login {n} at +{i['start_h']} h: " + "; ".join(i["parts"]))
    other = []
    for v in (24, 32, 48, 64, 96):
        try:
            o = schedule(plan, window, margin, v)
            other.append(f"{v}: {o['wall_clock_h']} h, {o['logins']} login(s)")
        except ValueError:
            other.append(f"{v}: does not fit")
    lines.append("wall clock by MAX_VCPU: " + "; ".join(other))
    return "\n".join(lines)


def remaining(path, prices, plan, now, exclude=""):
    """The estimate (USD) still to come of the parts running: each line of the
    parts file is "<id> <usd> <hours> <start epoch>"; a part's estimate is spent
    evenly over its hours (an overrun counts 0; the stop at stop_usd covers it)."""
    total = 0.0
    if os.path.exists(path):
        for line in open(path):
            f = line.split()
            if len(f) == 4 and f[0] != exclude:
                usd, h, start = float(f[1]), float(f[2]), float(f[3])
                total += usd * max(0.0, 1 - (now - start) / (h * 3600)) if h > 0 else 0.0
    return round(total, 4)


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    a = argv[2:]
    prices = load_prices(os.environ.get("PRICES"))
    now = float(os.environ["COST_NOW"]) if os.environ.get("COST_NOW") else time.time()
    if cmd == "start":
        ledger, kind, ident, what = a[0], a[1], a[2], a[3]
        e = {"kind": kind, "id": ident, "start": now, "end": None}
        if kind == "instance":
            e.update(type=what, disk_gb=int(a[4]) if len(a) > 4 else 30)
            if what not in prices["instance_hour"]:
                sys.exit(f"cost: no price for {what} in prices.json")
        else:
            e["gb"] = float(what)
        append(ledger, e)
    elif cmd == "end":
        append(a[0], {"id": a[1], "end": now})
    elif cmd == "data-out":
        append(a[0], {"kind": "data_out", "bytes": int(a[1])})
    elif cmd == "total":
        t = total(read_ledger(a[0]), prices, now)
        carried = carried_total(a[1:], prices, now)
        t = {"total": round(t["total"] + sum(carried.values()), 4), "session": t["total"],
             "carried": carried, "items": t["items"]}
        json.dump(t, sys.stdout)
        sys.stdout.write("\n")
    elif cmd == "check":
        t = total(read_ledger(a[0]), prices, now)["total"] + sum(carried_total(a[2:], prices, now).values())
        print(f"{t:.2f}")
        if t >= float(a[1]):
            sys.exit(3)
    elif cmd == "estimate":
        plan = json.load(open(a[0]))
        e = estimate(plan, prices)
        try:
            e["schedule"] = schedule(plan, *login_settings(plan), max_vcpu(plan))
        except ValueError as err:
            e["schedule"] = {"error": str(err)}
        json.dump(e, sys.stdout, indent=1)
        sys.stdout.write("\n")
    elif cmd == "brief":
        print(brief(json.load(open(a[0])), prices))
    elif cmd == "part":
        plan = json.load(open(a[0]))
        est = {p["name"]: p["cost"] for p in estimate(plan, prices)["parts"]}
        p = next(p for p in plan["parts"] if p.get("id") == a[1])
        print(p["hours"], part_vcpu(p, plan), est[p["name"]])
    elif cmd == "remaining":
        plan = json.load(open(a[1]))
        print(remaining(a[0], prices, plan, now, a[2] if len(a) > 2 else ""))
    elif cmd == "after":
        for ident, deps in after(json.load(open(a[0]))):
            print(" ".join([ident, *deps]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
