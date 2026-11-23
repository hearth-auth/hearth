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
  cost.py total <ledger>                                  {"total": ..., "items": [...]}
  cost.py check <ledger> <stop_at>                        exit 3 when total >= stop_at
  cost.py estimate <plan.json>                            the plan's hours and cost per part
"""
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


def append(path, entry):
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


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
        json.dump(total(read_ledger(a[0]), prices, now), sys.stdout)
        sys.stdout.write("\n")
    elif cmd == "check":
        t = total(read_ledger(a[0]), prices, now)["total"]
        print(f"{t:.2f}")
        if t >= float(a[1]):
            sys.exit(3)
    elif cmd == "estimate":
        json.dump(estimate(json.load(open(a[0])), prices), sys.stdout, indent=1)
        sys.stdout.write("\n")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
