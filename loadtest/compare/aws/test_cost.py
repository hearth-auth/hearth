"""Tests for cost.py: the #913 session's cost ledger and the plan estimate.

Usage: python3 -I loadtest/compare/aws/test_cost.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cost  # noqa: E402

PRICES = cost.load_prices()
H = 3600


class Prices(unittest.TestCase):
    def test_the_table_covers_every_size_of_the_session_and_cites_sources(self):
        for t in ("c7i.large", "c7i.xlarge", "c7i.2xlarge", "r7i.large"):
            self.assertGreater(PRICES["instance_hour"][t], 0)
        for k in ("instance_hour", "gp3_gb_month", "snapshot_gb_month", "public_ipv4_hour"):
            self.assertIn("https://", PRICES["sources"][k])
        self.assertEqual(PRICES["region"], "us-east-1")
        self.assertRegex(PRICES["fetched"], r"^\d{4}-\d\d-\d\d$")


class Ledger(unittest.TestCase):
    def test_an_instance_costs_hours_times_price_plus_its_address_and_disk(self):
        e = {"kind": "instance", "id": "i-1", "type": "c7i.large", "disk_gb": 30, "start": 0, "end": 2 * H}
        got = cost.total([e], PRICES)["total"]
        want = 2 * (0.08925 + 0.005) + 30 * 0.08 * 2 / 730
        self.assertAlmostEqual(got, want, places=4)

    def test_an_open_entry_counts_until_now_and_the_end_line_closes_it(self):
        entries = [{"kind": "instance", "id": "i-1", "type": "c7i.xlarge", "disk_gb": 0, "start": 0, "end": None}]
        self.assertAlmostEqual(cost.total(entries, PRICES, now=H)["total"], 0.1835, places=4)
        entries.append({"id": "i-1", "end": H / 2})
        self.assertAlmostEqual(cost.total(entries, PRICES, now=10 * H)["total"], 0.1835 / 2, places=4)

    def test_a_short_instance_bills_at_least_a_minute(self):
        e = {"kind": "instance", "id": "i-1", "type": "c7i.2xlarge", "disk_gb": 0, "start": 0, "end": 1}
        self.assertAlmostEqual(cost.total([e], PRICES)["total"], (0.357 + 0.005) / 60, places=4)

    def test_volumes_snapshots_and_data_out(self):
        entries = [
            {"kind": "volume", "id": "vol-1", "gb": 73, "start": 0, "end": 10 * H},
            {"kind": "snapshot", "id": "snap-1", "gb": 10, "start": 0, "end": H},
            {"kind": "data_out", "bytes": 2 * 10**9},
        ]
        items = {i.get("id", i["kind"]): i["cost"] for i in cost.total(entries, PRICES)["items"]}
        self.assertAlmostEqual(items["vol-1"], 73 * 0.08 * 10 / 730, places=4)
        # A snapshot counts a whole month, however soon it is deleted.
        self.assertAlmostEqual(items["snap-1"], 10 * 0.05, places=4)
        self.assertAlmostEqual(items["data_out"], 2 * PRICES["data_out_gb"], places=4)

    def test_an_unknown_instance_type_is_refused(self):
        e = {"kind": "instance", "id": "i-1", "type": "m7i.48xlarge", "start": 0, "end": 1}
        with self.assertRaises(KeyError):
            cost.total([e], PRICES)

    def test_the_command_line_stops_at_the_limit(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            env = dict(os.environ, COST_NOW="0")
            run = lambda *a, **kw: subprocess.run(  # noqa: E731
                [sys.executable, "-I", os.path.join(HERE, "cost.py"), *a],
                env=kw.get("env", env), capture_output=True, text=True)
            self.assertEqual(run("start", ledger, "instance", "i-1", "c7i.2xlarge", "30").returncode, 0)
            # 10 h later: about $3.66.
            later = dict(env, COST_NOW=str(10 * H))
            ok = run("check", ledger, "20", env=later)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertAlmostEqual(float(ok.stdout), 10 * 0.362 + 30 * 0.08 * 10 / 730, places=2)
            stop = run("check", ledger, "3", env=later)
            self.assertEqual(stop.returncode, 3)
            run("end", ledger, "i-1", env=dict(env, COST_NOW=str(H)))
            self.assertEqual(run("check", ledger, "3", env=later).returncode, 0)
            self.assertNotEqual(run("start", ledger, "instance", "i-2", "m7i.large").returncode, 0)


class Estimate(unittest.TestCase):
    def test_parts_add_up(self):
        plan = {"parts": [
            {"name": "a", "hours": 2, "instances": {"c7i.large": 1, "c7i.xlarge": 2}, "disk_gb": 0},
            {"name": "b", "hours": 1, "instances": {"c7i.large": 1}, "disk_gb": 0, "snapshot_gb": 10},
        ]}
        e = cost.estimate(plan, PRICES)
        self.assertAlmostEqual(e["parts"][0]["cost"], round(2 * (0.08925 + 2 * 0.1785 + 3 * 0.005), 2))
        self.assertAlmostEqual(e["parts"][1]["cost"], round(0.09425 + 0.5, 2))
        self.assertEqual(e["hours"], 3)

    def test_the_session_plan_fits_the_cap(self):
        plan = json.load(open(os.path.join(HERE, "session-plan.json")))
        e = cost.estimate(plan, PRICES)
        self.assertLessEqual(e["total"], plan["cap_usd"])
        self.assertLessEqual(e["total"], plan["stop_usd"])
        self.assertEqual(plan["stop_usd"], 20)

    def test_the_seed_parts_match_the_model(self):
        plan = json.load(open(os.path.join(HERE, "session-plan.json")))
        m = plan["model"]
        for p in plan["parts"]:
            if p.get("id", "").startswith("seed:"):
                product = p["id"].split(":")[1]
                self.assertEqual(p["hours"], m["seed_hours"][product], p["name"])
                server = m["seed_server"].get(product, m["seed_server"]["default"])
                self.assertEqual(p["instances"], {server: 1}, p["name"])
        self.assertEqual(m["seed_server"]["authentik"], "c7i.2xlarge")


VCPU = {"vcpu": {"c7i.large": 2, "c7i.xlarge": 4}}


def part(i, hours, after=(), vcpu=2):
    return {"id": i, "name": i, "hours": hours, "after": list(after),
            "instances": {"c7i.large": vcpu // 2}}


class Schedule(unittest.TestCase):
    def test_parts_run_in_parallel_after_what_they_need(self):
        plan = {**VCPU, "parts": [part("seed:a", 1), part("seed:b", 3), part("s1:a", 2, ["seed:a"]),
                                  part("s1:b", 2, ["seed:b"]), part("drill", 4), part("s2:x", 1, ["s1:*"])]}
        s = cost.schedule(plan, 100, 0, 100)
        # s1:a 1..3 and s1:b 3..5 overlap the drill 0..4; s2:x after both s1: 5..6.
        self.assertEqual(s["wall_clock_h"], 6)
        self.assertEqual(s["logins"], 1)
        self.assertEqual(s["peak_vcpu"], 6)

    def test_a_part_waits_while_it_would_pass_max_vcpu(self):
        plan = {**VCPU, "parts": [part("a", 2, vcpu=4), part("b", 1, vcpu=4), part("c", 1, vcpu=2)]}
        s = cost.schedule(plan, 100, 0, 6)
        # a (4) and c (2) start at 0; b (4) waits for a: 2..3.
        self.assertEqual(s["wall_clock_h"], 3)
        self.assertEqual(s["peak_vcpu"], 6)

    def test_a_part_that_would_pass_the_window_waits_for_a_new_login(self):
        plan = {**VCPU, "parts": [part("a", 1), part("b", 4.5), part("x", 4, ["a"])]}
        s = cost.schedule(plan, 6, 0.5, 100)
        # a 0..1, b 0..4.5; x at 1 ends at 5, plus 0.5: inside a 6 h login.
        self.assertEqual(s["logins"], 1)
        # In a 5.4 h login it does not fit: the session waits for b (4.5), then
        # login 2: x 4.5..8.5.
        s = cost.schedule(plan, 5.4, 0.5, 100)
        self.assertEqual([i["start_h"] for i in s["per_login"]], [0, 4.5])
        self.assertEqual(s["per_login"][1]["parts"], ["x"])
        self.assertEqual(s["wall_clock_h"], 8.5)

    def test_a_part_longer_than_a_login_or_max_vcpu_is_refused(self):
        with self.assertRaises(ValueError):
            cost.schedule({**VCPU, "parts": [part("x", 12)]}, 11.5, 0.25, 100)
        with self.assertRaises(ValueError):
            cost.schedule({**VCPU, "parts": [part("x", 1, vcpu=8)]}, 11.5, 0.25, 6)

    def test_the_session_plan_runs_in_one_login_at_56_vcpus(self):
        plan = json.load(open(os.path.join(HERE, "session-plan.json")))
        window, margin = cost.login_settings(plan)
        s = cost.schedule(plan, window, margin, 56)
        self.assertEqual(s["logins"], 1)
        self.assertAlmostEqual(s["wall_clock_h"], 10.7, places=1)
        self.assertLessEqual(s["peak_vcpu"], 56)
        # A smaller quota is slower, never wrong.
        self.assertGreater(cost.schedule(plan, window, margin, 24)["wall_clock_h"], s["wall_clock_h"])


class Remaining(unittest.TestCase):
    def test_the_running_parts_estimate_still_to_come(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "parts.active")
            with open(f, "w") as out:
                out.write("s1:a 2.0 4 0\n")      # half done at 2 h: $1 to come
                out.write("seed:b 1.0 1 0\n")    # overrun at 2 h: 0
                out.write("s1:c 3.0 2 7200\n")   # just started: $3
            self.assertAlmostEqual(cost.remaining(f, PRICES, {}, 2 * H), 4.0)
            self.assertAlmostEqual(cost.remaining(f, PRICES, {}, 2 * H, "s1:c"), 1.0)
            self.assertEqual(cost.remaining(os.path.join(d, "none"), PRICES, {}, 0), 0)


if __name__ == "__main__":
    unittest.main()
