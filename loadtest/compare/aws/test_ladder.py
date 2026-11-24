"""Tests for ladder.py: the #913 step ladder, the step verdicts, the clean rate, the
fastest-product rule and the seed lifetime.

Usage: python3 -I loadtest/compare/aws/test_ladder.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ladder  # noqa: E402


def row(step, p99=10.0, finished=6000, failed=0, classes=None, dropped=0, alive=True, gen=100.0):
    return {"step": step, "p99_ms": p99, "finished": finished, "failed": failed,
            "error_ratio": failed / finished if finished else None,
            "fail_classes": classes or {}, "dropped": dropped, "server_alive": alive,
            "server_cpu_pct_mean": 150.0, "server_rss_mb_max": 300.0,
            "disk_write_iops_mean": 40.0, "disk_write_mbps_mean": 1.5,
            "generator_cpu_pct_mean": gen}


def report(journey, rows):
    return {"journey": journey, "steps": rows}


class Rates(unittest.TestCase):
    def test_coarse_doubles_from_the_fixed_start_rates(self):
        self.assertEqual(ladder.coarse_rates("login"), [2, 4, 8, 16, 32, 64, 128, 256])
        self.assertEqual(ladder.coarse_rates("mix")[:3], [5, 10, 20])
        for j in ("refresh", "client_credentials", "create_user"):
            self.assertEqual(ladder.coarse_rates(j)[0], 25)
        for j in ("userinfo", "introspect", "admin_lookup"):
            self.assertEqual(ladder.coarse_rates(j)[-1], 100 * 128)
        self.assertEqual(len(ladder.coarse_rates("refresh")), 8)

    def test_fine_steps_are_evenly_between_last_clean_and_first_fail(self):
        self.assertEqual(ladder.fine_rates(200, 400), [250, 300, 350])
        self.assertEqual(ladder.fine_rates(2, 4), [2.5, 3, 3.5])
        # The first coarse step failed: from 0.
        self.assertEqual(ladder.fine_rates(0, 2), [0.5, 1, 1.5])
        with self.assertRaises(ValueError):
            ladder.fine_rates(4, 4)

    def test_rates_per_minute_split_evenly_over_the_generators(self):
        self.assertEqual(ladder.rates_pm(2, [2, 2.5, 100]), [120, 150, 6000])
        # 0.5/s over 4 generators: 30/min is not a multiple of 4; rounded per generator.
        self.assertEqual(ladder.rates_pm(4, [0.5]), [32])
        for pm in ladder.rates_pm(4, [0.5, 1.75, 3.3]):
            self.assertEqual(pm % 4, 0)
        self.assertEqual(ladder.rates_pm(2, [0.001]), [2])


class Judge(unittest.TestCase):
    def test_a_clean_step(self):
        self.assertEqual(ladder.judge_step(row(1), 50), (True, []))

    def test_each_rule_fails_a_step(self):
        self.assertFalse(ladder.judge_step(row(1, p99=50.1), 50)[0])
        self.assertTrue(ladder.judge_step(row(1, p99=50.0), 50)[0])
        # 0.1 % errors fails, 0.09 % passes.
        self.assertFalse(ladder.judge_step(row(1, finished=10000, failed=10), 50)[0])
        self.assertTrue(ladder.judge_step(row(1, finished=10000, failed=9), 50)[0])
        self.assertFalse(ladder.judge_step(row(1, dropped=1), 50)[0])
        self.assertFalse(ladder.judge_step(row(1, alive=False), 50)[0])
        self.assertFalse(ladder.judge_step(row(1, finished=0, p99=None), 50)[0])

    def test_only_hearths_kdf_sheds_are_not_errors(self):
        r = row(1, finished=1000, failed=50, classes={"login_submit:503": 50})
        self.assertTrue(ladder.judge_step(r, 1000, ladder.SHED_CLASSES["hearth"])[0])
        # The same 503s from another product: its queue is full, an error.
        self.assertFalse(ladder.judge_step(r, 1000, ladder.SHED_CLASSES.get("keycloak", set()))[0])
        # A shed plus a real error.
        r = row(1, finished=1000, failed=52, classes={"login_submit:503": 50, "code_exchange:500": 2})
        self.assertFalse(ladder.judge_step(r, 1000, ladder.SHED_CLASSES["hearth"])[0])

    def test_the_warm_up_step_is_never_judged_and_judging_stops_at_the_first_fail(self):
        rates = [100, 200, 400, 800]
        rep = report("userinfo", [row(0, p99=999), row(1), row(2), row(3, p99=80), row(4)])
        v = ladder.judge("keycloak", "userinfo", rep, rates)
        self.assertEqual([x["clean"] for x in v], [True, True, False])
        self.assertEqual(v[2]["rate"], 400)
        self.assertIn("p99 80 ms > 50 ms", v[2]["reasons"])

    def test_a_step_the_run_did_not_reach_is_not_run(self):
        rep = report("refresh", [row(0), row(1)])
        v = ladder.judge("hearth", "refresh", rep, [25, 50])
        self.assertEqual(v[-1], {"rate": 50, "clean": None, "reasons": ["not run"]})

    def test_steps_after_a_live_stop_did_not_run(self):
        # Stopped at step 2 (clean after all): step 3 has sampler rows only.
        rep = report("refresh", [row(0), row(1), row(2), row(3, finished=0, p99=None)])
        v = ladder.judge("hearth", "refresh", rep, [25, 50, 100], ran=2)
        self.assertEqual([x["clean"] for x in v], [True, True, None])
        v = ladder.judge("hearth", "refresh", rep, [25, 50, 100])
        self.assertEqual([x["clean"] for x in v], [True, True, False])


class Live(unittest.TestCase):
    def metrics(self, steps):
        """A k6 /v1/metrics answer: steps maps step -> (p95 ms, ok rate)."""
        data = []
        for st, (p95, rate) in steps.items():
            data.append({"id": f"journey_ms{{step:{st},phase:hold}}", "attributes": {"sample": {"p(95)": p95}}})
            data.append({"id": f"journey_ok{{step:{st},phase:hold}}", "attributes": {"sample": {"rate": rate}}})
        data.append({"id": "journey_ms", "attributes": {"sample": {"p(95)": 999}}})
        return {"data": data}

    def test_stops_at_the_first_finished_step_that_fails_for_sure(self):
        m = self.metrics({0: (900, 0.5), 1: (10, 1.0), 2: (60, 1.0), 3: (70, 1.0)})
        # Steps are 65 s; at 200 s steps 0, 1 and 2 are over. Step 0 is the warm-up.
        self.assertEqual(ladder.live_stop("ory", "userinfo", [m], 200, 0), 2)
        # At 190 s step 2 is not over yet.
        self.assertIsNone(ladder.live_stop("ory", "userinfo", [m], 190, 0))

    def test_any_generator_and_errors_count(self):
        good = self.metrics({1: (10, 1.0), 2: (10, 1.0)})
        bad = self.metrics({1: (10, 1.0), 2: (10, 0.98)})
        self.assertEqual(ladder.live_stop("keycloak", "refresh", [good, bad], 200, 0), 2)
        # 0.5 % errors: not for sure (the judge decides after the run).
        meh = self.metrics({1: (10, 1.0), 2: (10, 0.995)})
        self.assertIsNone(ladder.live_stop("keycloak", "refresh", [meh], 200, 0))

    def test_hearths_login_is_stopped_on_latency_only(self):
        shed = self.metrics({1: (100, 0.9)})
        self.assertIsNone(ladder.live_stop("hearth", "login", [shed], 140, 0))
        self.assertEqual(ladder.live_stop("zitadel", "login", [shed], 140, 0), 1)
        slow = self.metrics({1: (1500, 1.0)})
        self.assertEqual(ladder.live_stop("hearth", "login", [slow], 140, 0), 1)


class Phases(unittest.TestCase):
    def verdicts(self, journey, clean_steps, fail=True):
        rates = ladder.coarse_rates(journey)
        out = [{"rate": r, "clean": True} for r in rates[:clean_steps]]
        if fail and clean_steps < len(rates):
            out.append({"rate": rates[clean_steps], "clean": False})
        return out

    def test_fine_after_the_first_failing_coarse_step(self):
        self.assertEqual(ladder.next_phase(self.verdicts("refresh", 3)), [125, 150, 175])
        self.assertEqual(ladder.next_phase(self.verdicts("login", 0)), [0.5, 1, 1.5])

    def test_no_fine_phase_when_all_8_coarse_steps_are_clean(self):
        self.assertIsNone(ladder.next_phase(self.verdicts("login", 8)))

    def test_a_coarse_run_that_ended_early_resumes(self):
        v = self.verdicts("mix", 2, fail=False) + [{"rate": 20, "clean": None}]
        self.assertIsNone(ladder.next_phase(v))
        self.assertEqual(ladder.resume_from("mix", v), [20, 40, 80, 160, 320, 640])
        self.assertEqual(ladder.resume_from("mix", self.verdicts("mix", 2)), [])

    def test_clean_rate_is_the_highest_clean_step_of_both_phases(self):
        coarse = self.verdicts("refresh", 3)  # 25, 50, 100 clean; 200 fails
        fine = [{"rate": 125, "clean": True, "p99_ms": 70}, {"rate": 150, "clean": False}]
        r = ladder.journey_result("zitadel", "refresh", coarse, fine)
        self.assertEqual(r["clean_rate"], 125)
        self.assertEqual(r["p99_ms"], 70)
        self.assertFalse(r["at_least"])
        self.assertEqual(r["flags"], [])

    def test_at_least_when_the_8th_coarse_step_is_clean(self):
        r = ladder.journey_result("hearth", "login", self.verdicts("login", 8))
        self.assertEqual(r["clean_rate"], 256)
        self.assertTrue(r["at_least"])

    def test_no_clean_step_gives_0(self):
        coarse = self.verdicts("login", 0)
        fine = [{"rate": 0.5, "clean": False}]
        self.assertEqual(ladder.journey_result("authentik", "login", coarse, fine)["clean_rate"], 0)

    def test_flags_non_monotonic_and_generator_bound(self):
        coarse = self.verdicts("refresh", 3)
        fine = [{"rate": 125, "clean": False}, {"rate": 150, "clean": True, "generator_cpu_pct_mean": 350}]
        r = ladder.journey_result("ory", "refresh", coarse, fine)
        self.assertEqual(r["clean_rate"], 150)
        self.assertEqual(r["flags"], ["non-monotonic", "generator-bound"])


class Fastest(unittest.TestCase):
    def test_highest_geometric_mean_over_the_8_journeys(self):
        base = {j: 100 for j in ladder.JOURNEYS}
        results = {
            "hearth": {j: 10000 for j in ladder.JOURNEYS},
            "keycloak": dict(base, login=50),
            "zitadel": dict(base, refresh=400),  # geomean > keycloak's
            "ory": dict(base),
        }
        f = ladder.fastest(results)
        self.assertEqual(f["product"], "zitadel")
        self.assertEqual([r["product"] for r in f["ranking"]], ["zitadel", "ory", "keycloak"])
        self.assertAlmostEqual(f["geomean"], 100 * 4 ** (1 / 8), places=2)

    def test_a_missing_or_zero_journey_counts_as_0(self):
        results = {
            "keycloak": {j: 1000 for j in ladder.JOURNEYS if j != "mix"},  # no mix
            "ory": {j: 10 for j in ladder.JOURNEYS},
        }
        self.assertEqual(ladder.fastest(results)["product"], "ory")

    def test_ties_at_0_go_to_more_clean_journeys_then_their_geomean(self):
        results = {
            "keycloak": dict({j: 100 for j in ladder.JOURNEYS}, login=0),
            "authentik": dict({j: 100 for j in ladder.JOURNEYS}, login=0, mix=0),
            "ory": dict({j: 200 for j in ladder.JOURNEYS}, login=0),
        }
        f = ladder.fastest(results)
        self.assertEqual(f["product"], "ory")
        self.assertEqual(f["geomean"], 0)
        self.assertEqual(f["ranking"][-1]["product"], "authentik")


class Seed(unittest.TestCase):
    def test_estimate_plus_half_at_most_16_hours(self):
        self.assertEqual(ladder.seed_minutes(60), 90)
        self.assertEqual(ladder.seed_minutes(41), 62)
        self.assertEqual(ladder.seed_minutes(700), 960)
        with self.assertRaises(ValueError):
            ladder.seed_minutes(0)


if __name__ == "__main__":
    unittest.main()
