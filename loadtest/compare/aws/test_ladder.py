"""Tests for ladder.py: the #913 step ladder, the step verdicts, the clean rate, the
fastest-product rule and the seed lifetime.

Usage: python3 -I loadtest/compare/aws/test_ladder.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile
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

    def test_a_password_hash_shed_is_an_error(self):
        # Hearth's KDF gate refuses a sign-in with 503 or 429: errors, like any product's
        # queue-full 503 (#913, changed on 2026-11-24).
        for cls in ("login_submit:503", "login_submit:429"):
            r = row(1, finished=1000, failed=50, classes={cls: 50})
            self.assertEqual(ladder.judge_step(r, 1000), (False, ["errors 5.00%"]))
        rep = report("login", [row(0), row(1, finished=1000, failed=800,
                                            classes={"login_submit:503": 800})])
        v = ladder.judge("login", rep, [256])
        self.assertEqual([x["clean"] for x in v], [False])
        self.assertEqual(v[0]["reasons"], ["errors 80.00%"])

    def test_the_warm_up_step_is_never_judged_and_judging_stops_at_the_first_fail(self):
        rates = [100, 200, 400, 800]
        rep = report("userinfo", [row(0, p99=999), row(1), row(2), row(3, p99=80), row(4)])
        v = ladder.judge("userinfo", rep, rates)
        self.assertEqual([x["clean"] for x in v], [True, True, False])
        self.assertEqual(v[2]["rate"], 400)
        self.assertIn("p99 80 ms > 50 ms", v[2]["reasons"])

    def test_a_step_the_run_did_not_reach_is_not_run(self):
        rep = report("refresh", [row(0), row(1)])
        v = ladder.judge("refresh", rep, [25, 50])
        self.assertEqual(v[-1], {"rate": 50, "clean": None, "reasons": ["not run"]})

    def test_steps_after_a_live_stop_did_not_run(self):
        # Stopped at step 2 (clean after all): step 3 has sampler rows only.
        rep = report("refresh", [row(0), row(1), row(2), row(3, finished=0, p99=None)])
        v = ladder.judge("refresh", rep, [25, 50, 100], ran=2)
        self.assertEqual([x["clean"] for x in v], [True, True, None])
        v = ladder.judge("refresh", rep, [25, 50, 100])
        self.assertEqual([x["clean"] for x in v], [True, True, False])


FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata",
                       "k6-metrics-setup-overran.json")
# The 2026-11-25 Authentik refresh ramp: its setup signed the token pool in past
# START_AT, and the driver asked at START_AT + 130 s, before any journey had run.
SETUP_OVERRAN_START_AT = 1795604176
SETUP_OVERRAN_NOW = 1795604306


class CutShort(unittest.TestCase):
    """A step whose hold the run did not reach (analyze.py's hold_complete False) is
    never clean: when what it ran looks clean, or it ran no journey, it did not run;
    when what it ran already fails (k6's failure-ratio guard aborted the run, say), it
    fails."""

    def test_the_2026_11_25_ory_step_is_not_clean(self):
        # Stopped 1 s into step 1's hold: 23 of 1,500 journeys, 0 errors, p99 17 ms.
        cut = dict(row(1, p99=16.98, finished=23), hold_complete=False)
        rep = report("refresh", [dict(row(0), hold_complete=True), cut])
        v = ladder.judge("refresh", rep, [25, 50], ran=1)
        self.assertEqual(len(v), 1)
        self.assertIsNone(v[0]["clean"])
        self.assertEqual(v[0]["reasons"], ["cut short: the run ended before its hold did"])
        self.assertEqual(ladder.steps_run(v), 0)
        # The coarse phase goes on from that rate, not from the next one.
        self.assertEqual(ladder.resume_from("refresh", v)[:2], [25, 50])

    def test_a_cut_short_step_that_already_fails_fails(self):
        # The failure-ratio guard (stress.js ABORT_FAIL_RATIO) ended the run mid-step.
        cut = dict(row(2, finished=900, failed=600, classes={"503": 600}), hold_complete=False)
        v = ladder.judge("refresh", report("refresh", [row(1), cut]), [25, 50])
        self.assertEqual([x["clean"] for x in v], [True, False])
        self.assertEqual(v[1]["reasons"], ["errors 66.67%", "cut short: the run ended before its hold did"])

    def test_a_cut_short_step_without_journeys_did_not_run(self):
        cut = dict(row(1, p99=None, finished=0), hold_complete=False)
        v = ladder.judge("refresh", report("refresh", [cut]), [25])
        self.assertIsNone(v[0]["clean"])

    def test_a_complete_step_and_an_old_report_are_judged_as_before(self):
        for extra in ({"hold_complete": True}, {}):
            rep = report("refresh", [dict(row(1), **extra), dict(row(2, p99=500), **extra)])
            v = ladder.judge("refresh", rep, [25, 50])
            self.assertEqual([x["clean"] for x in v], [True, False], extra)

    def test_cut_short_after_a_failing_step_does_not_matter(self):
        rep = report("refresh", [row(1, p99=500), dict(row(2), hold_complete=False)])
        v = ladder.judge("refresh", rep, [25, 50])
        self.assertEqual([x["clean"] for x in v], [False])


def k6_metrics(steps, start=0):
    """A k6 /v1/metrics answer of stress.js: steps maps step -> (p95 ms, ok rate) or
    (p95 ms, ok rate, journeys); `start` is the scenario start (epoch s), None before
    the scenario started."""
    data = []
    for st, v in steps.items():
        p95, rate, n = v if len(v) == 3 else (*v, 100)
        data.append({"id": f"journey_ms{{step:{st},phase:hold}}", "attributes": {"sample": {"p(95)": p95}}})
        data.append({"id": f"journey_ok{{step:{st},phase:hold}}", "attributes": {"sample": {"rate": rate}}})
        data.append({"id": f"journeys{{step:{st},phase:hold}}",
                     "attributes": {"sample": {"count": n, "rate": 0}}})
    data.append({"id": "journey_ms", "attributes": {"sample": {"p(95)": 999}}})
    if start is not None:
        data.append({"id": "scenario_start_s", "attributes": {"sample": {"value": start}}})
    return {"data": data}


def setup_overran(stress_js="old", start=None, steps=None):
    """The saved 2026-11-25 answer (k6 pre-declares every thresholded submetric, so
    each step reads p95 0 and rate 0 before a journey ran). stress_js="new" adds what
    stress.js now reports: each step's journey count (0) and, once its scenario
    started, the start. `steps` maps step -> (p95, rate, journeys) to fill in."""
    with open(FIXTURE) as f:
        m = json.load(f)
    if stress_js == "new":
        for st in range(9):
            m["data"].append({"id": f"journeys{{step:{st},phase:hold}}", "attributes": {
                "type": "counter", "contains": "default", "tainted": None,
                "sample": {"count": 0, "rate": 0}}})
        if start is not None:
            m["data"].append({"id": "scenario_start_s", "attributes": {
                "type": "gauge", "contains": "default", "tainted": None,
                "sample": {"value": start}}})
    by_id = {d["id"]: d["attributes"]["sample"] for d in m["data"]}
    for st, (p95, rate, n) in (steps or {}).items():
        by_id[f"journey_ms{{step:{st},phase:hold}}"]["p(95)"] = p95
        by_id[f"journey_ok{{step:{st},phase:hold}}"]["rate"] = rate
        by_id[f"journeys{{step:{st},phase:hold}}"]["count"] = n
    return m


class Live(unittest.TestCase):

    def test_stops_at_the_first_finished_step_that_fails_for_sure(self):
        m = k6_metrics({0: (900, 0.5), 1: (10, 1.0), 2: (60, 1.0), 3: (70, 1.0)})
        # Steps are 65 s; at 200 s steps 0, 1 and 2 are over. Step 0 is the warm-up.
        self.assertEqual(ladder.live_stop("userinfo", [m], 200), 2)
        # At 190 s step 2 is not over yet.
        self.assertIsNone(ladder.live_stop("userinfo", [m], 190))

    def test_any_generator_and_errors_count(self):
        good = k6_metrics({1: (10, 1.0), 2: (10, 1.0)})
        bad = k6_metrics({1: (10, 1.0), 2: (10, 0.98)})
        self.assertEqual(ladder.live_stop("refresh", [good, bad], 200), 2)
        # 0.5 % errors: not for sure (the judge decides after the run).
        meh = k6_metrics({1: (10, 1.0), 2: (10, 0.995)})
        self.assertIsNone(ladder.live_stop("refresh", [meh], 200))

    def test_errors_stop_a_login_or_mix_run_too(self):
        # 10 % of the journeys refused (Hearth's KDF sheds, for one): the run stops.
        shed = k6_metrics({1: (100, 0.9)})
        slow = k6_metrics({1: (1500, 1.0)})
        for journey in ("login", "mix"):
            self.assertEqual(ladder.live_stop(journey, [shed], 140), 1)
            self.assertEqual(ladder.live_stop(journey, [slow], 140), 1)

    def test_the_2026_11_25_answer_before_any_journey_stops_nothing(self):
        # Every step reads rate 0, but no journey ran: the run must go on, with the
        # stress.js of that day (no counts, no start) and with today's.
        for stress_js in ("old", "new"):
            m = setup_overran(stress_js)
            for now in (SETUP_OVERRAN_NOW, SETUP_OVERRAN_START_AT + 3600):
                self.assertIsNone(ladder.live_stop("refresh", [m, m], now), (stress_js, now))

    def test_steps_count_from_the_scenario_start_not_start_at(self):
        # Setup ran 130 s past START_AT. At START_AT + 200 s, START_AT says steps 0-2
        # are over; the scenario has run 70 s, so only step 0 is.
        start = SETUP_OVERRAN_START_AT + 130
        m = setup_overran("new", start, {1: (40, 0.5, 300)})
        self.assertIsNone(ladder.live_stop("refresh", [m], SETUP_OVERRAN_START_AT + 200))
        self.assertIsNone(ladder.live_stop("refresh", [m], start + 129))
        self.assertEqual(ladder.live_stop("refresh", [m], start + 130), 1)

    def test_a_finished_step_without_journeys_is_not_judged(self):
        # Step 1 is over but recorded no journey (its rate and p95 read 0): only the
        # judge, after the run, rules on it. Step 2 ran and fails.
        m = k6_metrics({1: (0, 0, 0), 2: (10, 0.5, 40)})
        self.assertIsNone(ladder.live_stop("refresh", [m], 194))
        self.assertEqual(ladder.live_stop("refresh", [m], 195), 2)

    def test_each_generator_counts_from_its_own_start(self):
        early = k6_metrics({1: (10, 1.0)}, start=0)
        late = k6_metrics({1: (10, 0.5)}, start=60)
        # At 140 s step 1 is over on the early generator only: the late one's is half run.
        self.assertIsNone(ladder.live_stop("refresh", [early, late], 140))
        self.assertEqual(ladder.live_stop("refresh", [early, late], 200), 1)
        # A generator whose scenario has not started yet counts no step.
        waiting = k6_metrics({1: (10, 0.5)}, start=None)
        self.assertIsNone(ladder.live_stop("refresh", [early, waiting], 1000))


class CommandLine(unittest.TestCase):
    """compare.sh's `judge` and `live` calls: they name the product, and every product
    gets the same rule."""
    PRODUCTS = ("hearth", "keycloak", "zitadel", "ory", "authentik")

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = d.name

    def write(self, name, obj):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ladder.main(["ladder.py", *args])
        return json.loads(out.getvalue())

    def test_judge_fails_a_step_of_password_hash_sheds_for_every_product(self):
        # #913's first Hearth ramp: 80 % of the logins at 256/s refused with 503.
        for cls in ("login_submit:503", "login_submit:429"):
            rep = self.write("report.json", report("login", [
                row(0), row(1, p99=400, finished=1000, failed=800, classes={cls: 800})]))
            for product in self.PRODUCTS:
                v = self.run_cli("judge", product, rep, "-1", "256")
                self.assertEqual(len(v), 1, (product, cls))
                self.assertIs(v[0]["clean"], False, (product, cls))
                self.assertEqual(v[0]["reasons"], ["errors 80.00%"], (product, cls))

    def test_ran_prints_the_number_of_steps_that_ran(self):
        none = self.write("none.json", [{"rate": 25, "clean": None, "reasons": ["not run"]}])
        some = self.write("some.json", [{"rate": 25, "clean": True}, {"rate": 50, "clean": False}])
        self.assertEqual(self.run_cli("ran", none), 0)
        self.assertEqual(self.run_cli("ran", some), 2)

    def test_live_stops_a_login_or_mix_step_of_sheds_for_every_product(self):
        m = self.write("metrics.json", k6_metrics({1: (100, 0.2)}))
        for product in self.PRODUCTS:
            for journey in ("login", "mix"):
                self.assertEqual(self.run_cli("live", product, journey, "140", "60", m),
                                 {"stop": 1}, (product, journey))


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

    def test_steps_run_counts_the_judged_steps(self):
        # A phase whose k6 never started (#913: generator.env did not load) has no step
        # row: its first step did not run.
        self.assertEqual(ladder.steps_run(ladder.judge("refresh", report("refresh", []), [25, 50])), 0)
        self.assertEqual(ladder.steps_run(self.verdicts("refresh", 0)), 1)  # ran, and failed
        self.assertEqual(ladder.steps_run(self.verdicts("mix", 2, fail=False) + [{"rate": 20, "clean": None}]), 2)

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
