// The arrival-rate schedule of a stress ramp (stress.js). No k6 imports, so
// node can test it (test_schedule.mjs).
//
// Two forms:
//   linear (the #647 rounds)  step i offers START_RATE + i * STEP_RATE per
//                             second, for STEPS steps (timeUnit 1s)
//   RATES_PM (#913 ladders)   step i offers the i-th rate of a comma-separated
//                             list, in journeys per MINUTE (timeUnit 1m), so a
//                             fine step such as 2.5/s split over two
//                             generators (75/min each) needs no fraction
// Each step is RAMP_S seconds of ramp to its rate, then HOLD_S seconds at it.

/**
 * The schedule from the environment `e` (k6's __ENV).
 * Returns { timeUnit, startRate, stages, steps, perSecond }: perSecond[i] is
 * step i's offered rate in journeys per second (for logs and tests).
 */
export function schedule(e) {
  const rampS = num(e, 'RAMP_S', 5);
  const holdS = num(e, 'HOLD_S', 60);
  const stages = [];
  if (e.RATES_PM !== undefined && e.RATES_PM !== '') {
    const rates = String(e.RATES_PM)
      .split(',')
      .map((s) => {
        const v = Number(s.trim());
        if (!Number.isInteger(v) || v <= 0) throw new Error(`RATES_PM: "${s}" is not a positive integer`);
        return v;
      });
    for (const r of rates) {
      stages.push({ duration: `${rampS}s`, target: r });
      stages.push({ duration: `${holdS}s`, target: r });
    }
    return { timeUnit: '1m', startRate: rates[0], stages, steps: rates.length, perSecond: rates.map((r) => r / 60) };
  }
  const startRate = num(e, 'START_RATE');
  const stepRate = num(e, 'STEP_RATE');
  const steps = num(e, 'STEPS');
  const perSecond = [];
  for (let i = 0; i < steps; i++) {
    const target = startRate + i * stepRate;
    stages.push({ duration: `${rampS}s`, target });
    stages.push({ duration: `${holdS}s`, target });
    perSecond.push(target);
  }
  return { timeUnit: '1s', startRate, stages, steps, perSecond };
}

/**
 * Thresholds that only make k6 keep per-step submetrics, so its REST API
 * (K6_ADDRESS) shows each step's hold latency (p95), success rate and
 * journey count while the ramp runs: the #913 ladder driver reads them to end
 * a coarse phase at its first failing step. k6 lists these submetrics from
 * the start, at p95 0 and rate 0 before any sample; only the count tells a
 * step that ran from one that did not. They always pass, so they never change
 * k6's exit status. Only for RATES_PM ramps; the #647 rounds keep their options.
 */
export function liveThresholds(steps) {
  const out = {};
  for (let i = 0; i < steps; i++) {
    out[`journey_ms{step:${i},phase:hold}`] = ['p(95)>=0'];
    out[`journey_ok{step:${i},phase:hold}`] = ['rate>=0'];
    out[`journeys{step:${i},phase:hold}`] = ['count>=0'];
  }
  return out;
}

function num(e, name, dflt) {
  const raw = e[name];
  if (raw === undefined || raw === '') {
    if (dflt === undefined) throw new Error(`environment variable ${name} is required`);
    return dflt;
  }
  const v = parseInt(raw, 10);
  if (!Number.isFinite(v) || v < 0) throw new Error(`${name} must be a non-negative integer`);
  return v;
}
