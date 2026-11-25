// Tests for schedule.js, the arrival-rate schedule of stress.js. The #647
// rounds' linear ramps must keep their stages; the #913 ladders give a list of
// per-minute rates.
//
// Usage: node loadtest/live/k6/test_schedule.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const src = readFileSync(new URL('./schedule.js', import.meta.url), 'utf8');
const s = await import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`);

test('a linear ramp keeps the #647 stages: ramp then hold at start + i * step, per second', () => {
  const got = s.schedule({ START_RATE: '200', STEP_RATE: '100', STEPS: '3', HOLD_S: '90' });
  assert.equal(got.timeUnit, '1s');
  assert.equal(got.startRate, 200);
  assert.equal(got.steps, 3);
  assert.deepEqual(got.stages, [
    { duration: '5s', target: 200 },
    { duration: '90s', target: 200 },
    { duration: '5s', target: 300 },
    { duration: '90s', target: 300 },
    { duration: '5s', target: 400 },
    { duration: '90s', target: 400 },
  ]);
  assert.deepEqual(got.perSecond, [200, 300, 400]);
});

test('RATES_PM gives one step per listed rate, per minute', () => {
  const got = s.schedule({ RATES_PM: '75,150,300', START_RATE: '0', STEP_RATE: '0', STEPS: '3' });
  assert.equal(got.timeUnit, '1m');
  assert.equal(got.startRate, 75);
  assert.equal(got.steps, 3);
  assert.deepEqual(got.stages.map((x) => x.target), [75, 75, 150, 150, 300, 300]);
  assert.deepEqual(got.stages.map((x) => x.duration), ['5s', '60s', '5s', '60s', '5s', '60s']);
  assert.deepEqual(got.perSecond, [1.25, 2.5, 5]);
});

test('RATES_PM wins over STEPS, and the linear variables are then not needed', () => {
  const got = s.schedule({ RATES_PM: '60, 120', STEPS: '8' });
  assert.equal(got.steps, 2);
});

test('RATES_PM refuses a rate that is not a positive whole number per minute', () => {
  for (const bad of ['75,1.5', '0,60', '60,x', '60,,120']) {
    assert.throws(() => s.schedule({ RATES_PM: bad }), /RATES_PM/, bad);
  }
});

test('a linear ramp still needs START_RATE, STEP_RATE and STEPS', () => {
  assert.throws(() => s.schedule({ STEP_RATE: '1', STEPS: '1' }), /START_RATE/);
});

test('the live thresholds name each step hold submetric and always pass', () => {
  const t = s.liveThresholds(2);
  assert.deepEqual(Object.keys(t), [
    'journey_ms{step:0,phase:hold}',
    'journey_ok{step:0,phase:hold}',
    'journeys{step:0,phase:hold}',
    'journey_ms{step:1,phase:hold}',
    'journey_ok{step:1,phase:hold}',
    'journeys{step:1,phase:hold}',
  ]);
  assert.deepEqual(t['journey_ms{step:1,phase:hold}'], ['p(95)>=0']);
  assert.deepEqual(t['journey_ok{step:0,phase:hold}'], ['rate>=0']);
  // k6 shows a step's p95 and rate as 0 before it has a sample, and after samples
  // of 0: only the count tells the live watcher that the step ran (#913).
  assert.deepEqual(t['journeys{step:1,phase:hold}'], ['count>=0']);
});
