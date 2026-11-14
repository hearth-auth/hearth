// Tests for realms.js, the pure helpers that spread a live stress run over
// several realms (#647 round B). realms.js has no k6 imports, so node runs it.
//
// Usage: node loadtest/live/k6/test_realms.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

// k6 loads realms.js as an ES module; a data: URL makes node do the same
// whatever its module-type detection.
const src = readFileSync(new URL('./realms.js', import.meta.url), 'utf8');
const r = await import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`);

const one = {
  STRESS_REALM: 'stress',
  STRESS_APP_CLIENT_ID: 'app-1',
  STRESS_API_CLIENT_ID: 'api-1',
  STRESS_API_SECRET: 'secret-1',
};
const three = Object.assign({}, one, {
  STRESS_REALMS: '3',
  STRESS_REALM_2: 'stress2',
  STRESS_APP_CLIENT_ID_2: 'app-2',
  STRESS_API_CLIENT_ID_2: 'api-2',
  STRESS_API_SECRET_2: 'secret-2',
  STRESS_REALM_3: 'stress3',
  STRESS_APP_CLIENT_ID_3: 'app-3',
  STRESS_API_CLIENT_ID_3: 'api-3',
  STRESS_API_SECRET_3: '',
});

test('without STRESS_REALMS there is one realm, from the unsuffixed variables', () => {
  assert.deepEqual(r.realmsFromEnv(one), [
    {
      number: 1,
      name: 'stress',
      appClientId: 'app-1',
      apiClientId: 'api-1',
      apiSecret: 'secret-1',
      secretVar: 'STRESS_API_SECRET',
    },
  ]);
});

test('STRESS_REALMS=3 reads realms 2 and 3 from the _2 and _3 variables', () => {
  const got = r.realmsFromEnv(three);
  assert.deepEqual(got.map((x) => [x.number, x.name, x.appClientId, x.apiClientId, x.apiSecret, x.secretVar]), [
    [1, 'stress', 'app-1', 'api-1', 'secret-1', 'STRESS_API_SECRET'],
    [2, 'stress2', 'app-2', 'api-2', 'secret-2', 'STRESS_API_SECRET_2'],
    [3, 'stress3', 'app-3', 'api-3', '', 'STRESS_API_SECRET_3'],
  ]);
});

test('a missing realm variable or a bad count is an error that names it', () => {
  const missing = Object.assign({}, three);
  delete missing.STRESS_API_CLIENT_ID_3;
  assert.throws(() => r.realmsFromEnv(missing), /STRESS_API_CLIENT_ID_3 is required/);
  for (const bad of ['0', '-1', 'x', '1.5']) {
    assert.throws(() => r.realmsFromEnv(Object.assign({}, one, { STRESS_REALMS: bad })), /STRESS_REALMS/);
  }
});

test('VUs take the realms in turn and each gets its own slot in its realm', () => {
  // 10 VUs over 3 realms: realm 0 gets VUs 1, 4, 7, 10.
  const realms = [];
  const slots = [];
  for (let vu = 1; vu <= 10; vu++) {
    realms.push(r.vuRealm(vu, 3));
    slots.push(r.vuSlot(vu, 3));
  }
  assert.deepEqual(realms, [0, 1, 2, 0, 1, 2, 0, 1, 2, 0]);
  assert.deepEqual(slots, [0, 0, 0, 1, 1, 1, 2, 2, 2, 3]);
  // One realm: every VU in realm 0, slot = VU - 1 (as before REALMS).
  assert.deepEqual([1, 2, 1000].map((vu) => [r.vuRealm(vu, 1), r.vuSlot(vu, 1)]), [[0, 0], [0, 1], [0, 999]]);
});

test('share splits a count so that shares differ by at most 1 and add up', () => {
  assert.deepEqual([0, 1, 2].map((i) => r.share(10, 3, i)), [4, 3, 3]);
  assert.deepEqual([0].map((i) => r.share(1000, 1, i)), [1000]);
  assert.deepEqual([0, 1, 2].map((i) => r.share(2, 3, i)), [1, 1, 0]);
  // Each realm's pool holds at least one session per VU of that realm.
  for (let i = 0; i < 10; i++) {
    let vus = 0;
    for (let vu = 1; vu <= 1000; vu++) if (r.vuRealm(vu, 10) === i) vus++;
    assert.equal(r.share(1000, 10, i), vus);
  }
});

test('realmBounds splits a user range evenly', () => {
  assert.deepEqual(r.realmBounds(0, 1000000, 10), [
    0, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000, 1000000,
  ]);
  assert.deepEqual(r.realmBounds(5, 15, 3), [5, 9, 12, 15]);
  assert.deepEqual(r.realmBounds(0, 1000, 1), [0, 1000]);
});

test('import batches without bounds are the batches of one realm', () => {
  assert.deepEqual(r.importBatches(0, 5000, 2000, null), [
    { start: 0, end: 2000, realm: 0 },
    { start: 2000, end: 4000, realm: 0 },
    { start: 4000, end: 5000, realm: 0 },
  ]);
  assert.deepEqual(r.importBatches(0, 0, 2000, null), []);
});

test('import batches never cross a realm bound', () => {
  // The users 0..1M on 2 generators and 10 realms: generator 2 gets 500k..1M.
  const bounds = r.realmBounds(0, 1000000, 10);
  const batches = r.importBatches(500000, 1000000, 2000, bounds);
  assert.equal(batches.length, 250);
  assert.deepEqual(batches[0], { start: 500000, end: 502000, realm: 5 });
  assert.deepEqual(batches[249], { start: 998000, end: 1000000, realm: 9 });
  // An uneven split: bounds 5, 9, 12, 15 for realms 0, 1, 2.
  assert.deepEqual(r.importBatches(5, 15, 3, r.realmBounds(5, 15, 3)), [
    { start: 5, end: 8, realm: 0 },
    { start: 8, end: 9, realm: 0 },
    { start: 9, end: 12, realm: 1 },
    { start: 12, end: 15, realm: 2 },
  ]);
  // Each realm gets the same number of users over both generators.
  const perRealm = new Array(10).fill(0);
  for (const [lo, hi] of [[0, 500000], [500000, 1000000]]) {
    for (const b of r.importBatches(lo, hi, 2000, bounds)) perRealm[b.realm] += b.end - b.start;
  }
  assert.deepEqual(perRealm, new Array(10).fill(100000));
});

test('ACK lines carry the realm number only with several realms, and parse back', () => {
  const id = '0190f3a4-1b2c-7d3e-8f40-123456789abc';
  assert.equal(r.ackLine(id, 0, 1), `ACK ${id}`);
  assert.equal(r.ackLine(id, 2, 3), `ACK ${id} 3`);
  // k6 --console-output lines, from a one-realm and a three-realm ramp.
  const text = [
    `time="2026-11-14T08:00:00Z" level=info msg="ACK ${id}" source=console`,
    'time="2026-11-14T08:00:00Z" level=info msg="STRESS_STARTED" source=console',
    `time="2026-11-14T08:00:01Z" level=info msg="ACK ${id.replace('abc', 'abd')} 3" source=console`,
    `time="2026-11-14T08:00:01Z" level=info msg="ACK ${id.replace('abc', 'abe')} 1" source=console`,
  ].join('\n');
  assert.deepEqual(r.parseAcks(text), [
    { id, realm: 0 },
    { id: id.replace('abc', 'abd'), realm: 2 },
    { id: id.replace('abc', 'abe'), realm: 0 },
  ]);
});
