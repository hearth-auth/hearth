// Several realms in one live stress run (gen-config.sh REALMS, #647 round B).
// Pure functions without k6 modules, so node tests them (test_realms.mjs).
//
// generator.env describes realm k (1-based) with STRESS_REALM, STRESS_APP_CLIENT_ID,
// STRESS_API_CLIENT_ID and STRESS_API_SECRET, plus the suffix `_<k>` for k > 1.
// STRESS_REALMS is the number of realms: 1 when unset (gen-config.sh writes it
// only for more than one).
//
// Each VU works in one realm for all its journeys: VU v takes realm (v - 1) % n.

/** The generator.env suffix of realm `k` (1-based): none for realm 1, `_<k>` after. */
export function suffix(k) {
  return k === 1 ? '' : `_${k}`;
}

/**
 * The run's realms from the environment `e` (k6's __ENV): one object per realm
 * with its `number` (1-based), `name`, `appClientId`, `apiClientId`,
 * `apiSecret` ('' until prepare.js has set it) and `secretVar` (the variable
 * that holds the secret).
 */
export function realmsFromEnv(e) {
  const raw = e.STRESS_REALMS;
  const n = raw === undefined || raw === '' ? 1 : Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`STRESS_REALMS must be a positive integer, not ${raw}`);
  }
  const out = [];
  for (let k = 1; k <= n; k++) {
    const s = suffix(k);
    const need = (name) => {
      const v = e[name + s];
      if (v === undefined || v === '') throw new Error(`environment variable ${name}${s} is required`);
      return v;
    };
    out.push({
      number: k,
      name: need('STRESS_REALM'),
      appClientId: need('STRESS_APP_CLIENT_ID'),
      apiClientId: need('STRESS_API_CLIENT_ID'),
      apiSecret: e[`STRESS_API_SECRET${s}`] || '',
      secretVar: `STRESS_API_SECRET${s}`,
    });
  }
  return out;
}

/** The realm (0-based index) of VU `vu` (exec.vu.idInTest, 1-based) among `n`. */
export function vuRealm(vu, n) {
  return (vu - 1) % n;
}

/** VU `vu`'s place (0-based) among its realm's VUs: its session in that realm's pool. */
export function vuSlot(vu, n) {
  return Math.floor((vu - 1) / n);
}

/**
 * Realm `i`'s (0-based) share of `count` items over `n` realms. The shares
 * differ by at most 1 and add up to `count`; realm i's share of the VUs is the
 * number of VUs that vuRealm puts in it.
 */
export function share(count, n, i) {
  return Math.floor(count / n) + (i < count % n ? 1 : 0);
}

/** The bounds of `n` realms over users [from, to): realm i owns [b[i], b[i + 1]). */
export function realmBounds(from, to, n) {
  const b = [from];
  for (let i = 0; i < n; i++) b.push(b[i] + share(to - from, n, i));
  return b;
}

/** The realm (0-based) whose bounds hold user `u`; users outside go to the nearest end. */
function realmOf(u, bounds) {
  let i = 0;
  while (i < bounds.length - 2 && u >= bounds[i + 1]) i++;
  return i;
}

/**
 * The import batches of users [lo, hi): `{ start, end, realm }`, at most
 * `batch` users each, and never across a realm bound. Without bounds (one
 * realm) every batch is in realm 0 and starts at lo + k * batch.
 */
export function importBatches(lo, hi, batch, bounds) {
  const out = [];
  for (let start = lo; start < hi;) {
    let end = Math.min(start + batch, hi);
    let realm = 0;
    if (bounds) {
      realm = realmOf(start, bounds);
      if (realm < bounds.length - 2) end = Math.min(end, bounds[realm + 1]);
    }
    out.push({ start, end, realm });
    start = end;
  }
  return out;
}

/**
 * The console line stress.js writes for an acknowledged user `id` in realm
 * `ri` (0-based) of `n`: `ACK <id>`, plus the realm number with several realms.
 */
export function ackLine(id, ri, n) {
  return n > 1 ? `ACK ${id} ${ri + 1}` : `ACK ${id}`;
}

/** The acknowledged users in a ramp's console output: `[{ id, realm }]`, realm 0-based. */
export function parseAcks(text) {
  const out = [];
  const re = /ACK ([0-9a-f-]{36})(?: ([0-9]+))?/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ id: m[1], realm: m[2] === undefined ? 0 : parseInt(m[2], 10) - 1 });
  }
  return out;
}
