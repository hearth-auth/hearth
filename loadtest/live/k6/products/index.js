// The product adapters of the same-hardware comparison (#913). The k6 scripts
// run the same journeys against any product; PRODUCT (default hearth) picks
// the adapter. k6 has no dynamic import, so every adapter is imported here.
//
// An adapter supplies only what differs between products: the endpoints, the
// login page (loginSteps), the admin API (user lookup, listing, create, bulk
// import) and the admin context. The journeys, pools, metrics and the method
// stay in stress.js and lib.js.
import { authentik } from './authentik.js';
import { hearth } from './hearth.js';
import { keycloak } from './keycloak.js';
import { ory } from './ory.js';
import { zitadel } from './zitadel.js';

export const PRODUCTS = { hearth, keycloak, ory, zitadel, authentik };

/** The adapter named `name` (PRODUCT); hearth when unset. */
export function productFor(name) {
  const key = name === undefined || name === '' ? 'hearth' : name;
  const p = PRODUCTS[key];
  if (!p) throw new Error(`PRODUCT must be one of ${Object.keys(PRODUCTS).join(', ')}, not ${name}`);
  return p;
}
