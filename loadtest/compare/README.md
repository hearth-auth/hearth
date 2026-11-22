# Same-hardware comparison (#913)

The per-node comparison of Hearth with other self-hosted identity servers. The method (journeys,
budgets, steps, settings) is fixed in issue #913; this directory holds the products' setups. The
journeys themselves are the live stress test's (`loadtest/live/k6/stress.js`), run through one
adapter per product (`loadtest/live/k6/products/`), so every product gets the same load, pools,
metrics and analysis as Hearth.

| Part | What it is |
|---|---|
| `images.env` | Every image of the comparison, pinned by digest |
| `postgres/postgresql.conf` | The one PostgreSQL config for every product that needs PostgreSQL (`fsync=on`, `synchronous_commit=on`) |
| `tls.sh` | A CA and an HTTPS leaf, the same kind as Hearth's (`gen-config.sh`) |
| `k6.sh` | Runs a `loadtest/live/k6` script from the pinned k6 image, for a host without k6 |
| `keycloak/` | Keycloak 26.8.2: `compose.yaml` (Keycloak and PostgreSQL), `realm.py` (the realm, tested by `test_realm.py`), `keycloak.sh` (up, seed, restart, down) |

## Adapters

A product adapter (`loadtest/live/k6/products/<product>.js`) supplies only what differs between
products: the endpoints, the login page as a list of steps (each builds its request and checks
its answer), the admin API (user lookup, listing, create, bulk import) and the admin context.
`PRODUCT` in the generator environment picks it; Hearth is the default, so the #647 rounds run
unchanged. `k6/test_products.mjs` pins the requests the Hearth adapter sends to the ones the
#647 rounds sent.

| Journey (#913) | `JOURNEY` | Keycloak |
|---|---|---|
| 1 login | `login` | the authorization endpoint renders Keycloak's login page; its form posts to `login-actions/authenticate`, which answers `302` with the code; code exchange with PKCE (3 requests) |
| 2 refresh | `refresh` | `refresh_token` grant of `app` (rotation on: `revokeRefreshToken`) |
| 3 client credentials | `client_credentials` | `client_credentials` grant of `api` (service account) |
| 4 userinfo | `userinfo` | `GET …/protocol/openid-connect/userinfo` |
| 5 introspect | `introspect` | `POST …/token/introspect` as `api`; the users' tokens carry `api` in `aud` (audience mapper) |
| 6 admin user lookup | `admin_lookup` | `GET /admin/realms/stress/users/{id}`; the realm admin signs in with the `kc-admin-api` scope |
| 7 user create | `create_user` | `POST /admin/realms/stress/users` (`201`, id from `Location`) |
| 8 the mix | `mix` | the #647 weights |

## Running Keycloak locally

Needs Docker with Compose, `openssl`, `curl` and `python3`. The first `up` writes the bundle to
`.build/keycloak/` (git-ignored, mode 0700): the CA, the TLS leaf and generated passwords. No
password is printed or passed on a command line.

```bash
loadtest/compare/keycloak/keycloak.sh up              # PostgreSQL, Keycloak, realm, 1,000 login users
loadtest/compare/keycloak/keycloak.sh seed 0 100000   # bulk users through partialImport; prints the seed time
loadtest/compare/k6.sh loadtest/compare/.build/keycloak stress.js \
  JOURNEY=login START_RATE=5 STEP_RATE=0 STEPS=1 HOLD_S=30 VUS=50 SUMMARY_OUT=/out/login.json
loadtest/compare/keycloak/keycloak.sh down            # removes the containers and the database volume
```

`OUT=<name>` before `k6.sh` also writes k6's per-request CSV and console to the bundle's `out/`.

Local runs check that an adapter works (every request answers what it should, with 0 errors).
They are not results: results come only from the AWS rounds of #913, on the hardware it fixes.

### Keycloak settings

From Keycloak's own guides (links in `keycloak/compose.yaml`), the rest at Keycloak's defaults:

- production mode (`start`), HTTPS on Keycloak's listener (port 8443), plain HTTP off,
  `hostname` set; health and metrics on the management port (9000)
- Argon2id m=19456 KiB, t=2, p=1 (`KC_SPI_PASSWORD_HASHING__ARGON2__*`); the stored credentials
  show `"memory":["19456"]`, `"hashIterations":2`, `"parallelism":["1"]`
- database pool initial = min = max = 30; `http-max-queued-requests` 1000 (excess requests get
  `503`); container memory limit 2 GiB (the JVM takes 70 % as heap)
- realm: access tokens live 1 h and refresh tokens rotate with reuse refused, as in the Hearth
  run; the `api` client's secret is kept the way Keycloak keeps it (as given, not hashed: the
  report states this for the client credentials journey); full scope is off on both clients, so
  Keycloak does not log a deprecation warning at every token request
