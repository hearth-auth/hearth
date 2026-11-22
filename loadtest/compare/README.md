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
| `zitadel/` | Zitadel v4.20.5: `compose.yaml` (Zitadel's init, setup and start, and PostgreSQL), `instance.py` (the clients and login users, tested by `test_instance.py`), `zitadel.sh` (up, seed, hashes, restart, down) |

## Adapters

A product adapter (`loadtest/live/k6/products/<product>.js`) supplies only what differs between
products: the endpoints, the login page as a list of steps (each builds its request and checks
its answer), the admin API (user lookup, listing, create, bulk import) and the admin context.
`PRODUCT` in the generator environment picks it; Hearth is the default, so the #647 rounds run
unchanged. `k6/test_products.mjs` pins the requests the Hearth adapter sends to the ones the
#647 rounds sent.

The client credentials journey uses the `api` client unless `STRESS_CC_CLIENT_ID` and
`STRESS_CC_SECRET` name another (Zitadel, where an API application cannot take that grant);
Hearth and Keycloak do not set them (`k6/test_realms.mjs`).

| Journey (#913) | `JOURNEY` | Keycloak | Zitadel |
|---|---|---|---|
| 1 login | `login` | the authorization endpoint renders Keycloak's login page; its form posts to `login-actions/authenticate`, which answers `302` with the code; code exchange with PKCE (3 requests) | the authorization endpoint answers `302` to login UI v1; the login name page, the password page and the callback (`302` with the code); code exchange with PKCE (6 requests); the scope adds `offline_access`, without which Zitadel issues no refresh token |
| 2 refresh | `refresh` | `refresh_token` grant of `app` (rotation on: `revokeRefreshToken`) | `refresh_token` grant of `app` (Zitadel always rotates and refuses a reused token) |
| 3 client credentials | `client_credentials` | `client_credentials` grant of `api` (service account) | `client_credentials` grant of the service account `cc` (`STRESS_CC_*`) with scope `profile` (Zitadel refuses the grant without a scope) |
| 4 userinfo | `userinfo` | `GET …/protocol/openid-connect/userinfo` | `GET /oidc/v1/userinfo` |
| 5 introspect | `introspect` | `POST …/token/introspect` as `api`; the users' tokens carry `api` in `aud` (audience mapper) | `POST /oauth/v2/introspect` as the API application `api` (basic auth); the users' tokens carry its project in `aud` |
| 6 admin user lookup | `admin_lookup` | `GET /admin/realms/stress/users/{id}`; the realm admin signs in with the `kc-admin-api` scope | `GET /v2/users/{id}`; the realm admin (IAM_OWNER) signs in with the Zitadel API audience scope |
| 7 user create | `create_user` | `POST /admin/realms/stress/users` (`201`, id from `Location`) | `POST /v2/users/human` (`200`, `userId` in the body); no password and a verified email, so, as Hearth, no initialization code and no email |
| 8 the mix | `mix` | the #647 weights | the #647 weights |

### Every product presents its own newest token (`PRESENT=chain`)

Every run of the comparison sets `PRESENT=chain`, for every product, Hearth included: each VU
presents its own newest access token (a new one after each refresh), as a real client presents
it. `k6.sh` sets it, and a run of the comparison on other hosts must set it too. The #647 rounds
keep `stress.js`'s default, `PRESENT=pool`, where the userinfo and introspect journeys present
the tokens of a shared pool. In the mix, the pool's tokens are the ones the VUs' refresh chains
replace, and Zitadel revokes an access token when its refresh token is used: with `pool`,
about 1 in 9 Zitadel mix journeys failed locally on a token that no real client would still
present. One condition for all products keeps the comparison fair.

## Running locally

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

Zitadel is the same with `zitadel/zitadel.sh` and the bundle `.build/zitadel/`; its `up` also
waits for Zitadel's `setup` (migrations and the first instance, about a minute on the first
start), and `zitadel.sh hashes` prints the parameters of the stored password hashes.

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

### Zitadel settings

From Zitadel's own guides (links in `zitadel/compose.yaml`), the rest at Zitadel's defaults:

- production split: `init`, `setup` and `start` (`--masterkeyFromEnv --tlsMode enabled`), each in
  its own container; TLS on Zitadel's own listener (port 8443), no proxy; external domain, port
  and `ExternalSecure` set
- Argon2id m=19456 KiB, t=2, p=1 (`ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_*`); the
  stored hashes show `$argon2id$v=19$m=19456,t=2,p=1` (`zitadel.sh hashes`). Client secrets keep
  Zitadel's SecretHasher default, bcrypt cost 4
- login UI v1, served by Zitadel itself (`LOGINV2_REQUIRED=false`). Zitadel v4 makes login v2
  the default for a new instance; v2 is a separate Next.js server that the vendor's compose puts
  behind a path-routing TLS proxy, so the product would no longer terminate TLS on its own
  listener and would be two servers instead of one. Zitadel's guide to adopting v2 says that
  staying on v1 is supported and "is the right default unless you have a concrete reason to
  move"
- database pool at its defaults (10 open, 5 idle): the tuning guide says the defaults typically
  work well; the memory cache for the instance and organization objects is on, as the cache
  guide recommends for one server (it is marked beta); container memory limit 2 GiB, as
  Keycloak's
- realm: the first instance (`setup`) with its organization `stress`, a human IAM_OWNER (the
  realm admin) and a service account whose PAT `instance.py` uses for the project, the clients
  and the login users; access tokens live 1 h; refresh tokens rotate with reuse refused (Zitadel
  has no switch for it); the "set up a second factor" prompt after the password is off
  (`MfaInitSkipLifetime` 0), as no product's users have a second factor; the `app` and `cc`
  clients get JWT access tokens (Zitadel's default is opaque) because the harness reads `iat`
  and `exp` from them. Zitadel signs them with RS256, its default key type
- bulk seed: `POST /admin/v1/import` (the admin API's ImportData), into the existing
  organization, 1,000 users per request, an existing user counted as failed. The import answers
  once the events are stored; the users reach the user API and the login page only when
  Zitadel's user projection has applied them, so `zitadel.sh seed` waits for that and prints
  both times. Each bulk user gets the run's unusable Argon2id hash (`hashedPassword`, the
  import's documented field for hashes from another system; `instance.py` makes it, with the
  run's parameters and a random salt and digest, so no password matches it). Without a password
  or a hash Zitadel puts a user in its initial state: one initialization code and one email per
  user, work that Hearth's seed (password-less users, no email) does not cause. Zitadel only
  parses an imported hash, and Argon2id is its configured hasher, so its verifier is on

Two Zitadel behaviours change what a journey sees:

- refreshing revokes the access token of the refresh token used: `userinfo` answers `401` and
  introspection `active: false` for it (Hearth's and Keycloak's access tokens stay valid until
  they expire). The comparison runs with `PRESENT=chain` for every product (above)
- the client credentials grant needs a scope; the adapter asks for `profile`, which answers
  an access token without an ID token, as the other products do
