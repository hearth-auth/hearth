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
| `ory/` | Ory Hydra v26.2.0 and Ory Kratos v26.2.0 with Ory's reference login and consent UI: `compose.yaml` (the three, the migrations and PostgreSQL), `hydra.yaml`, `kratos.yaml`, `identity.schema.json`, `initdb.sh` (the two databases), `realm.py` (the clients and login users, tested by `test_realm.py`), `ory.sh` (up, seed, hashes, messages, restart, down) |
| `authentik/` | Authentik 2026.8.6: `compose.yaml` (Authentik's server and worker, and PostgreSQL), `tls.yaml` (the run's TLS leaf as the web certificate), `realm.py` (the providers, the service account and the blueprints of the login and bulk users, tested by `test_realm.py`), `authentik.sh` (up, seed, settle, hashes, tasks, restart, down) |
| `zitadel/` | Zitadel v4.20.5: `compose.yaml` (Zitadel's init, setup and start, and PostgreSQL), `instance.py` (the clients and login users, tested by `test_instance.py`), `zitadel.sh` (up, seed, hashes, restart, down) |
| `aws/` | The AWS session (below): `compare.sh` (the driver), `remote.sh` (its server side), `ladder.py` (rates, verdicts, the size 2 product), `cost.py` and `prices.json` (the running total), `session-plan.json` (hours per part), `compose-sampler.sh` (the sampler for a compose project), `dryrun/` (shims for `DRY_RUN=1`) |

## The AWS session (`aws/`)

`aws/compare.sh` runs #913 on AWS in one session, on top of `loadtest/live/cloud.sh` (`up`,
`deploy`, `import`, `ramp`, `collect`, `down`) with `PROVIDER=aws`. Run it detached
(`scripts/run-detached.sh run compare -- env SESSION=913a IMAGE=hearth-stress:<tag>
loadtest/compare/aws/compare.sh session`); the header of `compare.sh` lists its commands and
settings.

1. **Seeds** (`compare.sh seed <product>`), one c7i.large server alone per product: 1M bulk users
   and 1,000 login users through the product's own seed tool (`cloud.sh import` for Hearth),
   then `ids.js` lists the first 1M user ids through the admin API. The seed record
   (`seed-<product>.json`) has the time of the seed call, the time until the admin API lists
   all 1M users, the settle time, the idle RSS and the store size. The store is on a second
   EBS volume (made at launch, deleted with the instance), which is kept as a snapshot tagged
   with the seed run's tag. The server's lifetime is the seed estimate plus 50 %, at most 16 h.
2. **Ramps** (`compare.sh ramps <product> <1|2>`): size 1 is a c7i.large server and 2
   c7i.xlarge generators, size 2 a c7i.2xlarge server and 4 generators, with the products'
   memory limits and PostgreSQL's `shared_buffers` times 4 (`remote.sh scale`). The server's
   data volume is made from the seed's snapshot. Each journey: a restore of the seeded store,
   a page-cache drop and a restart, a warm-up minute, then the coarse phase (doubling from the
   #913 start rate, at most 8 steps), then 3 fine steps, each phase one k6 run (`RATES_PM`).
   While a phase runs, the driver reads each generator's k6 REST API every 15 s and stops the
   run at the first step that fails for sure (p95 over the budget, or 1 % errors); afterwards
   `aws/ladder.py` judges each step with the clean-step rule (no dropped journey, errors below
   0.1 % not counting Hearth's password-hash sheds, p99 within the budget, the server alive)
   and stops at the first failing one. Per step it records the rate, the p99, the errors by
   class, the server's CPU, RSS and disk writes. The cold read (`cold100k`, `cold1m`) is admin
   user lookup over the first 100,000 or 1M seeded users after the cache drop (the
   1,000-user case is journey 6). Every product runs with `PRESENT=chain`.
3. **Session** (`compare.sh session`): the seeds in parallel, size 1 for the 5 products as their
   snapshots complete, the #647 10M restore drill (`round.sh` with
   `loadtest/live/plans/913-drill-r7i-large-10m.txt`, unchanged), then size 2 for Hearth and the
   other product with the highest geometric mean of the 8 clean rates at size 1
   (`ladder.py fastest`). Results: `loadtest/live/results/compare-<session>/` (`summary.md`).

**Cost.** `aws/cost.py` keeps a ledger of every instance (from before `up` to after `down`),
volume, snapshot and the results fetched, priced with `aws/prices.json` (us-east-1 on-demand,
from AWS's price list files, with sources and the date). The total is printed after every step
and written to `cost.txt`; at `STOP_USD` ($15) the session tears everything down and stops. A
part whose estimate would pass `CAP_USD` ($20) does not start. `compare.sh plan` prices
`aws/session-plan.json`, the hours per part.

**Safety.** Every instance terminates itself at the end of its lifetime (`cloud.sh`, tested by
`loadtest/live/test_lifetime.sh`). Snapshots outlive their runs on purpose: `cloud.sh down`
and `compare.sh snapshots` list them, and only `compare.sh delete-snapshots <id>...` deletes
them (only the session's own). Products' images are pulled on the server by digest
(`images.env`); Docker comes from Ubuntu 24.04's archive.

**Without AWS.** `DRY_RUN=1` puts shims for `aws`, `ssh`, `scp`, `docker` and `curl` on the PATH
(`aws/dryrun/`): every AWS call and remote command is printed and answered, the k6 output is made
up, nothing leaves the machine. `aws/test_dryrun.sh` runs a seed and the ramps that way and
checks the result; `aws/test_ladder.py` and `aws/test_cost.py` test the ladder and the cost.

## Adapters

A product adapter (`loadtest/live/k6/products/<product>.js`) supplies only what differs between
products: the endpoints, the login page as a list of steps (each builds its request and checks
its answer), the admin API (user lookup, listing, create, bulk import) and the admin context.
`PRODUCT` in the generator environment picks it; Hearth is the default, so the #647 rounds run
unchanged. `k6/test_products.mjs` pins the requests the Hearth adapter sends to the ones the
#647 rounds sent.

The client credentials journey uses the `api` client unless `STRESS_CC_CLIENT_ID` and
`STRESS_CC_SECRET` name another (Zitadel, where an API application cannot take that grant;
Authentik, where the grant authenticates a service account); Hearth and Keycloak do not set
them (`k6/test_realms.mjs`).

| Journey (#913) | `JOURNEY` | Keycloak | Zitadel | Ory | Authentik |
|---|---|---|---|---|---|
| 1 login | `login` | the authorization endpoint renders Keycloak's login page; its form posts to `login-actions/authenticate`, which answers `302` with the code; code exchange with PKCE (3 requests) | the authorization endpoint answers `302` to login UI v1; the login name page, the password page and the callback (`302` with the code); code exchange with PKCE (6 requests); the scope adds `offline_access`, without which Zitadel issues no refresh token | Hydra's authorization endpoint answers `302` to the UI's login page; the UI starts a Kratos browser login flow; the login page (Ory Elements form); the form posts to Kratos, which accepts Hydra's login request (`303` back to Hydra); Hydra sends the browser to the UI's consent page, which accepts at once (`skip_consent`); Hydra answers `303` with the code; code exchange with PKCE (9 requests); the scope adds `offline_access`, without which Hydra issues no refresh token | the authorization endpoint answers `302` to the flow interface of the default authentication flow; the interface page, then the flow executor API (`/api/v3/flows/executor/…`, what the page's script calls): the identification challenge, the email, the password challenge, the password, the MFA stage (it passes: no user has an authenticator) and the user login stage, which sends the browser back to the authorization endpoint; with the implicit-consent flow that answers `302` with the code; code exchange with PKCE (10 requests); the scope adds `offline_access`, without which Authentik issues no refresh token |
| 2 refresh | `refresh` | `refresh_token` grant of `app` (rotation on: `revokeRefreshToken`) | `refresh_token` grant of `app` (Zitadel always rotates and refuses a reused token) | `refresh_token` grant of `app` (Hydra rotates, refuses a reused token and revokes its family) | `refresh_token` grant of `app` (Authentik issues a new refresh token at every use, `refresh_token_threshold` 0, and refuses a used one) |
| 3 client credentials | `client_credentials` | `client_credentials` grant of `api` (service account) | `client_credentials` grant of the service account `cc` (`STRESS_CC_*`) with scope `profile` (Zitadel refuses the grant without a scope) | `client_credentials` grant of `api` (`client_secret_basic`; Hydra keeps the secret as a PBKDF2-SHA256 hash, 25,000 iterations) | `client_credentials` grant of `api` with the service account `cc` (`STRESS_CC_*`: the client secret is base64 of the account's username and app password, Authentik's machine-to-machine guide) |
| 4 userinfo | `userinfo` | `GET …/protocol/openid-connect/userinfo` | `GET /oidc/v1/userinfo` | `GET /userinfo` (Hydra's public port) | `GET /application/o/userinfo/` |
| 5 introspect | `introspect` | `POST …/token/introspect` as `api`; the users' tokens carry `api` in `aud` (audience mapper) | `POST /oauth/v2/introspect` as the API application `api` (basic auth); the users' tokens carry its project in `aud` | `POST /admin/oauth2/introspect` on Hydra's admin port (4445, TLS), which takes no client authentication | `POST /application/o/introspect/` as `api` (basic auth): Authentik introspects only for a confidential provider, and `app` lists `api` as a federated provider, so `api` may introspect `app`'s tokens |
| 6 admin user lookup | `admin_lookup` | `GET /admin/realms/stress/users/{id}`; the realm admin signs in with the `kc-admin-api` scope | `GET /v2/users/{id}`; the realm admin (IAM_OWNER) signs in with the Zitadel API audience scope | `GET /admin/identities/{id}` on Kratos's admin port (4434, TLS), which has no authentication of its own: the realm admin signs in like the other products' admins, but no token is sent | `GET /api/v3/core/users/{id}/`; the realm admin (`akadmin`) signs in with the `goauthentik.io/api` scope, whose access token the API takes |
| 7 user create | `create_user` | `POST /admin/realms/stress/users` (`201`, id from `Location`) | `POST /v2/users/human` (`200`, `userId` in the body); no password and a verified email, so, as Hearth, no initialization code and no email | `POST /admin/identities` (`201`, `id` in the body); no credentials and a verified email, so, as Hearth, no password and no message (`ory.sh messages` stays 0) | `POST /api/v3/core/users/` (`201`, `pk` in the body); no password (Authentik stores an unusable one) and no email (`authentik.sh tasks` counts the worker's email tasks: 0) |
| 8 the mix | `mix` | the #647 weights | the #647 weights | the #647 weights | the #647 weights |

### Every product keeps its own access-token format

Each product issues access tokens in its own default format; the harness never reads a token to
time it. A token's lifetime is the token response's `expires_in` (RFC 6749 section 5.1), for every
product: each VU replaces a token when 10 to 25 % of that lifetime is left, and a response
without a valid `expires_in` stops the run (`tokenLife` in `k6/products/common.js`, tested in
`k6/test_products.mjs`). The formats, each product's default:

| Product | Access token |
|---|---|
| Hearth | JWT, Ed25519 (EdDSA) |
| Keycloak | JWT, RS256 |
| Zitadel | opaque (bearer) |
| Ory Hydra | opaque |
| Authentik | JWT, RS256 |

Only Hearth's admin context comes from its access token (the realm id, `tid`). Zitadel's admin
API takes the organization from the environment (`STRESS_ORG_ID`, `STRESS_ORG_NAME`, written by
`instance.py`); Keycloak's, Kratos's and Authentik's need none.

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
start), and `zitadel.sh hashes` prints the parameters of the stored password hashes. Ory is the
same with `ory/ory.sh` and `.build/ory/`; `ory.sh messages` counts the messages Kratos has
queued (emails and SMS). Its host name is `ory.stress.test` (five ports, below). Authentik is
the same with `authentik/authentik.sh` and `.build/authentik/`, except its seed, which runs on the
server's host (below); `authentik.sh tasks` prints the worker's tasks and the number of email
tasks, and `authentik.sh settle` waits until the worker has none left.

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
  clients keep Zitadel's default opaque (bearer) access tokens (above)
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

### Ory settings

From Ory's own guides (links in `ory/compose.yaml`), the rest at Ory's defaults:

- one server with the three parts Ory's self-hosted setup needs: Hydra (OAuth 2.0 and OpenID
  Connect, no users), Kratos (the users) and a login and consent app. The app is Ory's own reference
  UI (`kratos-selfservice-ui-node`, the official image of the same release), the one Kratos's
  quickstart runs, here wired to Hydra (`HYDRA_ADMIN_URL`): its login page starts a Kratos login
  flow for Hydra's login challenge (Kratos's native Hydra integration, `oauth2_provider.url`,
  accepts the challenge), and its consent page accepts at once for a client with `skip_consent`,
  Ory's documented setup for first-party clients. Kratos and the UI share Hydra's network namespace,
  so the three answer on one name, as on one host: Hydra 4444 (public) and 4445 (admin), Kratos 4433
  (public) and 4434 (admin), the UI 4455. Each listener terminates TLS itself (`serve.*.tls`, the
  UI's `TLS_CERT_PATH`); they call each other over TLS by that name
- production mode: `hydra serve all` and `kratos serve` without `--dev`, the migrations as
  separate one-shot containers; one PostgreSQL server with a database per part (`initdb.sh`),
  the shared `postgresql.conf`; connection pools at Ory's defaults (from the CPU count); no
  telemetry (`sqa.opt_out`, `SQA_OPT_OUT`)
- Argon2id m=19456 KiB, t=2, p=1 (`hashers.argon2`: `memory: 19456KB`, Kratos counts KB as
  1,024 bytes; `iterations: 2`, `parallelism: 1`); the stored hashes show
  `$argon2id$v=19$m=19456,t=2,p=1` (`ory.sh hashes`). Kratos's default is bcrypt. Hydra keeps
  client secrets as PBKDF2-SHA256 hashes, 25,000 iterations (its default; it has no Argon2
  option)
- access tokens live 1 h; refresh tokens rotate with no grace period (Hydra's default: a reused
  one is refused and its family revoked); access tokens keep Hydra's default opaque format
  (above), which is also Ory's advice
- the admin ports have no authentication of their own; Ory's guides say to keep them off the
  public network (behind a gateway that authenticates). The comparison calls them directly, so
  the introspect and admin journeys pay for no caller authentication: the report says so
- container memory 2 GiB in all, as Keycloak's and Zitadel's: Kratos 1 GiB (each concurrent
  Argon2id check takes 19 MiB), Hydra 512 MiB, the UI 512 MiB (Node.js)
- no courier (`--watch-courier` is off): no journey and no seed queues a message, which
  `ory.sh messages` checks; verification and recovery are off (Kratos's defaults), and every
  address is created verified
- bulk seed: `PATCH /admin/identities` (Kratos's batch import), 1,000 users per request (its
  limit), an existing user counted as failed. Each batch is written in one transaction before
  the call answers, so the users are usable at once (`ory.sh seed` checks the last one). Each
  bulk user gets the run's unusable Argon2id hash (`hashed_password`, Kratos's documented
  import of hashes from another system; `realm.py` makes it with the run's parameters and a
  random salt and digest, so no password matches it). Kratos stores an imported hash without
  hashing anything, so the seed costs no Argon2id work, as Hearth's. The 1,000 login users and
  the admin go in through the same API with their password (200 per request at most), which
  Kratos hashes

One Ory behaviour changes what a journey sees: as Zitadel, refreshing revokes the access token
of the refresh token used (`PRESENT=chain`, above).

### Authentik settings

From Authentik's own guides (links in `authentik/compose.yaml`), the rest at Authentik's defaults:

- the vendor's Docker Compose setup: the server (`authentik server`: the router, which terminates
  TLS, and the Django app under gunicorn) and the worker (`authentik worker`: background tasks),
  on one PostgreSQL with the shared `postgresql.conf`. Since 2025.10 Authentik needs no Redis
  (cache, sessions and the task queue are in PostgreSQL). TLS on Authentik's own HTTPS listener
  (9443), plain HTTP off; the run's leaf is the default brand's web certificate (`tls.yaml`, a
  file blueprint the worker applies at its first start; `up` then restarts the server once, as
  the server reads the certificate at its start). No update check, no startup analytics
- tuning at Authentik's defaults: gunicorn 2 workers with 4 threads each (`web.workers`,
  `web.threads`; the configuration guide advises against fewer than 2 workers), the worker 1
  process with 2 threads (`worker.processes`, `worker.threads`), database connections not kept
  (`postgresql.conn_max_age` 0, which the guide advises for a direct connection to PostgreSQL)
- PBKDF2-SHA256 with 1,000,000 iterations, Django 5.2's default, which Authentik keeps (Argon2
  is in its list of hashers, but not first). The running worker reports Django 5.2.19 and
  `pbkdf2_sha256` 1,000,000 iterations first in `PASSWORD_HASHERS`; the stored hashes show
  `pbkdf2_sha256$1000000` (`authentik.sh hashes`). The login users' hash has Django's salt
  length (22 characters), so a login does not re-hash it
- container memory 2 GiB in all, as Keycloak's, Zitadel's and Ory's: the server 1,280 MiB (two
  gunicorn workers and the router, about 380 MiB idle and up to about 700 MiB under the
  journeys locally), the worker 768 MiB (one process, about 300 MiB)
- realm (`realm.py`, through the API with the automated install's bootstrap token; the admin
  `akadmin` with its email and a password hash from the automated install): the OAuth2/OpenID
  providers `app` (public, code with PKCE and refresh tokens) and `api` (confidential), each
  with its application; access tokens live 1 h; a new refresh token at every refresh, the used
  one refused (`refresh_token_threshold` 0, the default); the vendor's implicit-consent flow, its
  documented flow for first-party applications (no consent page); access tokens are JWTs signed
  with the vendor's "authentik Self-signed Certificate" (RS256), the key the vendor's OpenID
  conformance blueprint uses (without a signing key Authentik signs with HS256 and the client
  secret)
- client credentials: Authentik's machine-to-machine guide authenticates a service account with
  an app password token; `realm.py` makes the service account `cc` and its token
  (`POST /api/v3/core/users/service_account/`), and the journey sends the `api` provider's client
  id with base64 of `cc`'s username and app password as the secret (basic auth), the guide's
  form. The other way in that guide, the provider's own secret, makes Authentik update its
  automatic service account at every request
- introspection: Authentik introspects only for a confidential provider authenticated with its
  own secret, and only tokens of its own or of a provider that names it as federated
  (`jwt_federation_providers`, the guide's cross-provider introspection): `app` names `api`
- the admin API takes an OAuth access token with the `goauthentik.io/api` scope (Authentik's
  API authentication guide): `akadmin` signs in through the same login flow as the users with
  that scope, as Keycloak's admin signs in with `kc-admin-api`
- the login users (1,000) go in as one blueprint with a hash of their password (`password_hash`,
  the blueprints' documented field for hashes), so nothing is hashed at import
- bulk seed: blueprints (`realm.py bulk`, 1,000 users per file), each applied by Authentik's
  blueprint importer in one transaction, in one-off worker containers (`ak apply_blueprint`;
  `SEED_PROCS` of them, default 2), on the server's host (`authentik.sh seed`), not through
  `prepare.js`. The bulk users get no hash: Authentik stores its unusable password, as for a
  user made without a password through the users API. Two documented paths would cause work
  per user that Hearth's seed does not: every model change made through the API (the blueprint
  import endpoint, the users API) writes an audit event, and setting a password hash writes a
  `password_set` event wherever it is done; each event queues a task for the worker
  (`event_trigger_dispatch`) and one more per notification rule (4 by default). The one-off
  containers apply the blueprints outside an HTTP request and outside the worker's queue, so the
  seed writes no event and queues no task (`authentik.sh tasks` before and after). The running
  worker never sees the files, so its hourly blueprint discovery does not parse them. Locally
  (12 cores) 100,000 users took about 20 minutes (0 to 10,000 with 2 processes in 219 s, the
  rest with 4 in 969 s), each file usable once applied; at that rate 1,000,000 take some hours,
  depending on the host's cores (`SEED_PROCS`)

Three Authentik behaviours change what a run sees:

- every sign-in, client credentials grant and API change writes audit events, each of which
  queues worker tasks (above): at the journeys' rates the worker falls behind and its queue
  grows in PostgreSQL. This is Authentik's default and is left on; `authentik.sh settle` waits
  for the queue to empty (after the login users' import too)
- the login is 10 requests, as a browser drives Authentik's flow executor
- every request looks up the brand with one query that joins about 20 tables, and PostgreSQL
  plans it in about 50 ms (the shared settings, `join_collapse_limit` 8); with the password
  check this keeps local sign-ins to about 2 per second (correctness checks only, not a result)
