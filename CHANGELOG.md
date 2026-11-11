# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). See [VERSIONING.md](VERSIONING.md) for the SemVer policy, support window, and deprecation rules.

## [Unreleased]

### Changed
- **The audit list shows the newest events first** (#644): `GET /admin/audit`,
  `GET /admin/api/realms/{realm}/audit/events` and the admin audit page now return the newest
  events, newest first, when the request has no start time. They read back in growing time
  windows (1 hour, 1 day, 7 days, 30 days, 365 days, then the rest of the log) and stop when the
  page is full, so a large audit log no longer slows the page or takes memory from sign-ins.
  Before, they loaded the whole log and returned its oldest events. With a start time, events
  still come oldest first from it, and the read now stops when the page is full.

### Fixed
- **Audit queries apply every filter**: a query with both an actor and an action filter ignored
  the action, and a query with an actor or action filter and an `agent_id` or `tool` filter
  counted events toward the limit before it filtered them, so a page could be short.
- **`prompt=login` and `max_age` force a new sign-in, and ID tokens carry `auth_time`** (#782):
  a browser authorization request with `prompt=login`, or with a `max_age` that is less than the
  time since the last sign-in, now shows the sign-in page before it issues a code (OIDC Core
  §3.1.2.1). Before, Hearth issued the code from the current session. With `prompt=none` such a
  request gets `login_required`. The new sign-in opens a new session and revokes the old one, as
  every sign-in does. Every ID token from a browser sign-in now has `auth_time`, the time the
  sign-in (with any second factor) completed. A `max_age` that is not a non-negative integer gets
  `invalid_request`. `max_age` is read from the query string only, not from a request object or
  a pushed request.

## [4.10.0] — 2026-11-11

### Added
- **Store format version** (#646): the data directory now holds a `FORMAT` file with the store
  format version (`hearth-store-format 1`). Hearth writes it when it opens a data directory that
  has none. A build refuses at startup a data directory with a different store format version,
  before it reads a record, and the error names `docs/guides/upgrading.md`. Hearth does not
  migrate a data directory between store format versions: to move to a release with a new
  store format, restore a backup archive into an empty data directory (see the upgrade guide).
- **A backup metric and alert** (#648): `/metrics` now has
  `hearth_backup_last_success_timestamp_seconds{source}`, the time of the last successful
  `online` (`POST /admin/backup`) and `offline` (`hearth backup create`) backup, or `0` if none.
  Each backup writes its time to a small file in `storage.data_dir`, so a backup that the CLI took
  while the server was stopped also counts. `deploy/monitoring/` adds the `HearthBackupTooOld`
  alert (no backup for more than 26 hours) and a backup-age panel on the dashboard.

### Fixed
- **Writes continue during a backup** (#643): `POST /admin/backup` no longer holds the node's
  writes while it reads a realm. Before, every write (sign-ins, token refreshes, sign-ups, admin
  changes, audit records) waited for the read pass, and once `storage.max_writes_in_flight`
  writes waited, the next ones failed with `503`. A backup now reads one storage snapshot, taken
  at its start, for all its realms, so the archive is also one point in time across realms (it
  was one point in time per realm). While a backup runs, the node keeps the SST files that the
  snapshot reads, so compaction frees their disk space only when the backup ends. Each backup
  adds one SST file.
- **Session cleanup sweep evicts every expired session in one pass**: expired sessions past the
  first page were evicted on later cleanup ticks, so `SessionEvicted` events and session-version
  bumps came late. Such sessions were already refused on read.

### Security
- **rustix 1.1.6** (RUSTSEC-2026-0486): the lockfiles move from rustix 1.1.4, which the advisory
  marks unsound in its `xattr` functions, to 1.1.6.

## [4.9.0] — 2026-11-10

### Added
- **Prometheus alert rules and a Grafana dashboard** (#648): `deploy/monitoring/` ships
  `prometheus/hearth-alerts.yml` (15 alerts: instance down, 5xx rate, WAL write fence, low and
  filling data disk, slow WAL fsync, failed compaction, SST file count, refused writes, audit chain
  failure, unannounced revocations, rate limiters off, Argon2id and user-create shedding), their
  `promtool` unit tests, and `grafana/hearth-dashboard.json`. `deploy/monitoring/README.md` explains
  each alert and what to do. `make monitoring-check` checks them.
- **Storage metrics for alerts** (#648): `/metrics` now has
  `hearth_storage_wal_fsync_duration_seconds` (WAL fsync latency),
  `hearth_storage_compactions_total{kind,outcome}`, `hearth_storage_compaction_duration_seconds{kind}`,
  `hearth_storage_compaction_last_success_timestamp_seconds`, and
  `hearth_storage_data_dir_available_bytes` and `hearth_storage_data_dir_total_bytes` (the free and
  total space of the file system that holds `storage.data_dir`, read at each scrape). See the
  metrics table in the configuration reference.
- **A `hearth.export` seed role** (#637): every new realm now has a `hearth.export` role that holds
  only the `hearth.export` permission. Assign it next to a sub-admin role (for example
  `hearth.users.admin`) to let that sub-admin export its realm. Alone it grants nothing, because
  every export endpoint also requires an admin permission. Before, the only role with
  `hearth.export` was `realm.admin`, which is full superuser access, so a sub-admin could not get
  export rights. A realm created before this release does not get the role automatically.

### Removed
- **The reserved-permission bypass on role requests** (#637): `CreateRoleRequest` and
  `UpdateRoleRequest` in the Rust library no longer have `allow_reserved_permissions`. A custom
  role can never hold a `hearth.*` permission. No HTTP endpoint or config key changes: the field
  was never read from a request body.

### Security
- **Token exchange runs the pre-token webhook** (#763): the token-exchange grant
  (`urn:ietf:params:oauth:grant-type:token-exchange`) at `POST /token` and
  `POST /realms/{realm_name}/token` now calls the realm's pre-token webhook before it issues the
  token, and obeys `on_error`. If the webhook fails and `on_error` is `fail_closed`, the grant
  issues no token, as the other user grants do. The webhook's `extra_claims` now reach the
  exchanged token.
- **The consent approval applies the current MFA requirement** (#765): `POST /ui/oauth/consent`
  now does the second-factor and required-action checks of the authorization request again before
  it records the consent and issues the code. If the realm or the client starts to require a second
  factor while the consent page is open, a session that proved no second factor gets
  `login_required` (or the enrolment page, if the user has no factor yet). Before, the approval
  issued the code.
- **A reused authorization code ends the grant of its first exchange** (#783): when an
  authorization code is presented a second time at `POST /token` or
  `POST /realms/{realm_name}/token`, Hearth now revokes the tokens that the first exchange issued
  (RFC 6749 §4.1.2, RFC 9700 §4.5). The access token then fails at UserInfo and introspection, and
  the refresh token gets `invalid_grant`. The second request still gets `400 invalid_grant`.
  Hearth keeps the record of an exchanged code until the code expires
  (`oidc.authorization_code_ttl`), so a reuse after that time is refused but revokes nothing.
  Before, the tokens of the first exchange stayed valid.

### Fixed
- **The audit prune now runs soon after startup** (#645): the daily sweep that applies the audit
  `retention_days` and `max_rows` and the realm quotas `max_audit_rows` and `max_disk_bytes` ran
  its first pass 24 hours after startup. A server that restarted more often than once a day never
  pruned, so its audit log grew without limit. The first sweep now runs 60 seconds after startup,
  then once every 24 hours.
- **The storage sizing guide named metrics that do not exist** (#648): it told operators to alert
  on `storage_hot_tier_hits` and `storage_hot_tier_misses`. It now gives the hot-tier hit rate from
  `hearth_storage_get_total{outcome}`. A new test fails when the docs or the shipped deploy files
  name a metric that Hearth does not export.
- **Token endpoint errors and caching follow RFC 6749 §5** (#639): at `POST /token` and
  `POST /realms/{realm_name}/token`:
  - an invalid, expired or reused authorization code now gets `"error": "invalid_grant"`. Before,
    the `error` was `"invalid authorization code"` (an `InvalidGrant` error was `"invalid grant"`).
    The status stays `400`, and `error_code` stays `HEARTH_INVALID_GRANT`.
  - a refresh token presented by a client other than the one it was issued to now gets
    `400 invalid_grant`. Before, it got `401 invalid_client`. A confidential client's refresh
    without client authentication still gets `401 invalid_client`.
  - every response now carries `Cache-Control: no-store` and `Pragma: no-cache`. Before, token
    responses had no cache headers.
- **A refresh token that is not valid gets `400 invalid_grant`** (#783): at `POST /token` and
  `POST /realms/{realm_name}/token`, a refresh token that is not valid, has expired or was revoked
  now gets `400` with `"error": "invalid_grant"` (RFC 6749 §5.2). Before, it got `401` with
  `"error": "invalid token"`, `"token expired"` or `"token revoked"`. The `error_code` stays
  `HEARTH_TOKEN_INVALID`, `HEARTH_TOKEN_EXPIRED` or `HEARTH_TOKEN_REVOKED`.
- **A `private_key_jwt` client can omit `client_id`** (#785): at `POST /token`,
  `POST /device_authorization`, `POST /as/par`, `POST /introspect`, `POST /revoke` and their
  `/realms/{realm_name}/…` twins, a request that authenticates with `client_assertion` and has no
  `client_id` now uses the client that the assertion names in `sub` (it must equal `iss`; RFC 7521
  §4.2, RFC 7523 §3). Hearth then verifies the assertion in full, as before. Before, `/token` and
  `/device_authorization` refused such a request with `400`. `POST /device_authorization` also
  accepts a client that sends its `client_id` only in the HTTP Basic header, as `/token` does.
- **A client that Hearth cannot identify gets `401 invalid_client`** (#785): at `POST /token`,
  `POST /device_authorization`, `POST /revoke` and their `/realms/{realm_name}/…` twins, a request
  with no `client_id`, or with a `client_id` that is not a client id, now gets `401` with
  `"error": "invalid_client"` and `WWW-Authenticate: Basic` (RFC 6749 §5.2). Before, it got `400`
  with `"error": "invalid client_id UUID"` or `"client_id required"`, or `401` with
  `"error": "client_id required"`.
- **A confidential client's authorization request without PKCE gets an error redirect** (#639):
  `GET /ui/oauth/authorize` and `GET /ui/realms/{realm_name}/oauth/authorize` now refuse a plain
  request without `code_challenge` from any client, public or confidential, with an
  `invalid_request` redirect to the registered `redirect_uri` (the `state` comes back). Before,
  only a public client got this redirect. A confidential client's request went on through consent,
  and then the user got a server error page (`500`). PKCE is still required for every client: no
  request without it gets a code.
- **A `prompt=none` authorization request with no signed-in user gets `login_required`** (#639):
  `GET /realms/{realm_name}/authorize` (and `/ui/realms/{realm_name}/oauth/authorize`) now answers
  a plain `prompt=none` request from a browser with no session with an `error=login_required`
  redirect to the client's registered `redirect_uri`, with the request's `state` (OIDC Core
  §3.1.2.6). Before, the browser went to the sign-in page, which a silent request must not show. A
  request with an unregistered `redirect_uri` gets the error page. A `prompt=none` request that
  uses `request` or `request_uri` still goes to the sign-in page.
- **The UserInfo endpoint answers POST** (#639): `POST /userinfo` and
  `POST /realms/{realm_name}/userinfo` now give the same answer as `GET` (OIDC Core §5.3.1: the
  endpoint must support both methods). The access token goes in the `Authorization` header. Before,
  `POST` got `405`.
- **Profile claims with no value are left out** (#639): `name`, `given_name`, `family_name`,
  `email` and `preferred_username` are no longer sent as empty strings in ID tokens, access tokens
  and UserInfo responses when the user's field is empty (OIDC Core §5.3.2). Before, a user with no
  first or last name got `"given_name": ""` and `"family_name": ""`.
- **Discovery states that `request_uri` is not fetched by reference** (#639): both discovery
  documents (`/.well-known/openid-configuration` and
  `/realms/{realm_name}/.well-known/openid-configuration`) now carry
  `request_uri_parameter_supported: false` and `request_parameter_supported: true`. Before, both
  fields were missing. OpenID Connect Discovery reads a missing `request_uri_parameter_supported`
  as `true`, so a relying party could send a `request_uri` that Hearth then refused. Hearth
  accepts only the `request_uri` that its PAR endpoint returns, and a signed `request` object.
- **Discovery lists the client assertion algorithms** (#639): both discovery documents now carry
  `token_endpoint_auth_signing_alg_values_supported`, `revocation_endpoint_auth_signing_alg_values_supported`
  and `introspection_endpoint_auth_signing_alg_values_supported`, each `["PS256", "ES256", "EdDSA"]`:
  the algorithms that Hearth accepts for a `private_key_jwt` client assertion. RFC 8414 requires
  them when `private_key_jwt` is listed. Before, they were missing, so a client could not know
  that Hearth refuses `RS256` for client authentication.
- **Operators can sign in with a passkey at the operator console** (#769):
  `POST /ui/admin/login/passkey-complete` now completes the sign-in in the system realm. Before, it
  answered `400` ("Realm not resolvable") for every assertion, also a correct one, so an operator
  could not sign in with a passkey.
- **Device approval refuses an archived client** (#764): `POST /ui/device` now refuses a user code
  whose client was archived (or deleted) after the device flow started, and shows the "invalid
  code" message. Before, the approval succeeded; the token endpoint still refused the device's
  poll, so the device got no token.
- **Realm deletes free the realm's audit state in memory** (#609): deleting a realm now also
  removes the realm's audit chain lock and its cached audit HMAC key from memory. Before, both
  stayed until the server restarted.

## [4.8.0] — 2026-11-06

### Added
- **Agents have an optional `endpoint_url`, and the Agent Card serves it as `url`** (#632). Set it
  on `POST /v1/agents` or `PATCH /v1/agents/{id}`; it must be an absolute `https` URL, and an
  empty string on update clears it. Before, `/.well-known/agent.json` always served `url: ""`;
  now it serves the endpoint, and leaves `url` out for an agent that has none.

## [4.7.13] — 2026-11-05

### Fixed
- **Agent audit events carry the delegation chain and the tool invocation context** (#632). The
  `AgentDelegation` event now records `delegation_chain`: the user, then each actor from the
  earliest to the newest. An allowed `POST /v1/tools/invoke` now records `actor`, `on_behalf_of`,
  `delegation_chain`, `tool`, `token_jti` and `dpop_jkt` in its `AgentToolInvocation` event.
  Before, that event had no metadata, so an audit query by `tool` did not find it.

## [4.7.12] — 2026-11-04

### Fixed
- **An approval request past its `expires_at` reads `Expired`** (#632). Before, a request that
  expired without a decision stayed `Pending` in `GET /v1/approval-requests/{id}` and in the list,
  and `?status=expired` found nothing. Now get and list report it as `Expired`, `?status=expired`
  lists it, and `?status=pending` no longer does.

## [4.7.11] — 2026-11-04

### Fixed
- **Five more realm names are reserved** (#631). `config`, `identity-providers`, `abuse`,
  `webhooks` and `approvals` are admin console route keywords under `/ui/admin/realms/{realm}/`,
  but a realm could take one of these names and collide with an admin route. Realm create and
  realm rename now refuse them as reserved. An existing realm with one of these names does not
  change.

## [4.7.10] — 2026-11-03

### Fixed
- **The audit prune deletes in batches of 10 000 events** (#735). Before, the retention and row
  limit prune read every event that it deleted into memory, deleted them in one write, and blocked
  the realm's audit writes until the end. Now each batch streams its events and commits on its
  own, so the prune of a large log needs memory for one batch, and an audit write waits for one
  batch at most. If a batch fails, the batches before it stay deleted.

## [4.7.9] — 2026-11-03

### Fixed
- **The daily audit prune enforces the realm quota `max_audit_rows`** (#630). Before, it had no
  effect. The prune now keeps no more events than the lower of the audit `max_rows` and
  `max_audit_rows`, and deletes the oldest. The prune also counts the events, and measures the realm
  for `max_disk_bytes`, without loading them into memory.

## [4.7.8] — 2026-11-03

### Fixed
- **Realm quotas load from `hearth.yaml`** (#630). The documented `realms.<name>.quotas` block
  (`max_users`, `max_orgs`, `max_clients`, `max_agents`, `max_sessions`, `max_audit_rows`,
  `max_disk_bytes`) refused to boot, and no other way set a quota. It now loads, and a create at a
  count limit fails with `429` and `HEARTH_QUOTA_EXCEEDED`. Each quota check now counts keys up to
  the limit and reads no records; before, it read every record of its kind in the realm.
  `max_audit_rows` is accepted but not enforced yet.

## [4.7.7] — 2026-11-02

### Fixed
- **`POST /authorize` refuses a pushed request with an unsupported `response_mode`** (#628). With
  a PAR `request_uri`, `POST /authorize` and `POST /realms/{name}/authorize` ignored the pushed
  `response_mode`, so a pushed mode such as `query.jwt` got a code. Both routes now answer `400`
  `invalid_request` (`unsupported_response_mode`), as the browser `/authorize` does. For embedders
  of the engine, `authorize()` now uses the `response_mode` of a signed request object (RFC 9101
  §4) and refuses an unsupported one.
- **The SAML endpoints answer with `HEARTH_SAML_*` error codes** (#629). The ACS, metadata and
  begin endpoints under `/ui/realms/{realm}/federation/saml/` answered a refusal with plain text
  and no code. They now answer with the JSON error shape of the REST API (`error` and
  `error_code`): a parse, signature, validity, replay or `RelayState` failure is
  `HEARTH_SAML_INVALID` (`400`), and an IdP that is not a SAML IdP of the realm is
  `HEARTH_SAML_ENTITY_NOT_FOUND` (`404`; the ACS answered `400` for it). The `5xx` answers do not
  change.

## [4.7.6] — 2026-11-01

### Changed
- **The token endpoint answers `400` for `invalid_dpop_proof` and `use_dpop_nonce`** (#626). Both
  token routes (`/token` and `/realms/{name}/token`) answered `401`, so a DPoP client library
  could treat the refusal as an authentication failure and not retry with the nonce. RFC 9449 §5
  and §8 give `400`. The `DPoP-Nonce` header is unchanged. Resource endpoints still answer `401`
  with `WWW-Authenticate`. A client that retries on `401 use_dpop_nonce` from the token endpoint
  must also retry on `400`.

## [4.7.5] — 2026-11-01

### Fixed
- **A required password change before consent no longer sends the user back to the login page**
  (#627). When a user had to change their password (`UPDATE_PASSWORD`) during an authorization
  and the client then asked for consent, the password change revoked the browser session that the
  consent approval is posted from. The flow now opens a new browser session after the password
  change, with the same second-factor proof as the revoked one, and shows the consent page.

### Security
- **A DPoP proof that fails the key-binding check at the token endpoint no longer spends its
  `jti`** (#624). On the refresh-token and token-exchange grants, the proof key must match the
  grant family's key or the subject token's `cnf.jkt`. A proof from another key was refused but
  still recorded its `jti`, so the key holder's later proof with that `jti` was refused as a
  replay. The `jti` is now recorded after the check passes, and before tokens are issued.

## [4.7.4] — 2026-11-01

### Security
- **An HTTPS-namespaced custom claim name may contain only URI characters** (#625). A claim
  mapping whose name starts with `https://` was accepted with any characters after the host,
  including spaces and control characters. Config load now refuses a name with a character
  outside `A-Za-z0-9` and `-._~:/?#[]@!$&'()*+,;=%`, and the error names the claim. Rename such a
  claim before you upgrade.

## [4.7.3] — 2026-11-01

### Security
- **`POST /admin/realms` and `PATCH /admin/realms/{id}` check authentication first** (#623). Both
  routes are disabled (realms live in `hearth.yaml`) and answered `405` to any caller. A request
  without a token now gets `401`, and a token without `hearth.realm.admin` gets `403`; a realm
  admin still gets the `405`.

## [4.7.2] — 2026-10-31

### Changed
- **`POST /admin/users/import` takes a request body up to 16 MiB** (#714). The body limit was
  the 1 MiB default, so a request got `413` at about 3,800 entries with password hashes, below
  the cap of 10,000 entries per request. The import now checks the admin token before it reads
  the body: a request without a valid token gets `401` (it got `413` for a large body, or `422`
  for a malformed one). The admin API guide and the OpenAPI document state both limits.

## [4.7.1] — 2026-10-31

### Security
- **Sign-in refuses a stored PBKDF2-SHA256 hash whose digest is shorter than 16 bytes**
  (hardening). The user import refuses such a hash (#701); a hash that `hearth migrate keycloak`
  or `hearth migrate auth0` stored now gets the same check at sign-in. Keycloak writes a 32-byte
  digest. A user whose stored hash has a shorter digest cannot sign in with a password: reset that
  user's password.

## [4.7.0] — 2026-10-31

### Added
- **`POST /admin/users/import` takes a password hash for each user** (#701). An entry's optional
  `password_hash` is a PHC string from another system: bcrypt (`$2a$`, `$2b$`, `$2y$`), `$argon2id$`,
  `$scrypt$` or `$pbkdf2-sha256$`. The user signs in with their existing password, and the first
  successful sign-in replaces the hash with an Argon2id hash. The import refuses an entry, with an
  error in `results`, when its hash is malformed, in another format, or asks for a work factor above
  the ceilings that sign-in applies. The response never contains the hash. The SDK admin clients now
  type the import request (`AdminImportUsersRequest`, `AdminImportUserEntry`).

## [4.6.18] — 2026-10-31

### Fixed
- **`hearth migrate auth0` imports a user whose bcrypt hash starts with `$2y$`** (#703). PHP's
  `password_hash()` writes this prefix. The import refused such a hash as an unrecognized format,
  so the user was not imported at all. The user now signs in with their existing password, and the
  first successful sign-in replaces the hash with an Argon2id hash.

## [4.6.17] — 2026-10-31

### Changed
- **`hearth backup keygen` writes a PKCS#8 v1 key** (#690): the key file had the PKCS#8 v2 form
  (RFC 5958, with the public key), which OpenSSL 3.0 (the version on Ubuntu 24.04) cannot read, so
  the `openssl pkey` command in the backup guide failed on such hosts. keygen now writes the v1
  form that `openssl genpkey -algorithm ed25519` writes. Keys from earlier versions keep working:
  Hearth reads both forms.

## [4.6.16] — 2026-10-30

### Fixed
- **A backup of a large realm no longer stops writes for most of an hour** (#695): `POST /admin/backup`
  read users 200 at a time, and each page walked every user key in the realm. Every write on the
  node (sign-in, token refresh, sign-up, admin changes, audit records) waits while a backup reads a
  realm, and at 1,000,000 users the reads took 36 minutes. A backup now reads the users in one
  walk. Writes still wait while a backup reads a realm, for a shorter time.

## [4.6.15] — 2026-10-29

No changelog entries for this release. The [GitHub release](https://github.com/hearth-auth/hearth/releases/tag/v4.6.15) lists its commits.

## [4.6.14] — 2026-10-29

### Fixed
- **A restore keeps each OAuth client's creation time** (#675): `hearth backup restore` gave each
  restored client the restore time as `created_at`, so the admin API and the admin console showed
  every client as new. A restore now keeps the archived creation time. Clients from the Auth0 and
  Keycloak migrations and from `hearth.yaml` still get the import time.

## [4.6.13] — 2026-10-29

### Changed
- **Go SDK: the Echo adapter uses Echo v5** (#688): `hearthecho` used `github.com/labstack/echo/v4`,
  which has two advisories with no v4 fix (GHSA-99jh-6h7p-pp36 in the reverse-proxy middleware,
  GHSA-246p-cpwv-v3jq in the rate limiter). It now uses `github.com/labstack/echo/v5` v5.4.2.
  **Breaking for Echo users:** your application must move to Echo v5, and handlers and the
  `WithTokenExtractor` and `WithOnUnauthorized` callbacks take `*echo.Context` instead of
  `echo.Context`. The SDK's other middleware does not change.

## [4.6.12] — 2026-10-28

### Changed
- **Cluster mode needs an explicit opt-in** (#650): cluster mode is experimental, and a node cut
  off from the leader can serve revoked sessions, lockout counts are per node, and the audit
  chain can fork. It used to start with only a warning. Startup and `hearth config validate` now
  refuse a `cluster:` section without `experimental_opt_in: true`, and the error names the key.
  **Breaking for cluster operators:** add `experimental_opt_in: true` to the `cluster:` section of
  each node before you upgrade. Single-node deployments are not affected, and one node is the
  supported deployment.

### Fixed
- **The purged-log startup refusal no longer tells operators to start a cluster node empty**
  (#670): the message said to move the node's data directory aside and start it empty under its
  old ID. The data directory holds `raft.db`, the node's Raft vote, and a node that forgets its
  vote can help elect a second leader. The message now says not to, and gives only the rebuild
  from a backup.
- **Python SDK: the device flow works, and the middleware answers 401 to a missing or invalid
  token** (#634): `start_device_flow()` posted to `/realms/{realm}/device/authorize`, which the
  server does not serve, so the device flow always failed with `404`. It now posts to the
  `device_authorization_endpoint` of the realm's discovery document, and raises `DiscoveryError`
  when discovery fails or names no such endpoint. The ASGI, WSGI and Django gates answered `403`
  to a missing or invalid token. They now answer `401` with `WWW-Authenticate: Bearer
  realm="hearth"`, with `error="invalid_token"` for a token that does not verify or that
  introspection reports as inactive. A valid token without the permission still gets `403`. In
  decision mode the server answers a bad token like a missing permission, so both get `403`.
- **Go SDK: calls time out, endpoints come from discovery, token requests are form-encoded, and the
  middleware answers 401 to a missing or invalid token** (#633): `NewClient` built an HTTP client
  with no timeout, so a server that never answered hung the caller. Every call now times out after
  10 s (`hearth.DefaultHTTPTimeout`); the new `WithHTTPTimeout` option sets another limit. The
  token, device-authorization, introspection and userinfo calls used paths that the SDK built
  itself, and `VerifyToken` guessed `{baseURL}/.well-known/jwks.json` when discovery failed. They
  now use the endpoints of the discovery document, fetched once per client, and a failed discovery
  returns `*DiscoveryError`. The token and device-authorization calls sent JSON; they now send
  `application/x-www-form-urlencoded` (RFC 6749, RFC 8628). The SDK sent `X-Realm-ID` to realm
  endpoints (`/realms/{realm}/...`), which the server refuses with `400 realm_mismatch` when the
  header does not name the realm in the path; it now sends the header only to global endpoints.
  `RequirePermission` answered `403` to a request without a token, and sent `401` without
  `WWW-Authenticate`. It now answers `401` with `WWW-Authenticate: Bearer realm="hearth"` (and a
  custom `OnUnauthorized` runs, not `OnDenied`), with `error="invalid_token"` for a token that does
  not verify or that introspection reports as inactive. A valid token without the permission still
  gets `403`; in decision mode the server answers a bad token like a missing permission, so both get
  `403`. In embedded mode the handler reads the verified claims with `hearth.ClaimsFromContext`.

## [4.6.11] — 2026-10-28

### Fixed
- **ID tokens name the sign-in methods in `amr`** (#619): no sign-in flow filled the `amr` claim,
  so a relying party could not check from the ID token that the user passed MFA. The ID token and
  the access token now carry RFC 8176 values: `pwd` for a password, `otp` for a TOTP or recovery
  code, `hwk` and `user` for a passkey, and `mfa` when the sign-in proved a second factor that the
  MFA policy accepts. A magic link, an email OTP and a federated sign-in add no value, and a token
  with no value has no `amr` claim. Browser sessions opened before this release do not record how
  the user signed in, so their tokens name only the second factor until the user signs in again. A
  sign-in that waits for its second factor during the upgrade starts again.
- **PHP SDK: `checkDecision()` asks the decision endpoint and fails closed** (#635): it posted to
  the OIDC `authorization_endpoint` from discovery instead of the decision endpoint
  `POST /oauth/authorize`, and it threw on a network error or an error answer. It now posts the
  token and `permission` (plus optional `organization_id` and `resource`) to `/oauth/authorize`
  and returns `['allowed' => false]` on any failure, without throwing. Only an explicit
  `"allowed": true` allows. The endpoint reads the realm from `X-Realm-ID`, so the call needs the
  new `realmId` argument of `HearthClient` (Laravel: `realm_id`, env `HEARTH_REALM_ID`), and
  throws `ConfigurationException` before sending anything when it is not set.
- **PHP SDK: an unreachable JWKS endpoint throws `JWKSFetchException`** (#635): a connection
  failure threw `NetworkException`, and a JWKS body that is not JSON threw a raw `JsonException`.
  Both now throw `JWKSFetchException`, with the original error as the previous exception, so one
  `catch (JWKSFetchException)` handles every JWKS outage.
- **TypeScript SDK: an unreachable JWKS endpoint throws `JWKSFetchError`** (#635): a refused
  connection or a timeout surfaced as the raw `fetch` error, a body that is not JSON as a
  `SyntaxError`, and a document without a `keys` array as a `jose` error. `JwksClient.verify()`
  and `HearthClient.verifyToken()` now throw `JWKSFetchError` for each, with the original error
  as its `cause`.
- **Backups carry the webhook subscriptions that deliver events** (#654): a backup exported the
  webhooks of a store that the webhook sender never read, and not the subscriptions made under
  `/admin/webhooks` or in the admin console. A restore lost every working webhook, with no error.
  The archive now has a `webhook_subscriptions.ndjson` member with each subscription and its
  signing secret, and a restore brings them back under their original IDs. A `webhooks.ndjson`
  member in an older archive is skipped and counted as `old webhooks`, because those webhooks never
  delivered. Archives made before this release do not hold the working subscriptions: after you
  restore one, create the webhooks again. `POST /admin/backup` and `POST /admin/backup/restore`
  answer `501` on a server without the webhook engine, which `hearth serve` always has.

### Security
- **Capped emails are audited** (#622): when the A-4 outbound volume shield or the A-50
  cross-realm cap stopped or flagged an email, the server only logged a warning. It now writes an
  `AbuseDetected` audit event in the sending realm, so a `security.abuse_detected` webhook
  receives it. The metadata has `guard` (for example `a4_email_hard_cap`), `flow`
  (`password_reset`, `verification`, `magic_link` or `password_email`) and `sent`, and no
  recipient address or realm count. At most one event is written per guard and realm in the
  guard's window.
- **A restore keeps each user's required actions, email verification and email codes** (#672):
  `hearth backup restore` re-created every user without its required actions, its email
  verification, its email-code second factor and its timestamps. After a restore, a forced
  password update set by an admin was gone, a user who used email codes as a second factor no
  longer had that factor, and every verified address was unverified. A restore now gives back
  each user as archived. Archives made by earlier versions already hold these fields.

## [4.6.10] — 2026-10-28

### Security
- **Role changes through the REST admin API are audited** (#620): assigning a role to a user or a
  group, removing a role assignment, and adding or removing an extra organization role through
  `/admin/*` wrote no audit event. The admin UI wrote one for the same changes. Each of these
  routes now writes `RoleAssigned` or `RoleRevoked` with the admin as the actor, the user or group
  as the resource, and the role, its scope and `via: api` in the metadata.
- **A delegated token is issued only with its audit record** (#621): an RFC 8693 token exchange
  issued the delegated token even when its `AgentDelegation` audit event failed to write. The
  exchange now fails with a server error and stores no delegation grant. An agent that the rate
  monitor suspends is now audited with actor `system` and `signal: agent_rate_limit`, and a
  suspension that fails is logged at `error`.

## [4.6.9] — 2026-10-28

### Security
- **Go SDK: `go-jose` 4.1.6** (#677): the Go SDK parses the JWKS that it fetches with `go-jose`,
  and a JWKS that holds RSA keys can cause a denial of service in `go-jose` 4.1.5 and older
  (GHSA-mgcc-cww5-fp2q). The SDK now requires 4.1.6. Update the SDK, or run
  `go get github.com/go-jose/go-jose/v4@v4.1.6` in your module.

## [4.6.8] — 2026-10-27

### Fixed
- **Webhooks made in the admin UI now receive events** (#617): the admin UI saved webhooks in a
  store that the webhook sender does not read, so they never received an event, and the UI did not
  list webhooks made through `/admin/webhooks`. Also, the create and edit forms answered `400`
  whenever an event box was ticked. The UI pages now use the same store as the REST API, and the
  forms accept any number of events. Webhooks made in the UI before this release never delivered:
  make them again. The create form now has the same rules as the REST API: a signing secret of at
  least 16 bytes, and the URL check that refuses private and reserved addresses. The edit form no
  longer shows the stored secret; leave the field blank to keep it.
- **`hearth rbac orphans purge` deletes only orphans** (#618): the command deleted every
  extra-permission grant in the system realm, whatever `--realm` said, and wrote no audit event.
  `list` showed the same wrong set. Both commands now find orphans with the rule of the startup
  orphan summary: an extra grant of a permission that `hearth.yaml` no longer declares, and an
  assignment of a role that is archived or no longer exists. `--realm` takes a realm UUID or name;
  without it, the commands check every realm. The purge writes a `UserPermissionRevoked` or
  `RoleRevoked` audit event (actor `cli`) for each orphan that it deletes.

## [4.6.6] — 2026-10-26

### Added
- **`storage.max_writes_in_flight`** (default `32`) and the metrics
  `hearth_storage_writes_in_flight`, `hearth_storage_write_permits` and
  `hearth_storage_writes_shed_total` (#596): the single-node write limit below.

### Fixed
- **A stalled disk no longer leaves hundreds of extra threads** (#596): on a single node, when
  the disk stopped completing syncs, each write that arrived waited and held its own thread, and
  the server kept those threads after the disk recovered. In one test run, a 9-second stall took
  the server from 148 to 523 threads. Now at most `storage.max_writes_in_flight` writes are in
  progress at once. A write over the limit is refused before it starts with `503`, `Retry-After`
  and `HEARTH_CLUSTER_UNAVAILABLE`, and nothing is written. Writes that wait at a backup export's
  barrier count toward the limit too.

### Security
- **zstd 0.14.3** (RUSTSEC-2026-0391, RUSTSEC-2026-0398, RUSTSEC-2026-0403,
  RUSTSEC-2026-0410): backup archives use zstd 0.14.3 (zstd-safe 8.2.0, zstd-sys 2.1.2).
  Hearth does not give zstd a borrowed context, read seekable archives, or build for
  WebAssembly, so three of the advisories do not apply. A restore and a signature check
  decompress the archive that they are given, so the fix for legacy frames (RUSTSEC-2026-0403)
  applies. The three zstd crates are now licensed BSD-3-Clause (`THIRD_PARTY_LICENSES`).

## [4.6.5] — 2026-10-26

### Fixed
- **Device-approval lockout history leaves memory after its cooldown** (#581): on
  `POST /ui/device`, a user's lockout history stayed in memory after the 7-day cooldown reset
  it. It now leaves memory. Lockouts and their escalation do not change.
- **Realm deletes and audit imports free their per-realm state** (#581): deleting a realm now
  also removes the realm's cached dummy password hash from memory. A finished import of audit
  events no longer keeps a lock in memory for its realm.
- **The start of a passkey ceremony examines only expired challenges** (#581): each passkey
  registration or sign-in start removes the expired pending challenges. Before, it examined
  every pending challenge of every realm.

## [4.6.4] — 2026-10-25

### Changed
- **Less memory per server thread** (#581): each thread's jemalloc cache now keeps freed objects
  of 4 KiB or less (jemalloc's default is 32 KiB), and on a single node a storage point read no
  longer hands its runtime worker's tasks to another thread. Under steady load the Tokio blocking
  pool keeps its threads, so their per-thread memory added up; `hearth_allocator_tcache_bytes`
  shows the cache part.

## [4.6.3] — 2026-10-24

### Security
- **Audit events only for realms that exist** (#581): the server's audit engine refuses an
  event whose realm does not exist, before it creates any per-realm state. Before, a request
  that named an unknown realm ID and reached an audit append (for example, a sign-in that an
  abuse guard challenged) could add a chain lock and an HMAC key in memory, and stored rows, for
  that ID. Nothing removed them. Events for the system realm and for existing realms do not
  change.
- **Per-realm DPoP state only for realms that exist** (#581): Hearth creates a realm's DPoP
  nonce secret, and records a DPoP proof's `jti`, only when the realm in the request exists. A
  request for an unknown realm gets the server-wide DPoP nonce, and a proof under an unknown
  realm is refused. Before, each unknown realm ID in a request could add an entry in memory and
  a stored row that nothing removed. The per-realm replay lock map now also keeps an entry only
  while a request holds the lock.

### Changed
- **Device approval forgets a day-old wrong-code count** (#581): on `POST /ui/device`, a
  user's count of wrong user codes below the lockout ceiling restarts from zero after 24 hours
  with no new wrong code, as it does after a correct code. Old counts also leave memory. Before,
  each count stayed until the user's next correct code. Lockouts and their escalation do not
  change.
- **A failure count below the lockout threshold is forgotten after 24 hours** (#581): a
  per-account count of wrong passwords or wrong MFA codes that has not reached the lockout
  threshold, with no new failure for 24 hours, is cleared in memory and in storage, as a
  successful sign-in clears it. Before, it stayed until the user's next successful sign-in, so
  memory grew with every account that ever had a wrong password. A count at the threshold does
  not change: after the lockout ends, the next wrong password locks the account again.

### Fixed
- **Session limit no longer keeps one lock per user** (#581): in a realm with
  `max_concurrent_sessions`, the lock that makes the session count and the new session atomic
  stayed in memory for every user who ever signed in. It now exists only while a sign-in holds
  it.

## [4.6.2] — 2026-10-24

### Security
- **tokio 1.53.3** (RUSTSEC-2026-0386): the server builds with tokio 1.53.3. The advisory is
  about `AsyncFd` constructors that accept a file descriptor the caller does not own. Hearth
  does not call `AsyncFd`, so no known path in Hearth reaches the flaw.
- **Go SDK: echo 4.16.1** (GHSA-9969-6676-49h5, GHSA-cxf3-9h37-7rr8, GHSA-f48p-c9v4-h7xv,
  GHSA-h7wr-284f-5qvc): the SDK's echo middleware (`hearth/echo`) requires
  `github.com/labstack/echo/v4` 4.16.1 or later, so an application that uses it gets the echo
  fixes. The SDK also builds and tests with go1.26.10.

## [4.6.1] — 2026-10-23

### Fixed
- **Writes no longer stall at the end of each compaction** (#445): the SST writer syncs the
  file every 4 MiB while it writes it, not only once at the end. One sync at the end sent a
  whole compaction output (up to ~1 GB in the steady-state memory test) to the disk at once,
  and writes waited behind it for up to seconds. Each waiting write kept a thread, so the
  server's thread count and memory grew at compactions and never went down.

## [4.6.0] — 2026-10-22

### Added
- **`hearth_allocator_tcache_bytes` on `/metrics`** (#445): the bytes of freed allocations that
  the allocator's thread caches keep for reuse. jemalloc counts them in
  `hearth_allocator_allocated_bytes`, so `allocated` minus this gauge is closer to the live heap.
  Absent where the other allocator gauges are absent (Windows).

## [4.5.1] — 2026-10-21

No changelog entries for this release. The [GitHub release](https://github.com/hearth-auth/hearth/releases/tag/v4.5.1) lists its commits.

## [4.5.0] — 2026-10-21

### Added
- **`heap-profile` cargo feature** (#445): a build with jemalloc's heap profiler, for memory
  soaks. With `prof:true` in `_RJEM_MALLOC_CONF`, the server writes a heap profile every
  `HEARTH_HEAP_PROFILE_INTERVAL_SECS` (default 900). Release builds and images do not include
  it.

## [4.4.0] — 2026-10-21

### Added
- **`hearth_allocator_*_bytes` on `/metrics`** (#445): the memory figures of the server's
  allocator (jemalloc), read at each scrape: `allocated`, `active`, `resident`, `metadata` and
  `retained`. Next to the process RSS, they tell live heap apart from memory the allocator keeps
  after the server frees it. The gauges are absent on Windows, where the server keeps the
  system allocator.

## [4.3.1] — 2026-10-21

### Security
- **TLS certificate checks reject the distrusted emSign intermediates** (RUSTSEC-2026-0381,
  RUSTSEC-2026-0382). The private keys of these intermediate certificates are public, so a
  certificate path through them proves nothing. `rustls-webpki` 0.103.16 rejects such paths.
  `webpki-roots` 1.0.10 removes the `emSign ECC Root CA - G3` root from the trust store of
  Hearth's outbound HTTPS and SMTP connections (federation, webhooks, email, OTLP export).

## [4.3.0] — 2026-10-19

### Added
- **`hearth_storage_hot_tier_bytes` and `hearth_storage_block_cache_bytes` on `/metrics`**
  (#445): the memory the two storage caches hold. The hot tier's figure is its tables plus its
  cached keys and values; the block cache's is the bytes it charges against
  `storage.block_cache_bytes`. Both caches stop at their capacity, but the default hot tier can
  take days to fill, and its tables grow in steps. With these gauges, memory that a filling
  cache holds is told apart from a leak.

## [4.2.4] — 2026-10-17

### Fixed
- **`POST /admin/users/import` no longer stops every write when several imports run at the
  same time (#536).** In 4.2.3 an import could wait for a write that only its own fsync makes
  durable. It then waited for ever, every other write of the server waited for it, and the
  server did not stop on `SIGTERM`. Eight concurrent 10,000-user requests caused this in less than
  30 seconds. One import on a server with other write load can also cause it: upgrade from 4.2.3
  before you import users.

## [4.2.3] — 2026-10-17

### Fixed
- **The expiry sweep keeps up under sustained sign-in load (#536).** It deleted expired rows one
  at a time, and each delete waited for its own fsync. On a cloud disk that capped it at about a
  hundred deletes a second, fewer than a busy server expires. Expired grant families, sessions and
  single-use markers then built up on disk, and in the hot tier, without a limit. The sweep now
  deletes each chunk of up to 512 expired rows in one durable write. Its log line also reports the
  single-use markers and the total.
- **`POST /admin/users/import` no longer times out on large requests (#536).** Each user waited
  for two fsyncs, so a request with 10,000 users (the documented maximum) ran past the 30-second
  request timeout on a cloud disk. The client got a `504` while the server went on importing, and
  a retry failed with "email exists". Each user's rows and audit event are now one write, and the
  writes of up to 64 users share one fsync.

## [4.2.2] — 2026-10-16

### Changed
- **The Linux and macOS binaries allocate through jemalloc (#445).** Under sustained load, glibc's
  malloc kept the pages that live objects pinned in its arenas, and Hearth's resident memory crept
  up for hours while its live data stayed bounded. jemalloc returns freed pages to the system a
  few seconds after they are freed. The Windows binary keeps the system allocator.
  `MALLOC_ARENA_MAX` and the glibc arena cap now apply only to the C libraries that Hearth links,
  such as zstd. In the arm64 Linux binary and image, jemalloc is built for 64 KiB pages, so it
  runs on arm64 kernels with 4 KiB or 64 KiB pages.

## [4.2.1] — 2026-10-15

### Security
- **rustls 0.23.46** fixes four advisories in the TLS library: RUSTSEC-2026-0346 (`Debug` output of
  client session values showed TLS secrets), RUSTSEC-2026-0347 (application data after an ECH
  rejection went to the outer server), RUSTSEC-2026-0348 (Brotli certificate decompression could
  allocate up to 1 GiB before authentication) and RUSTSEC-2026-0349 (an unauthenticated
  ServerHello could downgrade later connections to classical key exchange).

## [4.2.0] — 2026-10-14

### Added
- **`POST /admin/users/{id}/password-email`: let a user choose a password.** An application that
  creates users through the admin API or SCIM can now email the user a single-use link. A user
  with no password gets the `welcome` email with a set-password link; a user with a password gets
  the reset email. The response names the kind (`PASSWORD_EMAIL_KIND_SETUP` or
  `PASSWORD_EMAIL_KIND_RESET`). It needs `hearth.users.admin` and the admin ceiling, and shares the
  reset limit (3 per address per 15 minutes) and the outbound email caps. The SDKs add
  `sendPasswordEmail` (TypeScript, PHP), `SendPasswordEmail` (Go) and `send_password_email`
  (Python).
- **`realms.<name>.auth.token.set_password_token_ttl`** (default `72h`, capped at `7d` unless
  `allow_unsafe_ttl: true`): the lifetime of the set-password link. A reset link keeps
  `password_reset_token_ttl` (default `30m`).
- **A built-in `welcome` email template** with the `{{set_password_url}}` and `{{user_email}}`
  placeholders. The `welcome` kind of `email_templates` existed, but Hearth never sent it.

### Changed
- **The console's "Send reset email" and bulk "Send invite" actions send the welcome email to a
  user with no password**, with the 72-hour set-password link, instead of a 30-minute reset link.
  They now also apply the outbound email caps (A-4, A-50). The reset page says "Set your password"
  for a set-password link.

## [4.1.0] — 2026-10-14

### Added
- **SCIM 2.0 under the realm path, `/realms/{realm_name}/scim/v2`** (OpenSpec `scim-realm-path`):
  the path selects the realm, so an IdP needs only this base URL and a bearer token. Okta and
  Entra ID can now provision without a custom `X-Realm-ID` header or a proxy that adds one. The
  realm path takes the realm's SCIM provisioning token or an admin token of the realm, and keeps
  the DPoP sender constraint. An `X-Realm-ID` that names another realm is `400`
  (`realm_mismatch`); an unknown realm name is `404`. `meta.location` and the `Location` header
  use the base URL the request used. `/scim/v2` with `X-Realm-ID` still works. The SCIM guide now
  recommends the realm path.

## [4.0.0] — 2026-10-14

### Changed
- **BREAKING: entity IDs are bare UUIDs everywhere.** A user's access, refresh and ID tokens
  carry `sub` = the user's bare UUID, the same `id` that the admin API and SCIM return. Before,
  `sub` was `user_<uuid>`, so an application could not match a token with the user record it
  provisioned. `sid`, `tid` and `oid` are bare UUIDs too, and so are the back-channel logout
  token's `sub` and `sid`, the agent API's `agent_id`, audit records, the pre-token webhook
  payload and the backup manifest's `realm_id`. A client's own token (`client_credentials`,
  JWT-bearer) keeps `sub` = `client_<uuid>`, and an agent's token keeps `sub` = `agt_<uuid>`, so
  `sub` still tells a user from a client or an agent. Hearth still accepts the prefixed forms
  wherever it reads an ID, so a token issued before the upgrade stays valid until it expires.
  Delegation grants stored before the upgrade no longer show in the user's consent list and
  expire on their own.
- **BREAKING (Go SDK): the module path is `github.com/hearth-auth/hearth/sdks/go/v4`.** The SDKs
  move to 4.0 with the server, and Go installs a v4 release only from a `/v4` module path. Change
  each import from `.../sdks/go/v3/...` to `.../sdks/go/v4/...`.

## Older releases

The notes for releases 1.0.0 to 3.5.13 (2026-06-21 to 2026-10-14) are not in this file. Read
them in [CHANGELOG.md at `53550749`](https://github.com/hearth-auth/hearth/blob/53550749a806b7fc896316ad2b2fa2c592c0a576/CHANGELOG.md#101--3513--2026-06-23-to-2026-10-14).
Each release also has a git tag (`v1.0.0` to `v3.5.13`).
