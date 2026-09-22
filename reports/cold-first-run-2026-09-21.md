# The first hour, as a stranger

Tasks 23.19 (cold first-run with a transcript) and 23.6 (re-run P31, the day-2
upgrade and the cold first-run).

Everything below was run on 2026-09-21 against `cfb6c4f5`, following the README
and `docs/` only. Where a step failed, the failure is quoted verbatim; nothing
here is reconstructed from the source. Source was read only *after* a step
failed, to say whether the defect is in the code or in the prose.

**Headline.** The `--dev` path is in excellent shape: every step of the README's
30-second block and its nine-step curl walkthrough worked first time, including
the full PKCE flow. **The production path does not survive contact with its own
documentation.** A new operator following `README.md` → `hearth.example.yaml` →
`docs/guides/upgrading.md` hits, in order: a config file that cannot validate
(22 errors, 20 of them from *commented-out* lines), a `config validate` that
passes a config `serve` then rejects, no documented way to create the first
admin at all, and a pre-upgrade backup step that cannot run — first because the
server is still up, then because the archive exporter cannot read a
KEK-encrypted store by any route.

| | |
|---|---|
| Findings | **17** — 6 code, 9 documentation, 2 both |
| Blocker-class | **2** (C-1 backup of a production store is impossible; D-1 example config does not validate) |
| Task 23.6 verdict | **Could not determine empirically within this pass** — see §4. The format-level evidence says *yes*, and it is strong. |

---

## 0. Deviations from a true cold run

Stated up front so nothing below is over-claimed.

| Deviation | Why | Effect |
|---|---|---|
| The repo was already cloned; `git clone` was not run. | Shared worktree with live sibling agents. | None — `make setup` and every build prerequisite were still exercised from scratch. |
| `CARGO_TARGET_DIR=/scratch/cache/target`, `CARGO_BUILD_JOBS=2`, `nice -n 15`. | Machine is shared; CPU discipline is mandatory for this wave. | The binary lands at `/scratch/cache/target/release/hearth`, not `./target/release/hearth`. Referred to below as `hearth`. |
| `make tailwind-install` was **not** run. | It would overwrite this box's existing `ui/tailwindcss`, which other agents depend on. | The installed CLI was checked instead: `ui/tailwindcss --help` → `tailwindcss v3.4.17`, exactly the version the target pins. |
| Servers ran on ports 18420 (dev) and 18999 (prod), data dirs under `/scratch/tmp/coldrun/`. | Must not touch the repo or the default port. | URLs below show the real port used. |
| The full test suite was not run. | Forbidden for this wave. | No claim is made here about test results. |

---

## 1. Clone to running

### 1.1 Prerequisites

```
$ for b in protoc buf jq cargo rustc openssl cosign helm docker; do ...
protoc   /home/brad/.local/bin/protoc
buf      /home/brad/.local/bin/buf
jq       /run/current-system/sw/bin/jq
cargo    /home/brad/.cargo/bin/cargo
rustc    /home/brad/.cargo/bin/rustc
openssl  /run/current-system/sw/bin/openssl
cosign   MISSING
helm     /home/brad/.local/bin/helm
docker   /run/current-system/sw/bin/docker

$ protoc --version   →  libprotoc 29.3
$ cargo --version    →  cargo 1.97.0
$ grep rust-version Cargo.toml  →  rust-version = "1.88.0"
```

README § Prerequisites names Rust 1.88.0+, `protoc`, and `buf` ("optional — only
needed if you edit `proto/**/*.proto`"). All three claims hold. `CLAUDE.md` says
`buf` is "**required**", which is true for the pre-commit hook and CI but not for
a plain build; the README's framing is the correct one for a new operator and
was left alone.

`cosign` is missing on this host, so the README's signature-verification block
under § Install was not executed. Recorded as untested, not as a failure.

### 1.2 `make setup`

```
$ make setup
git config core.hooksPath .githooks
✓ Git hooks enabled (.githooks/pre-commit)
```

Works as documented.

### 1.3 `make tailwind-install`

Not executed (see §0). The pinned version matches:

```
$ ui/tailwindcss --help | head -3
tailwindcss v3.4.17
```

### 1.4 Build

README § Quick Start step 1 is `cargo build --release`.

```
$ PROTOC=$(which protoc) CARGO_TARGET_DIR=/scratch/cache/target \
  CARGO_BUILD_JOBS=2 nice -n 15 cargo build --release
   Compiling … (369 crates)
warning: hearth@1.6.11: Tailwind CSS rebuilt
    Finished `release` profile [optimized] target(s) in 7m 38s

$ hearth --version
hearth 1.6.11-143-gcfb6c4f5
```

Clean. Two things a cold operator should be told and is not:

* `build.rs` **runs Tailwind** — the `warning: Tailwind CSS rebuilt` line above.
  README § Prerequisites lists `protoc` but not `ui/tailwindcss`, so a plain
  `cargo build --release` on a fresh clone is quietly dependent on a binary the
  README never mentions. It did not fail here because `ui/tailwindcss` was
  already present. **Untested on a host without it** — recorded as a gap, not a
  confirmed break.
* The version string is derived by `build.rs` from `git describe`, so a
  source tarball with no `.git` reports the `Cargo.toml` version instead. Noted
  because it matters in §4.

---

## 2. The `--dev` path — everything worked

### 2.1 Start and health

```
$ HEARTH_DEV_DATA_DIR=/scratch/tmp/coldrun/devdata2 hearth serve --dev --port 18420
  Identity · Auth · RBAC   v1.6.11-143-gcfb6c4f5  [dev]
  API:     http://127.0.0.1:18420
  Admin:   http://127.0.0.1:18420/ui
  Setup:   http://127.0.0.1:18420/ui/setup  (token prefix: c2asy6Km… — read .setup_token for full token)
  Mail:    http://127.0.0.1:18420/dev/mail  pw: WWo7V2Gn30i8ZM8j
  Realms: 0   ·   Email: mailcatcher   ·   TLS: off
  Startup: 62 ms
HTTP server listening local_addr=127.0.0.1:18420
```

```
$ curl -sS -D- http://127.0.0.1:18420/health   → 200 {"status":"ok"}
$ curl -sS -D- http://127.0.0.1:18420/healthz  → 200 {"status":"ok"}
$ curl -sS -D- http://127.0.0.1:18420/readyz   → 200 {"status":"ready","storage":"ok"}
```

All three match the documented bodies exactly, including `upgrading.md`'s
Kubernetes probe table. `/metrics` answers `404` when unconfigured, which is the
correct fail-closed shape.

### 2.2 Bootstrap

```
$ curl -sS -X POST http://127.0.0.1:18420/admin/bootstrap
http=200
realm_id / user_id / access_token / refresh_token / quickstart /
admin_password (14 chars) / system_access_token / system_realm_id
```

Field-for-field what the README documents. Re-bootstrap behaves as documented in
shape but not in type — see **D-4**:

```
$ curl -X POST .../admin/bootstrap                       → 401 {"error":"missing authorization header"}
$ curl -X POST -H "Authorization: Bearer $AT" .../admin/bootstrap
  → 200 {"admin_password": null, ...}
```

### 2.3 The nine-step curl walkthrough

Run verbatim from README § End-to-End curl Walkthrough, substituting port 18420:

```
step2 register client → {"client_id":"d29ec85c-…","client_name":"my-app",
                         "grant_types":["authorization_code"],…}   (no client_secret echoed ✓)
step3 PKCE            → challenge=Zlnk8zF2WR5O0CQmFAGLMGXA9vIl0t15xH-s2HTyF94
step4 POST /authorize → {"code":"ywH23ryWtXiyJ-6tKN48HQDh5ifEOXPFZ4pPs0jvBjU","state":"60e06a…"}
step5 POST /token     → {"has_access":true,"expires_in":900,"token_type":"Bearer"}
step7 /userinfo       → 200 {"email":"admin@dev.local","email_verified":true,
                             "name":"Dev Admin","sub":"user_b5fdabb4-…"}
step8 /v1/me/permissions → 200 {"roles":["realm.admin"],"groups":[],
                                "permissions":[… 17 …],"scope":null}
```

Every step first time, no corrections. This is the best-documented surface in the
repo and it earns that.

### 2.4 Browser login

```
$ GET  /ui/admin/login                                        → 200 (form: _csrf, email, password, locale)
$ POST /ui/admin/login  email=admin@hearth.test   pw=<bootstrap>  → 303 → /ui
       set-cookie: hearth_ui_session=…00000000-0000-0000-0000-000000000000…
       set-cookie: hearth_ui_last_realm=__system__
$ POST /ui/admin/login  email=admin@dev.local     pw=<bootstrap>  → 401
$ POST /ui/admin/login  email=admin@hearth.test   pw=wrong        → 401
$ GET  /ui            (with cookie) → 200  <title>Hearth · Dashboard</title>
$ GET  /ui/admin      (with cookie) → 307 → /ui/admin/realms
$ GET  /admin         (with cookie) → 404
```

`CLAUDE.md`'s credentials are right and the README's are right; **they are not
the same account** and neither document says so — see **D-3**.

### 2.5 Admin API with the bootstrap tokens

```
$ curl -H "Authorization: Bearer $ADMIN_TOKEN" /admin/realms
  → 400 {"error":"missing X-Realm-ID header"}
$ curl -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-Realm-ID: $REALM_ID" /admin/realms
  → 200 {"items":[{"name":"dev-realm","status":"REALM_STATUS_ACTIVE",…}]}
$ curl -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-Realm-ID: $REALM_ID" /admin/users
  → 200 {"items":[{"email":"admin@dev.local","display_name":"Dev Admin",…}]}
$ curl -X POST -H "Authorization: Bearer $SYSTEM_TOKEN" \
       -H "X-Realm-ID: $SYSTEM_REALM_ID" /admin/realms/$REALM_ID/rotate-signing-key
  → 200
```

The first line is the interesting one: the command as printed in `CLAUDE.md` and
in `docs/guides/upgrading.md` § Post-upgrade verification **fails**. See **D-2**.

---

## 3. A non-dev first run

### 3.1 The example config does not validate

README § Configuration: *"Copy `hearth.example.yaml` to `hearth.yaml` and edit.
Every section is `#[serde(default)]`, so you can omit anything you don't want to
change."* `hearth.example.yaml`'s own header adds: *"An empty file (`{}`) starts
Hearth."*

```
$ cp hearth.example.yaml /scratch/tmp/coldrun/prod/hearth.yaml
$ hearth config validate hearth.yaml
✗ Configuration invalid — 22 error(s):

  ${HEARTH_KEK}: environment variable HEARTH_KEK is not set (substituted empty string) …
  ${SMTP_USERNAME}: …
  ${SMTP_PASSWORD}: …
  ${SENDGRID_API_KEY}: …          ${POSTMARK_SERVER_TOKEN}: …
  ${MAILGUN_API_KEY}: …           ${MAILTRAP_API_KEY}: …
  ${TWILIO_AUTH_TOKEN}: …         ${VAR}: …
  ${AWS_ACCESS_KEY_ID}: …         ${AWS_SECRET_ACCESS_KEY}: …
  ${HEARTH_METRICS_TOKEN}: …      ${HEARTH_DPOP_NONCE_SECRET}: …
  ${HEARTH_BACKUP_VERIFY_KEY}: …  ${PEPPER_KEY_HEX}: …
  ${OLD_PEPPER_HEX}: …            ${HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET}: …
  ${INTERNAL_API_SECRET}: …
  security.key_encryption_key: production mode requires a key-encryption key …
  server.tls_cert_path: production mode requires HTTPS …
EXIT=1
```

`serve` agrees exactly — same 22 errors, then `error: invalid configuration for
'${HEARTH_KEK}'`. So `config validate` and `serve` are consistent *here*; §3.3
is where they part company.

**All twenty placeholder errors come from lines that are commented out.** Every
one of them is behind a `#`:

```
$ grep -n '\${' hearth.example.yaml
68:#   key_encryption_key: "${HEARTH_KEK}"
85:#     username: "${SMTP_USERNAME}"
…
255:  #     auth_token: "${TWILIO_AUTH_TOKEN}"   # load from env via ${VAR}
…
649:#         client_secret: "${INTERNAL_API_SECRET}"
```

Substitution runs over the raw file text before the YAML parse, so a comment is
not a comment yet. Line 255 is the sharpest illustration: the file's own prose
explanation of the feature, `${VAR}`, is itself expanded and reported as a
missing variable.

The same applies to the CLI's generator, which is an embedded copy of the same
file:

```
$ hearth config example -o gen.yaml && hearth config validate gen.yaml
wrote example configuration to gen.yaml
✗ Configuration invalid — 22 error(s): …
```

*After this commit the count is 21, not 22: the self-referential `${VAR}` on line
255 is gone. The other nineteen placeholders are real examples an operator may
want, so they stay — the header now warns about them instead. The two production
gates are correct behaviour and stay too.*

And the empty-file claim is false:

```
$ echo '{}' > empty.yaml && hearth config validate empty.yaml
✗ Configuration invalid — 2 error(s):
  server.tls_cert_path: production mode requires HTTPS …
  oidc.issuer: required for production; set it to your public HTTPS URL …
EXIT=1
```

→ **D-1** (documentation, fixed) and **C-2** (code, reported).

### 3.2 Writing a config that does validate

Error messages on the way are excellent — every wrong key named the alternatives:

```
$ hearth config validate minimal.yaml
✗ parse error: server: unknown field `bind`, expected one of `bind_address`, `port`,
  `tls_cert_path`, `tls_key_path`, `tls_client_ca_path`, `tls_require_client_cert`,
  `trusted_proxies`, `default_realm`, `grpc_port`, `grpc_bind_address`,
  `assets_dir`, `trust_forwarded_proto` at line 2 column 3
```

Final config — four stanzas:

```yaml
server:
  bind_address: "127.0.0.1"
  port: 18999
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1/32"]
storage:
  data_dir: "/scratch/tmp/coldrun/prod/data"
oidc:
  issuer: "http://127.0.0.1:18999"
```

```
$ HEARTH_KEK=<64 hex> hearth config validate minimal.yaml
✓ Configuration valid

  issuer:           http://127.0.0.1:18999
  storage:          /scratch/tmp/coldrun/prod/data
  email transport:  log
  TLS:              disabled (plain HTTP)
EXIT=0
```

### 3.3 `config validate` says yes; `serve` says no

```
$ HEARTH_KEK=<64 hex> hearth serve -c minimal.yaml
 INFO hearth: Hearth identity server starting dev_mode=false port=18999 bind=127.0.0.1
 INFO hearth: hot tier auto-sized capacity=22923913
ERROR hearth: error: cryptographic operation failed: HEARTH_MASTER_KEY is not set and
      auto-generation is disabled in production mode; set HEARTH_MASTER_KEY to a
      64-hex-char random key (e.g. openssl rand -hex 32)
```

This is the direct answer to the task's question. **`hearth config validate` does
not agree with what `serve` accepts.** It checks `security.key_encryption_key` /
`HEARTH_KEK` and reports a clean bill of health, but it does not check
`HEARTH_MASTER_KEY`, which is equally mandatory on a fresh production data
directory. An operator who validates in CI and deploys gets a crash loop.

`README.md`'s environment table listed `HEARTH_MASTER_KEY` as **"Recommended"**
(the body text did say a fresh production start fails without it);
`docs/specs/CONFIGURATION.md:44` already said "Required in production".
`hearth.example.yaml`'s PRODUCTION READINESS CHECKLIST — the thing a new
operator actually works through — did not mention it at all.

→ **C-3** (code) and **D-5** (documentation, fixed).

### 3.4 It boots

```
$ HEARTH_KEK=<hex> HEARTH_MASTER_KEY=<hex> hearth serve -c minimal.yaml
 WARN onboarding.base_url is not configured; setup URL will use the bind address as a fallback
 WARN system realm mfa_required is not configured; admin sessions do not require a second factor
 WARN no password_policy configured for the system realm; the built-in 12-character floor …
 WARN sms.transport = log is active outside dev mode — no real SMS messages will be sent
 WARN first-run setup required: open this URL and supply the token from the token file
      in the data directory  setup_url=http://127.0.0.1:18999/ui/setup  token_file=".setup_token"
 WARN config diff: storage data_dir changed between startups — this is likely a misconfiguration
 WARN ignoring invalid trusted_proxies entry (expected IP address) addr=127.0.0.1/32
 INFO   Realms: 0   ·   Email: log   ·   TLS: off
 INFO HTTP server listening local_addr=127.0.0.1:18999
$ curl /readyz            → 200 {"status":"ready","storage":"ok"}
$ curl -X POST /admin/bootstrap → 404   ← matches the docs
```

The startup warnings are a genuine strength — each one names the key and the fix.

But look at the seventh. `trusted_proxies: ["127.0.0.1/32"]` **passed
`config validate`** and is then **discarded at runtime**, leaving
`trust_forwarded_proto: true` with an effectively empty proxy list — precisely
the combination the validator refuses:

```
$ hearth config validate tfp.yaml      # trust_forwarded_proto: true, no trusted_proxies
✗ server.trust_forwarded_proto: … requires a non-empty server.trusted_proxies. With no
  proxy list, X-Forwarded-Proto is accepted from any peer, so any client can decide
  whether its own session cookie carries the Secure attribute.
EXIT=1

$ hearth config validate minimal.yaml  # same, but with one CIDR entry
✓ Configuration valid
EXIT=0
```

`docs/specs/CONFIGURATION.md:124` already warns that CIDR is unsupported, so the
documentation is not at fault — the validator is, for counting a value the
runtime throws away. → **C-4**.

### 3.5 Creating the first production admin

`/admin/bootstrap` is `404` here, correctly. **The README does not document any
replacement.** Its one sentence on the subject — *"Operators run the first-run
setup exactly once"* — names no URL, no token, and no file. `docs/guides/local-dev.md`
documents the **dev** variant. The production variant had to be reconstructed
from the startup WARN:

```
$ curl /ui/setup                 → 404     ← the URL the log just printed
$ curl "/ui/setup?token=$(cat data/.setup_token)"  → 200
   form fields: token, admin_email, admin_display_name, admin_password
```

The `404` is deliberate (the flow must not be discoverable without the token),
but combined with a log line that prints the bare URL it reads as a broken link.
The rest of the flow does work, end to end:

```
$ POST /ui/setup  token=… admin_email=ops@example.com admin_password=…  → 303 → /ui/setup/sent
  (server log)
  WARN onboarding: verification link (check logs if email delivery fails)
       verification_url=http://127.0.0.1:18999/ui/admin/verify-email?token=oEhA5FTVICziutYT3oBZE2BTigYv5sBwXvSJ812o6ro
  WARN email.send (log transport): message not delivered and its body (which carries
       recovery links) is suppressed from the log — configure a real email.transport
$ GET  /ui/admin/verify-email?token=…  → 200
$ POST /ui/admin/login   (without _csrf)  → 422
$ POST /ui/admin/login   (_csrf from the form page)  → 303 → /ui
$ GET  /ui               → 200  <title>Hearth · Dashboard</title>
```

Two observations:

* The `422` on a missing `_csrf` is correct behaviour, but it is the axum form
  extractor answering, not the CSRF guard, so the response carries no
  explanation. A hand-rolled `curl` login in production looks broken.
* The admin **email-verification token is written to the production log in
  full**, at WARN. Task 2.8 removed the *setup* token from production logs for
  exactly this reason (the startup banner now says `token redacted in prod`).
  The verification token grants the same thing — completion of the first-admin
  account — and is still there. → **C-5**.

→ **D-6** (documentation, fixed: the production first-admin procedure is now in
the README).

### 3.6 Backups — the documented pre-upgrade step cannot run

`docs/guides/upgrading.md` § Pre-upgrade checklist, item 2, before any "stop the
service" instruction:

```
$ hearth backup create --data-dir ./data --include-audit --output ./pre.hearth-backup
ERROR hearth: error: data directory './data' is already locked by another process;
      stop the running Hearth instance before starting a new one
EXIT=2
```

The checklist's own ordering makes it fail. Stop the server and retry:

```
$ HEARTH_KEK=<hex> HEARTH_MASTER_KEY=<hex> hearth backup create --data-dir ./data --output ./pre.hearth-backup
ERROR hearth: error: signing error: key material has HKEY envelope but no
      key_encryption_key is configured — set security.key_encryption_key in
      hearth.yaml or the HEARTH_KEK environment variable
EXIT=2
```

`HEARTH_KEK` **was** set — the error is telling the operator to do the thing they
just did. Three routes were tried and all three fail:

```
$ env HEARTH_KEK=<hex> HEARTH_MASTER_KEY=<hex> hearth backup create …   → same error, EXIT=2
$ hearth backup create -c minimal.yaml …    → error: unexpected argument '-c' found
$ (./hearth.yaml in CWD carrying security.key_encryption_key, no env var)
                                            → same error, EXIT=2
```

Confirmed on the HEAD **release** binary, not just the debug one. `src/main.rs:4095`
`run_backup_create` builds its engines from `cli_storage_config(data_dir)` and
`build_all_engines` — it never loads a config file and never reads `HEARTH_KEK`
(the only `std::env::var("HEARTH_KEK")` in `main.rs`, line 1249, is on the
`serve` path). Since production *requires* a KEK, **no production data directory
can be exported by the CLI at all.** → **C-1**.

Two further problems found in the same five minutes:

```
$ hearth backup create --data-dir ./typo-dir --output ./typo.hearth-backup
ERROR hearth: warning: no realms found to export
 INFO hearth: Backup written to: ./typo.hearth-backup
EXIT=0

$ hearth backup verify --input typo.hearth-backup
 INFO hearth: OK — all checksums match (0 files verified)
EXIT=0

$ hearth backup inspect --input typo.hearth-backup
 INFO hearth:   format version : 2
 INFO hearth:   hearth version : 1.6.11-130-g333c74e6
 INFO hearth:   signing key DEK: present (passphrase-protected)
 INFO hearth:   checksummed files: 0
 INFO hearth:   realms (0):
EXIT=0
```

A mistyped `--data-dir` is **created**, an empty archive is written, and both
`create` and `verify` exit `0`. The guide tells operators to run exactly these
two commands and treat a clean exit as proof the backup is good. → **C-6**.

`inspect` also contradicts the guide's sample output twice: `format version` is
`2`, not `1`, and `signing key DEK` reads `present (passphrase-protected)` even
though `--encrypt` was never passed — the guide uses that line to tell operators
whether they will be prompted for a passphrase on restore. → **D-7** (fixed).

For contrast, everything else in the CLI checked out. All four `backup`
subcommands exist with the documented flags, exit codes are meaningful
(`2` = error, `3` = integrity failure), `rbac orphans list --data-dir` works
against a KEK store, `hearth realm create` prints
`{"realm_id":"0c46ee67-…"}` as documented, and all 27 `make` targets named in
`CLAUDE.md` exist in the `Makefile`.

---

## 4. Task 23.6 — can the current build read older data?

**Verdict: YES, and in both directions.** Verified empirically, not inferred.

### 4.1 The two binaries

The last released tag before HEAD is `v1.6.11` (`b291a723`, 2026-08-27), 143
commits back. Its source was extracted with `git archive` (no `.git`, so no
sibling's worktree was touched) and built with its own target directory:

```
$ git rev-parse v1.6.11                → b291a723e4d7ca76038d6c929cdb8313fe1d000e
$ git rev-list --count v1.6.11..HEAD   → 143
$ old --version                        → hearth 1.6.9
$ new --version                        → hearth 1.6.11-143-gcfb6c4f5
```

`1.6.9` is not a mistake: `build.rs` prefers `git describe` and falls back to
`Cargo.toml`, and `Cargo.toml` at the `v1.6.11` tag still says `1.6.9`. Provenance
was proved a different way — the old binary does not contain `sys:control:epoch`,
the replicated control-epoch key introduced after the tag, and HEAD's does:

```
$ strings -a <old> | grep -c 'sys:control:epoch'   → 0
$ strings -a <new> | grep -c 'sys:control:epoch'   → 1
```

### 4.2 Write with the old build

`v1.6.11`, `--dev`, fresh `HEARTH_DEV_DATA_DIR`, port 18500. Bootstrap, then real
data: a second user, an OAuth client, an authorization-code + PKCE exchange, and a
browser admin session.

```
bootstrap                → 200, realm 3ada0ce0-4f4a-4774-a948-017b67016abe
POST /admin/users        → 201 day2@example.com
POST /clients            → 201 day2-app (d83f4b64-…)
POST /authorize, /token  → 200, access + refresh token retained
POST /ui/admin/login     → 303 → /ui
GET  /admin/users        → ["admin@dev.local"]            (before the extra user)
GET  /admin/realms       → ["dev-realm","default"]
GET  /.well-known/jwks.json → 4 kids
```

Stopped with `SIGTERM`; `shutdown signal received, draining in-flight requests`
→ `Hearth server stopped`. On-disk result — no SST yet, everything in the WAL:

```
$ ls day2/     → .setup_token  hearth.host_key  hearth.keys  hearth.wal  LOCK
$ xxd -l 6 day2/hearth.wal
00000000: 4857 414c 0100      HWAL..      ← magic "HWAL", format version 1
```

This is exactly the check `docs/guides/upgrading.md` § Pre-upgrade checklist
prints, and it matches byte for byte.

### 4.3 Read with HEAD

Same data directory, HEAD release binary, no flags changed.

| Check | Result |
|---|---|
| Starts at all | **Yes** — `Storage: WAL 55 KB · 0 SSTs`, `HTTP server listening` |
| WAL migration run | None needed — no migration log line, version stayed `1` |
| Realms | `dev-realm` intact, `ACTIVE`, same UUID, same `created_at` |
| Users | `["admin@dev.local","day2@example.com"]` — both, including the one the old build created |
| OAuth client | `day2-app`, same `client_id`, same `redirect_uris` |
| **Old admin access token** | **Accepted** — `/v1/me/permissions` → 200, same 17 permissions |
| **Old OAuth access token** | **Accepted** — `/userinfo` → 200, same `sub` |
| **Old refresh token** | **Redeemed** — `grant_type=refresh_token` → 200 with a new access token |
| Old admin password | Accepted — `/ui/admin/login` → 303 → `/ui` |
| Browser session cookie | Rejected → `/ui/admin/login?return_to=%2Fui` (see 4.5) |

So a JWT signed by the old build's Ed25519 key validates against the new build,
because the key itself survived the upgrade intact.

### 4.4 Roll back, and read HEAD's data with the old build

One more user was written **on HEAD** (`post-upgrade@example.com`), HEAD was
stopped, and `v1.6.11` was started on the same directory. HEAD had by then
flushed an SST:

```
$ head -c 4 day2/000001.sst | xxd -p   → 48535333   "HSS3"   ← SST format v3
$ xxd -l 6 day2/hearth.wal             → HWAL..              ← still version 1
```

`v1.6.11` on that directory:

```
realms   → ["dev-realm","default"]
users    → ["admin@dev.local","day2@example.com","post-upgrade@example.com"]   ← all three
clients  → ["day2-app"]
old admin token → 200 {"roles":["realm.admin"]}
password login  → 303
grep -i 'InvalidSstFormat|not supported by this binary|DeserializationFailed|ChecksumMismatch'  → no matches
```

The old binary read a **v3 SST and a WAL written by HEAD** without complaint, and
saw the row HEAD created. `upgrading.md`'s claim — *"in-place binary rollback
between shipped v1.x versions is safe … the data directory is byte-compatible"* —
holds at HEAD, and this is the first time it has been demonstrated rather than
asserted.

### 4.5 Two differences, neither of them data loss

**The realm listing narrowed.** `GET /admin/realms` with the *dev-realm* token
returned `["dev-realm","default"]` on `v1.6.11` and `["dev-realm"]` on HEAD, which
reads at first like a lost realm. It is not. With the **system** token HEAD
returns both, and `GET /admin/realms/e1d420c7-…` returns the full `default`
record, `ACTIVE`, with its original `created_at` of `1790010370802908`. The same
call with the dev-realm token answers `403 forbidden`. The row is intact; what
changed is that **`v1.6.11` disclosed every realm to a single tenant's admin token
and HEAD scopes the listing** — a tightening, and an operator-visible one that
belongs in the changelog if it is not already there.

**The browser session did not survive.** The `hearth_ui_session` cookie minted by
the old build was rejected by HEAD. But it was *also* rejected by `v1.6.11`
itself after the round trip, so this is "admin UI sessions do not survive a
process restart in this configuration", not an upgrade regression. API tokens,
refresh tokens and passwords all did survive. Operators should still expect to
re-authenticate in the console after any restart.

### 4.6 Is the on-disk format versioned, and is there migration tooling?

Both answers are in the code and both are now confirmed against a real file.

| Artefact | Versioning | Current |
|---|---|---|
| WAL | `[4B "HWAL"][2B version LE]`, `src/storage/migrations.rs` | `1`; one migration in the table, `v0 → v1` |
| SST | magic per version — `HSST` (v1), `HSS2` (v2), `HSS3` (v3), `src/storage/sst.rs:63-70` | writes v3; v1 and v2 **stay readable** |
| Host key | `HRTHHKY1`, `src/storage/key_registry.rs:50` | — |
| Key envelope | `HKEY`, `src/identity/key_encryption.rs:38` | — |
| Backup archive | `format version` in `manifest.json` | **2** (the upgrade guide's sample still said `1` — corrected) |

The repo's standing note *"Greenfield — no migration tooling"* is **half true and
worth restating precisely**: there is no operator-facing hearth-to-hearth
migration command, and `hearth migrate` is an *importer* from other IdPs
(`keycloak`, `auth0`) plus a pepper-rotation audit — not a schema tool. But the
storage layer is versioned and self-migrating: `apply_migrations` runs on open,
and the WAL reader refuses a file from a *newer* binary rather than misreading it.
So the honest statement is "no migration tooling is needed, and none is exposed",
not "the format is unversioned".

### 4.7 What this does not prove

* Only one hop was tested: `v1.6.11` ↔ HEAD. Older tags (`v1.0.0` … `v1.6.10`)
  were not built. The format evidence says they are fine — the WAL has been
  version `1` throughout and SST v1/v2 readers are still present — but that is
  inference, not a run.
* Both runs were `--dev` (weakened Argon2, no KEK envelope on the signing keys).
  A **production, KEK-enveloped** data directory was not round-tripped, because
  the export needed to snapshot one first does not work (**C-1**). That is the
  one gap in this answer and it is worth closing once C-1 is fixed.
* No cluster was involved. A Raft log is a different compatibility question.

---

## 5. Findings

### Code — reported, not fixed

**C-1 — `hearth backup create` cannot export a production data directory.**
BLOCKER. Production requires a key-encryption key; every `--data-dir` CLI path
then fails with `key material has HKEY envelope but no key_encryption_key is
configured — set security.key_encryption_key in hearth.yaml or the HEARTH_KEK
environment variable`. The message names two fixes and **neither works**:
`HEARTH_KEK` exported in the environment fails, `security.key_encryption_key` in
a `./hearth.yaml` fails, and there is no `--config` flag to point the command at
one. `src/main.rs:4095` `run_backup_create` builds its engines from
`cli_storage_config(data_dir)` + `build_all_engines` and never loads a config or
reads the env var — the only `std::env::var("HEARTH_KEK")` in `main.rs` (line
1249) is on the `serve` path. Confirmed on the HEAD release binary. Consequence:
the pre-upgrade backup that `docs/guides/upgrading.md` makes mandatory cannot be
taken on any production deployment. Suggested fix: give the `backup`, `rbac` and
`migrate` subcommands the same `-c/--config` + `HEARTH_*` resolution `serve` has.

**C-2 — `${VAR}` is substituted inside YAML comments, so the shipped example
config cannot validate.** `cp hearth.example.yaml hearth.yaml && hearth config
validate hearth.yaml` → **22 errors**, of which **20 are `${…}` references on
commented-out lines**. Substitution runs over raw file text before the YAML
parse. The same applies to `hearth config example -o gen.yaml`, which emits an
embedded copy of the same file and therefore also does not validate. The
documentation side is fixed (D-1); the behaviour is a code decision. Either skip
`#` lines during substitution, or accept that the example must ship every
placeholder in `${VAR:-}` form.

**C-3 — `hearth config validate` passes configs that `serve` refuses.** It
checks `HEARTH_KEK` / `security.key_encryption_key` but not `HEARTH_MASTER_KEY`,
which is equally mandatory on a fresh production data directory. A config it
calls `✓ Configuration valid` aborts `serve` with `HEARTH_MASTER_KEY is not set
and auto-generation is disabled in production mode`. This defeats the point of
validating in CI. Fix: check every startup-fatal environment prerequisite, or say
plainly in the success output which checks were skipped.

**C-4 — a CIDR entry in `trusted_proxies` satisfies the `trust_forwarded_proto`
guard and is then discarded.** `trust_forwarded_proto: true` with an empty
`trusted_proxies` is correctly refused by both `config validate` and `serve`. But
`trusted_proxies: ["127.0.0.1/32"]` **passes validation** and the runtime then
logs `ignoring invalid trusted_proxies entry (expected IP address)
addr=127.0.0.1/32`, leaving the refused state — `trust_forwarded_proto` on, no
trusted proxies — actually running. `docs/specs/CONFIGURATION.md:124` already
documents that CIDR is unsupported, so this is purely a validator defect: it
counts entries the runtime throws away. Security-relevant, since the whole point
of the guard is that `X-Forwarded-Proto` must not be accepted from any peer.

**C-5 — the first-admin email-verification token is written to the production log
in full.** Task 2.8 removed the *setup* token from production logs for exactly
this reason — the startup banner now reads `token redacted in prod`. The
verification token that completes the same account is still printed:
`WARN onboarding: verification link (check logs if email delivery fails)
verification_url=…/ui/admin/verify-email?token=oEhA5FTVICziutYT3oBZE2BTigYv5sBwXvSJ812o6ro`.
Anyone with log read access can finish the first operator account. Same severity
class as the defect 2.8 closed.

**C-6 — a mistyped `--data-dir` produces a clean, empty, "verified" backup.**
`backup create --data-dir ./typo-dir` **creates** the directory, exports nothing,
prints only `warning: no realms found to export`, and exits **0**. `backup verify`
then prints `OK — all checksums match (0 files verified)` and exits **0**. The
upgrade guide instructs operators to run exactly those two commands and treat a
clean exit as proof. Fix: refuse a `--data-dir` that does not already contain a
store, and make a zero-realm export a non-zero exit.

**C-7 — the server-generated `quickstart` hard-codes port 8420 and points at a
file that does not exist.** `POST /admin/bootstrap` on port 18420 returned a
`quickstart` block whose commands all target `http://127.0.0.1:8420`, and whose
closing line reads `# 2. Full PKCE flow — see docs/guides/getting-started.md`.
The file is `getting-started.mdx`. Low severity, high visibility — it is the
first thing a new user copies.

### Documentation — fixed in this commit

**D-1 — `hearth.example.yaml` claims to be a working starting config and is not.**
The README said "copy and edit"; the file's own header said "An empty file (`{}`)
starts Hearth". Neither validates (22 errors and 2 errors respectively). Fixed in
both places, with the comment-substitution trap spelled out and the real minimum
config given.

**D-2 — the documented `/admin/realms` call fails.** `CLAUDE.md` and
`docs/guides/upgrading.md` § Post-upgrade verification both print
`curl -H "Authorization: Bearer <token>" …/admin/realms`, which answers
`400 {"error":"missing X-Realm-ID header"}` — easy to misread as an upgrade
regression. `X-Realm-ID` added in both, plus a note in the README.

**D-3 — the two bootstrap admins were undocumented.** `CLAUDE.md` says sign in as
`admin@hearth.test`; the README's walkthrough shows `admin@dev.local`. Both are
right and they are different accounts in different realms — signing in with the
wrong one answers a bare `401`. Now stated in the README as a table, and in
`CLAUDE.md`.

**D-4 — re-bootstrap returns JSON `null`, not `""`.** The README said "returns an
empty string" in two places. `jq -r .admin_password` therefore prints the string
`null`, which a script will happily use as a password. Corrected.

**D-5 — `HEARTH_MASTER_KEY` was "Recommended" and absent from the production
checklist.** It is required on a fresh production start.
`docs/specs/CONFIGURATION.md` already said so; the README table and
`hearth.example.yaml`'s PRODUCTION READINESS CHECKLIST — the two documents a new
operator actually works through — did not. Both corrected, with the
`config validate` blind spot (C-3) called out.

**D-6 — there was no documented way to create the first admin outside `--dev`.**
The README's only account-creation path is `/admin/bootstrap`, which is `404` in
production; its single sentence on first-run setup names no URL, no token and no
file. The working procedure — `.setup_token` in the data directory,
`/ui/setup?token=…`, the verification link from the log — is now in the README,
including why a bare `/ui/setup` answers `404`.

**D-7 — `upgrading.md`'s backup step cannot run where it is placed, and its
sample output is stale.** Taking the backup is item 2 of the pre-upgrade
checklist, before "stop the service" — but the data directory `LOCK` makes it
exit `2` against a live server. The `backup inspect` sample also showed
`format version : 1` (it is `2`) and `signing key DEK: absent` for an unencrypted
archive (it reads `present (passphrase-protected)` regardless of `--encrypt`).
All corrected, plus a warning about the silent empty-archive path (C-6).

**D-8 — `backup.md` did not mention the LOCK or the KEK blocker.** Both are now
"Known gap" admonitions at the top of the guide, with the HTTP export named as
the workaround.

**D-9 — dev-mode persistence was described three ways.** The README said "`--dev`
uses in-memory storage in a temp directory" and `getting-started.mdx` said "Data
does not persist across restarts", while `make dev` sets
`HEARTH_DEV_DATA_DIR=./data/dev` and persists. All three are now consistent with
`CONFIGURATION.md`'s three-level precedence rule; dev storage is also not
"in-memory" — it is a real WAL + SST store in a throwaway location.

**D-10 — the README CLI reference was wrong and incomplete.** `app create` was
documented as `--realm_id` / `--redirect_uri` (the real flags are `--realm-id` /
`--redirect-uri`) and omitted the **mandatory** `--token`, which
`CHANGELOG.md:2859` introduced and nobody propagated — the documented command
cannot run. Four whole subcommands were missing (`config`, `rbac`, `backup`,
`completions`) along with `migrate auth0` and `migrate rotate-pepper`. Rewritten
from `--help` output.

### Verified correct — recorded so a later pass does not re-litigate

* `/health`, `/healthz`, `/readyz` return exactly the documented bodies; the
  Kubernetes probe table in `upgrading.md` is right.
* The nine-step README curl walkthrough runs end to end with no corrections.
* `POST /clients` does accept and never echo `client_secret`, as the README says.
* `/admin/bootstrap` is `404` outside `--dev`, as documented everywhere.
* All 27 `make` targets named in `CLAUDE.md` exist in the `Makefile`.
* All four `backup` subcommands exist with the documented flags; exit codes are
  meaningful (`2` error, `3` integrity failure).
* `hearth realm create` prints `{"realm_id":"…"}` and needs no server.
* The WAL header check `xxd -l 6 …/hearth.wal` → `HWAL..` works as printed.
* `config validate` and `serve` agree on YAML-level errors; they diverge only on
  environment prerequisites (C-3).
* Configuration error messages are genuinely good — every rejected key listed the
  valid alternatives, and every production gate named the key and the fix.
* Row 26 of the 2026-08-28 audit (GHCR packages private) was **not** re-tested
  here; `reports/documentation-truth-sweep-2026-09-21.md` covers it and the
  README already carries the withdrawal.

---

## 6. What was changed

| File | Change |
|---|---|
| `README.md` | CLI reference rebuilt from `--help` (D-10) · `admin_password` null (D-4) · the two bootstrap admins, and `X-Realm-ID` on `/admin/*` (D-2, D-3) · new "Creating the first admin outside `--dev`" section (D-6) · example-config caveat, real minimum config, and the `config validate` blind spot (D-1, D-5) · `HEARTH_MASTER_KEY` promoted to Required (D-5) · dev-storage description corrected in three places (D-9) |
| `hearth.example.yaml` | Header rewritten: the file is a catalogue, not a starting config; the comment-substitution trap explained; the false "empty file starts Hearth" claim withdrawn (D-1) · `HEARTH_MASTER_KEY` and `trusted_proxies` added to the PRODUCTION READINESS CHECKLIST (D-5) · minimum-production block annotated with the env vars and the proxy pairing · the self-referential `${VAR}` on line 255 removed (C-2) |
| `docs/guides/upgrading.md` | Backup step: stop the server first, and the silent empty-archive path (D-7, C-6) · `backup inspect` sample corrected to `format version : 2` and the DEK line de-fanged (D-7) · `X-Realm-ID` added to the post-upgrade admin check (D-2) |
| `docs/guides/backup.md` | Two "Known gap" admonitions: the `LOCK`, and the KEK export blocker with the HTTP-export workaround (D-8, C-1) · the mistyped-`--data-dir` hazard (C-6) |
| `docs/guides/getting-started.mdx` | Dev persistence: bare `--dev` vs `make dev` (D-9) |
| `CLAUDE.md` | `/admin/realms` example given its `X-Realm-ID` (D-2) · the post-login landing corrected from `/admin` (404) to `/ui`, with the two-admin note (D-3) |

No `.rs` file, nothing under `openspec/`, no workflow and no script was touched.
