# What a backup does not carry, and what a device user cannot reach

Tasks 23.5 and 23.7 — the two audit re-runs the 2026-08-28 pass could not
complete (§7.2, §8.1 items 5 and 7).

Everything below was produced by running the binary built from HEAD
(`1.6.11-158-g718df0fc`) against real stores under `/scratch/tmp`, not by
reading code. Where a claim rests on code rather than a transcript, it says so.

---

## The question 23.7 was raised to answer

> **Is Dynamic Client Registration open to the internet by default?**

**No.** A non-dev server booted from a real `hearth.yaml` that passes
`hearth config validate` refuses unauthenticated registration:

```
$ ./hearth config validate prod.yaml
✓ Configuration valid
  issuer:           https://auth.rerun.test
  storage:          /scratch/tmp/hea-235-237/prod-data
  email transport:  smtp
  TLS:              disabled (plain HTTP)

$ ./hearth serve -c prod.yaml            # no --dev
  HTTP server listening local_addr=127.0.0.1:8471

POST /realms/acme/register
Content-Type: application/json
{"client_name":"attacker","redirect_uris":["https://evil.test/cb"]}

-> 403
{"error":"dynamic client registration is disabled for this realm"}
```

The gate is real, not a default that nothing reads. Declaring
`auth.dcr.mode: open` on the same realm flips it, with no credentials
presented:

```
POST /realms/acme/register
{"client_name":"attacker","redirect_uris":["https://evil.test/cb"],"trust_level":2}

-> 201
{"client_id":"36c799e6-ace3-4976-bc3d-48ec3d5c32fb","client_name":"attacker",
 "grant_types":["authorization_code"],"redirect_uris":["https://evil.test/cb"]}
```

Note the `trust_level: 2` the caller asked for is absent from the result — the
handler forces `ClientTrustLevel::ThirdParty` and strips any client-supplied
secret. Both `POST /register` and `POST /realms/{name}/register` consult
`realm.config().dcr_policy`, and `DcrPolicy`'s `#[default]` is `Disabled`, so a
realm that never mentions DCR is closed.

**Answer: DCR is closed by default and must be opened deliberately, per realm.**

---

## Findings

### B-1 — A "full" backup silently omits the system realm

`hearth backup create` with no `--realm` enumerates realms through
`identity.list_realms`, and `list_realms` does not return the system realm
(`RealmId::nil()`). Every operator-console account lives there.

**Transcript.** Origin store, listing realms with the system token:

```
dev realm    016ac7c8-d06b-4fdf-9b6e-ca28616f4c29
system realm 00000000-0000-0000-0000-000000000000

GET /admin/realms -> 200
{"items":[{"id":"016ac7c8-…","name":"dev-realm"},
          {"id":"dcda3e42-…","name":"default"}]}          # system absent

GET /admin/users (X-Realm-ID: 00000000-…) -> 200
{"items":[{"email":"admin@hearth.test","display_name":"Dev Admin", …}]}
```

The unfiltered export agrees with the listing, not with the store:

```
$ ./hearth backup create --data-dir ./dev-data -c dev.yaml -o rt1.hearth-backup
  exported 'dev-realm': 3 users, 1 clients
  exported 'default':   0 users, 0 clients
$ ./hearth backup inspect --input rt1.hearth-backup
  realms (2):
    dev-realm    users=3 credentials=1 clients=1 roles=10 groups=1
    default      users=0 credentials=0 clients=0 roles=9  groups=0
```

Named explicitly, the same store exports it fine — so this is an enumeration
gap, not a capability gap:

```
$ ./hearth backup create --realm 00000000-0000-0000-0000-000000000000 …
  exported 'system': 1 users, 0 clients
  realms (1):
    system   users=1 credentials=1 roles=9
```

**Failure scenario.** The disaster-recovery runbook takes an unfiltered
backup, the datacenter burns, the operator restores into a fresh data
directory, and then cannot log in to the console. Controlled A/B, same
password, same request:

```
port 8473 (origin)   : login -> 200 http://127.0.0.1:8473/ui
port 8474 (restored) : login -> 401
```

Nothing in the export, the restore, or `backup inspect` mentions that the
realm holding the only administrative account was skipped.

---

### B-2 — `backup create --include-audit` cannot read a KEK-encrypted store

`build_all_engines` (`src/main.rs`) threads the resolved KEK into
`EmbeddedIdentityEngine` and constructs `EmbeddedAuditEngine::new(storage,
clock)` beside it with no KEK. Per-realm audit HMAC keys are HKEY-enveloped at
rest exactly like signing keys, so the exporter cannot unwrap its own chain
key.

```
$ HEARTH_KEK=… ./hearth backup create --data-dir ./dev-data -c dev.yaml \
      --include-audit -o rt1.hearth-backup
ERROR error: export engine error: serialization error: audit HMAC key unwrap
      failed: signing error: key material has HKEY envelope but no
      key_encryption_key is configured — set security.key_encryption_key in
      hearth.yaml or the HEARTH_KEK environment variable
EXIT=2

$ HEARTH_KEK=… ./hearth backup create --data-dir ./dev-data -c dev.yaml \
      -o rt1.hearth-backup                       # same store, no --include-audit
  Backup written to: ./rt1.hearth-backup
EXIT=0
```

This is the same class as cold-run finding C-1 and it survived that fix
because it hides behind one optional flag: the ordinary backup works, so the
KEK looks wired. Production requires a KEK; `--include-audit` is what a
compliance-driven operator passes.

**Fixed** — see *Fixes*.

---

### B-3 — Deleting a file from an archive defeats both `verify` and `restore`

`ArchiveReader::verify_checksums` walks the entries **present in the tar** and
checks the ones that also appear in the manifest's checksum map. A file that
is not there is never iterated, so its absence is not an error. Nothing
cross-checks the manifest's `record_counts` on restore either — they are
printed by `backup inspect` and read by nothing else.

**Transcript.** `users.ndjson` removed from the tar, its checksum entry left
in the manifest:

```
### elide-users
  verify  exit=0 :: OK — all checksums match (15 files verified)
  restore exit=0
    realms   — created: 1, skipped: 0, overwritten: 0, errored: 0
    users    — created: 0, skipped: 0, overwritten: 0, errored: 0
    clients  — created: 1, skipped: 0, overwritten: 0, errored: 0
```

The `(15 files verified)` line is itself wrong: it reports the size of the
manifest's checksum map, not the number of files actually read — there were
fourteen. Removing the checksum entry too (a fully self-consistent lie) is
equally invisible:

```
### elide-users-and-checksum
  verify  exit=0 :: OK — all checksums match (14 files verified)
  restore exit=0 :: users — created: 0
```

**Failure scenario.** An archive passes `hearth backup verify` with `OK`, then
restores with exit 0 into a realm with every client, role and group intact and
zero users. Two commands in a row report success over a realm nobody can log
in to. This is exactly the attack the `audit_chain_included` manifest field
was added to close for `audit_chain.json`; it is open for every other member.

Not fixed here — see *Reported, not fixed*.

---

### B-4 — A restore's exit code and summary cover four of eleven entity types

`ImportReport` carries eleven buckets. `print_import_report` printed four
(realms, users, mfa, clients) and the partial-failure check named three
(users, clients, realms). Roles, permissions, groups, role assignments,
scopes, organizations and audit events could each fail to import without a
line of output and without moving the exit code off 0.

```rust
if report.users.errored > 0 || report.clients.errored > 0 || report.realms.errored > 0 {
    had_errors = true;
}
```

**Failure scenario.** A restore in which every role and every role assignment
errors prints `users — created: 3, errored: 0`, exits 0, and the runbook ticks
the box. The realm is back with no RBAC.

**Fixed** — see *Fixes*.

---

### B-5 — A failed `backup create` leaves a partial archive at `--output`

`BackupArchive::create(&out_path)` opens the output file before a realm is
read; every `?` after it returned without touching that file. The
mandatory-encryption gate is the worst case because it fires *after* the whole
export has been written.

```
$ ./hearth backup create --data-dir ./dev-data -o ./rt1.hearth-backup --include-audit
  exported 'default':   0 users, 0 clients
  exported 'dev-realm': 3 users, 1 clients
ERROR error: backup encryption is mandatory — set HEARTH_MASTER_KEY or use --encrypt
EXIT=2
$ ls -la rt1.hearth-backup
.rw-r--r-- 0 brad 21 Sep 16:04 rt1.hearth-backup
```

The exit code is right; the artifact is not. Task 26.26 fixed the *exit code*
of a typo'd `--data-dir`; the stub file it leaves is the residue of the same
shape. A cron wrapper that checks "did tonight's file appear" reports a
healthy backup history over a directory of zero-byte files.

**Fixed** — see *Fixes*.

---

### B-6 — A fatally-failed restore still applies the realm record

The unknown-member and corrupt-entity refusals both abort with exit 2, but
`import_realm_record` has already written the realm and its signing key by
then. The restored data directory is left holding a realm with no users:

```
### corrupt-entity            (one byte flipped inside users.ndjson)
  verify  exit=3 :: integrity failure: checksum mismatch for …/users.ndjson
  restore exit=2 :: error: serialization error: invalid unicode code point
    (data dir created)

$ ./hearth serve --dev -c dev3.yaml        # boot the aborted target
GET /realms/dev-realm/.well-known/jwks.json -> 200
  {"keys":[{"kty":"OKP","crv":"Ed25519","kid":"yabT9iuscBUnOnRRMbFwNg", …}]}
```

The realm exists, with the archive's original signing key, and no users.

**Severity note, stated honestly:** the operator is *not* stuck. Re-running
the good archive into the same directory recovers, because the default `skip`
mode treats the orphaned realm as a conflict and proceeds:

```
Realm 'dev-realm':
  realms   — created: 0, skipped: 1, overwritten: 0, errored: 0
  users    — created: 3, skipped: 0, overwritten: 0, errored: 0
  conflicts (1):
    ["realm"] "dev-realm" — realm with this id already exists
```

What does *not* recover is the realm record itself: the archive's realm
config is never re-applied, because the partial one already occupies the id.
Reported, not fixed — an all-or-nothing restore is a larger change than this
pass should make.

---

### B-7 — `restore` never runs the integrity check that `verify` runs

`run_backup_restore` opens the archive and imports. It does not call
`verify_checksums`. An archive that `backup verify` rejects restores cleanly:

```
### corrupt-checksum          (one checksum in the manifest set to 64 zeros)
  verify  exit=3 :: integrity failure: checksum mismatch for …/users.ndjson:
                    expected 000…000, got 8de2976c…
  restore exit=0 :: users — created: 3, clients — created: 1
```

Corruption detection is therefore opt-in and out of band. `docs/guides/backup.md`
presents `verify` as the integrity gate without saying that `restore` does not
run it. Reported, not fixed: making restore verify first is a policy change
(it doubles the read on a large archive) and belongs with B-3.

---

### O-1 — `verification_uri` in the device-authorization response is a 404

The end-user approval page is `handlers::device_approve_form`, registered on
the web router, which `router_with` mounts under the `/ui` nest. The engine
advertised `{issuer}/device`.

```
POST /device_authorization  (client_id=…, scope=openid)
-> 200 {"device_code":"l8F2…","user_code":"P7H3PWCJ","expires_in":600,
        "interval":5,"verification_uri":"http://127.0.0.1:8473/device"}

GET http://127.0.0.1:8473/device     -> 404
GET http://127.0.0.1:8473/ui/device  -> 400   (routed; wants a user_code)
```

Every RFC 8628 client displays `verification_uri` to a human. The human gets a
404, and the device grant cannot be completed at the URI the authorization
server itself printed. The existing conformance test only asserted the field
was non-empty, and the Playwright spec asserts `/\/device/`, which `/ui/device`
still satisfies — so nothing caught it.

**Fixed** — see *Fixes*.

---

### O-2 — Any public `client_id` authenticates the introspection endpoint

`verify_endpoint_client` → `authenticate_client_inner`: a client with no stored
secret is a public client and `client_id` alone succeeds; a secret presented
for a public client is ignored by design ("a stray secret on a public client is
ignored, as before").

```
POST /introspect  token=<admin access token>
  (no client_id)                         -> 401 {"error":"client_id required"}
  client_id=70e353ef-…                   -> 200 {"active":true,"sub":"user_1227bdd0-…",
                                                 "exp":…,"iss":"…/realms/dev-realm",
                                                 "aud":"…","mode":"embedded"}
  client_id=70e353ef-… client_secret=nope -> 200  (same body; wrong secret ignored)
```

`client_id` values are public by construction — they travel in every browser
authorization request, and DCR hands them out. RFC 7662 §2.1 requires the
endpoint to require authorization, and §4 warns that it is a token-information
oracle.

The cross-client audience gate at `engine/oauth.rs:2779` limits *which* tokens
are readable, but its third documented case — `azp` absent and `sid != "none"`,
i.e. an ordinary user-session token — permits **any** authenticated client. The
token above is exactly that shape, which is why it read back in full.

Reported, not fixed: requiring a confidential client at `/introspect` is a
behaviour change that would break any deployment currently introspecting with a
public client, and `verify_endpoint_client` is shared with `/revoke`, where
public-client use is legitimate (RFC 7009 §2.1). This is a policy call for the
owner, not a bug to patch under an audit re-run.

---

### O-3 — Device-code redemption is the one single-use path with no advisory lock

`code_exchange_lock` guards the authorization-code exchange and
`token_redemption_lock` guards refresh-token redemption, each held across the
whole get → validate → delete → issue sequence. `poll_device_token_inner`
takes neither: it reads the row, checks `Approved`, creates a session, issues a
token pair, and only then deletes the device-code and user-code rows.

**Failure scenario (code-derived, not demonstrated).** Two concurrent polls of
one approved device code both observe `Approved` before either delete lands,
and one user approval yields two independent sessions and two refresh-token
families. Rate limiting does not close it: `interval` is enforced against
`last_polled_at`, which the racing pair also read before either wrote.

Not fixed and **not mutation-proven** — a reliable concurrency test for this
needs a deterministic interleaving hook the engine does not expose, and I will
not claim a race I could not make happen on demand. Recorded so it is not
re-discovered as new.

---

### O-4 — An unknown `device_code` answers `expired_token`

RFC 8628 §3.5 reserves `expired_token` for a code that has expired; an unknown
one is `invalid_grant`. The storage miss maps to `IdentityError::DeviceCodeExpired`:

```
POST /token  grant_type=…:device_code  device_code=AAAA…(43)
-> 400 {"error":"expired_token","error_code":"HEARTH_DEVICE_CODE_EXPIRED"}
```

Minor, and arguably privacy-preserving (it hides whether the code ever
existed). Reported for completeness, not fixed — narrowing it would be a
deliberate trade against that property.

---

### O-5 — The two DCR endpoints register different kinds of client

`POST /register` builds a `DcrResponse` carrying `client_secret`,
`client_secret_expires_at`, `token_endpoint_auth_method` and
`client_id_issued_at`. `POST /realms/{name}/register` sets
`client_secret: None` and answers four fields:

```
POST /realms/acme/register  {"client_name":"m2m-bot","grant_types":["client_credentials"]}
-> 201 {"client_id":"e5f7c83d-…","client_name":"m2m-bot",
        "grant_types":["client_credentials"],"redirect_uris":[]}

POST /realms/acme/token  grant_type=client_credentials client_id=e5f7c83d-…
-> 401 {"error":"invalid_client"}
```

The realm-scoped endpoint validates `grant_types` against the server's
`grant_types_supported` but not against the client type it is about to create,
so it will happily register a public client for `client_credentials` — a grant
that client can never perform. The response also omits
`client_secret_expires_at` and `token_endpoint_auth_method`, so the caller
cannot tell it received a public client.

Reported, not fixed: which of the two shapes is correct is a product decision.

---

## What IS genuinely covered

| Property | Evidence |
|---|---|
| Truncation at any point fails closed | 25 %, 50 %, 90 %, 99 %: `verify` exit 3, `restore` exit 2 (`incomplete frame`), **no data directory created**. The manifest is the last tar entry, so any truncation removes it and nothing is applied. |
| Byte corruption inside an entity file is caught | `verify` exit 3 with the expected/actual SHA-256 pair; `restore` exit 2. |
| Manifest checksum tampering is caught by `verify` | exit 3, names the file and both hashes. |
| An unrecognized archive member is refused | `restore` exit 2: `unrecognized archive member 'realms/dev-realm/evil.ndjson' — … refusing to proceed`. Fail-closed against a newer or forked producer. |
| Format version is enforced in both directions | `format_version: 1` → `unsupported archive format version: 1`; `99` → likewise. |
| Repack control round-trips | An unmodified repack verifies `OK — all checksums match (15 files verified)` and restores 1 realm / 3 users / 1 client, so every negative above is attributable to the mutation, not to the harness. |
| Realm signing key round-trips | The restored realm's JWKS carries the original `kid` `yabT9iuscBUnOnRRMbFwNg` and the same `x`. HEA-2168's fail-closed gate does what it says. |
| DCR is closed by default and the gate is enforced on both endpoints | 403 by default, 201 under `mode: open`, `trust_level` forced to `ThirdParty`, client-supplied secret stripped. |
| Device grant: `interval` is enforced | Second poll inside 5 s → `slow_down` (RFC 8628 §3.5), not `authorization_pending`. |
| Device grant: the wrong client cannot poll another client's code | `-> 401 {"error":"invalid_client"}`. |
| Introspection requires *a* client identity | No `client_id` → `401 {"error":"client_id required"}` with `WWW-Authenticate: Basic`. |
| Cross-client introspection is bounded | `azp`-bound and `sid == "none"` (M2M) tokens are readable only by the `azp` client, the owning client, or a named audience member; everything else answers `active:false`. |
| Permission modes are honoured at issue time | `engine/mod.rs:8189–8234` emits `permissions`, `roles` and `groups` only when the client's mode is `Embedded`; `engine/oauth.rs:2859–2868` resolves live RBAC into the introspection response for `Introspection`/`Decision` clients. Observed end-to-end only for `embedded` — the introspection response carried `"mode":"embedded"`. **Static for the other two modes; the REST admin surface has no route to change a client's mode, so I could not flip one at runtime.** |

---

## What does not round-trip

Determined by enumerating the export's sources against `src/identity/keys.rs`
and `src/rbac/keys.rs`, and confirmed against the archive's actual member list.

The archive contains exactly: `realm.json`, `users.ndjson`,
`credentials.ndjson`, `mfa_factors.ndjson`, `clients.ndjson`, `roles.ndjson`,
`permissions.ndjson`, `groups.ndjson`, `assignments.ndjson`, `scopes.ndjson`,
`organizations.ndjson`, `signing_key.json`, and optionally `audit.ndjson` +
`audit_chain.json`.

| Not exported | Consequence of a restore |
|---|---|
| **Group memberships** (`gm_` forward/reverse) | `Group` carries no members and there is no `export_all_group_memberships`; `RbacEngine` has `import_group` and no membership importer. Groups come back empty, so every permission a user held *through* a group is gone while the role assignment to the group survives — the RBAC graph restores looking correct and resolving to nothing. Memory's note from HEA-2167 still holds. |
| **The system realm** | B-1. |
| **Sessions** | Every access and refresh token issued before the backup is dead after the restore even though the signing key survives (`GET /admin/users` with the pre-backup admin token → `401 {"error":"invalid token"}`). The `--allow-missing-signing-key` help text implies the converse. |
| **Organization memberships** (`om_`/`mu_`) | Organizations come back with no members. |
| **Identity providers** (`idp_`) and federation external-identity links | Federated login configuration and every user↔IdP binding are lost; a federated user cannot sign in again until the IdP is recreated. |
| **Webhooks** (`webhook_`) | Event delivery silently stops. |
| **Agents and agent credentials** (`agent_`) | All of AGENT_AUTH M1–M5 state. |
| **SAML SP registrations** (`saml_sp_`) and the per-realm SAML key | Service providers must re-federate. |
| **SCIM external-id mappings** | The next SCIM sync re-creates rather than updates. |
| **User consents** (`consent_`) | Every user is re-prompted. Benign. |
| **Organization invitations** | Outstanding invitations become dead links. |
| **Retiring signing keys** (`realm_retiring_keys`) | Only the current key is exported, so a restore during a rotation grace window drops the outgoing key and invalidates tokens the origin would still have accepted. |

Note that `restore` fails closed on an *unrecognized* member but has nothing to
say about a *missing* category — the importer's member allowlist is the union
of what the exporter writes, so a family nobody exports is a family nobody
misses.

---

## Per-design, NOT defects

Recording these so a later sweep does not "fix" them.

| Behaviour | Why it is right |
|---|---|
| Sessions are not exported | A session is per-node live state bound to a session version and a device. Restoring sessions would resurrect revoked ones. The defect is the documentation implying otherwise, not the omission. |
| Empty sections are omitted from the archive | `mfa_factors.ndjson`, `organizations.ndjson` and `audit.ndjson` are absent when the count is zero. The importer treats every member as optional, so this is compression, not loss — and it is why a *deleted* member (B-3) is indistinguishable from an empty one. |
| `--mode overwrite` refuses a live realm | Deliberate, from audit §3 B3: the old cascade raced its own deletion and destroyed 975 of 1,160 recorded runs. |
| Restore re-signs imported audit events under the destination key | The source realm's HMAC key is not the destination's. The archive's own chain is walked first, from `audit_chain.json`, before anything is imported. |
| `expired_token` for an unknown device code | Loses RFC precision, gains an anti-enumeration property (O-4). Worth a deliberate decision, not a silent narrowing. |
| A stray `client_secret` on a public client is ignored | Documented at `engine/oauth.rs:3275` and load-bearing for the timing-parity work in 22.25 — hashing must depend on the caller's input, never on what the lookup found. The problem is which endpoints accept a public client (O-2), not this rule. |
| Discovery always advertises `registration_endpoint` | `oidc_discovery()` is issuer-level, not realm-scoped, and cannot know a given realm's `dcr_policy`. The endpoint is present; it answers 403 where DCR is off. |
| `HEARTH_MASTER_KEY` is both the host key-wrapping key and the backup passphrase | Undocumented coupling rather than a defect, but worth knowing: rotating the host master key makes every previously written archive undecryptable with the new value, and pointing `backup create` at a store whose KEKs were wrapped under a different master key fails at open time. |

---

## Fixes

Four, each with a mutation proof: the guard was deleted, exactly the named
test was run, it went red, the guard was restored and the file compared
byte-for-byte against its pre-mutation SHA-256.

### F-1 — `build_all_engines` hands the audit engine the KEK (B-2)

`src/main.rs`. One line plus the derivation: the KEK the function already
receives for the identity engine now also reaches `EmbeddedAuditEngine`.

Test `build_all_engines_gives_the_audit_engine_the_kek` seeds an
HKEY-enveloped audit chain key with an engine that *definitely* has the KEK —
so the assertion cannot pass by both sides agreeing on "no KEK at all" — then
calls `export_chain_material`, which is exactly what
`backup create --include-audit` calls.

### F-2 — the restore summary and exit code cover every bucket (B-4)

`src/main.rs`. `print_import_report` now loops over all eleven
`EntityCounts`, and the exit-code decision moves into
`import_report_had_errors`, which names all eleven.

Test `restore_exit_code_counts_every_entity_bucket` sets **one bucket at a
time**, so a fix that only widens the check partially still fails.

### F-3 — a failed `backup create` deletes its partial archive (B-5)

`src/main.rs`. Everything from `BackupArchive::create` onward runs inside a
closure; on `Err` the output file is removed before the error propagates.

Test `backup_create_removes_the_partial_archive_when_it_fails`.

### F-4 — `verification_uri` names the routed page (O-1)

`src/identity/engine/oauth.rs`: `{issuer}/device` → `{issuer}/ui/device`.

Assertion added to the existing `conformance_rfc8628_device_authorization`
test in `tests/oauth.rs`, which previously only checked the field was
non-empty.

---

## Reported, not fixed

| # | Why not |
|---|---|
| B-1 system realm | The export omission is a one-line enumeration change, but *restoring* the system realm writes operator identities into a target store, and whether a DR restore should do that silently is an owner decision. Raise as its own task. |
| B-3 member elision | Needs the manifest to become the authority on the archive's contents — `verify` asserting that every checksummed path was actually read, and `restore` cross-checking `record_counts`. Both are real work and both change what an older archive means. |
| B-6 partial apply | Wants an all-or-nothing restore (stage then commit). Too large for this pass. |
| B-7 restore skips verification | Policy: doubles the read on a large archive. Pair it with B-3. |
| O-2 public-client introspection | Behaviour change with real breakage risk, on a helper shared with `/revoke`. |
| O-3 device-code redemption lock | Cannot be mutation-proven without an interleaving hook. **Unproven.** |
| O-4 `expired_token` | A deliberate trade, not an oversight. |
| O-5 DCR endpoint divergence | Which shape is correct is a product decision. |

## Documentation drift found along the way

- `docs/guides/backup.md`'s archive-layout table omits `mfa_factors.ndjson`,
  which the exporter has written since audit §4.18#5.
- The same table, and the `backup verify` section ("Detects silent corruption
  or tampering"), do not say that a *removed* member is neither detected nor
  reported (B-3), nor that `restore` does not run `verify` (B-7).
- `src/backup/mod.rs`'s doc on `BackupArchive::open` says
  `UnsupportedVersion` means "created by a newer, incompatible version".
  `open` rejects `format_version != MANIFEST_VERSION`, so an **older** v1
  archive is rejected by the same branch — confirmed above.
- `BackupManifest::signing_key_dek_b64` is documented as "retained for
  backward-compatible deserialization of v1 archives". No v1 archive can reach
  that deserialization, because `open` rejects it first. The field is dead.
- `--allow-missing-signing-key`'s help text ("every token issued before the
  backup will stop validating" if you pass it) implies that not passing it
  keeps them valid. It does not: sessions are not exported, so they stop
  validating either way.
