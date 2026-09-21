# What the documentation still claims that is not true

Task 24.5 (audit 2026-08-28 §6, §9 item 4).

§9 item 4 said "Section 6 has more FALSE rows than TRUE." It does: **22 FALSE, 1
TRUE-but-misleading, 4 TRUE, 3 unverified — 30 rows.** The audit also called that
table "a floor, not a ceiling," and it was right. Re-deriving every row at HEAD
(`333c74e6`) and then sweeping the same documents for claims §6 never looked at
produced **51 tested claims, 30 from §6 and 21 it never reached.**

**The headline result is the opposite of what the task brief expected.** Of the 22
rows §6 marked FALSE, **21 are now TRUE** — the code caught up over the intervening
three weeks and, in most cases, the documentation was corrected with it. Exactly one
§6 FALSE row is *still* false at HEAD. The rot has moved: it is now almost entirely
in the documents §6 never opened.

| Bucket | Tested | False at HEAD |
|---|---:|---:|
| §6 rows | 30 | 1 |
| Claims §6 never tested | 21 | 19 |
| **Total** | **51** | **20** |

One §6 row (the performance table) remains **unverified** rather than false — it
needs hardware this sweep does not have, and the README already says so. One remains
**unverifiable** (cluster-mode GA readiness) and is now caveated rather than asserted.

---

## Part 1 — every §6 row, re-derived at HEAD

Verdicts are mine, from the code at `333c74e6`. The audit's verdict is shown only so
the movement is visible.

| # | Claim | Audit | **At HEAD** | Evidence |
|---|---|---|---|---|
| 1 | "900+ Rust tests, all green" | FALSE | **FALSE → fixed** | README said 4,643 (2,245/2,337/61). Real count: **5,387** (2,593 unit · 2,715 integration · 79 simulation), 14 `#[ignore]`d. `cargo nextest list --workspace`. |
| 2 | `make check` passes | FALSE | **no doc asserts it** — and it does not pass (see D-1) | `make check` runs `clippy fmt test-quality test`; `test-quality` is red. Prescriptive text in `CLAUDE.md` only, so nothing to correct. |
| 3 | WAL `fsync`'d before ack; survives `kill -9` | FALSE | **TRUE** | Task 2.4 fixed rotation destroying acknowledged writes; task 24.2 (`63387739`) added the test that can tell `fsync`-before-ack from no `fsync`, and rewrote the doc comment that falsely claimed prior coverage. |
| 4 | "Encrypted at rest with per-realm keys" (3 normative docs) | FALSE | **TRUE** | All three now say the opposite, correctly: `ARCHITECTURE.md:250` ("the key-encryption key is **not** per realm"), `SECURITY.md:98` ("one KEK covers every realm"), `docs/guides/security-model.md:199`. |
| 5 | System realm read-only through public APIs | FALSE | **code TRUE, README incomplete → fixed** | 15 engine entry points raise `SystemRealmProtected`; RBAC writes are gated at the **protocol edge** instead (`reject_system_realm_write`: 10 REST routes, 17 gRPC RPCs). The README named only 5 operations and never mentioned the RBAC gate — the exact hole §4.1#7 exploited. |
| 6 | A failing release "is never published" | FALSE | **TRUE** | `CHANGELOG.md:57-65` carries an explicit, signed correction naming the unqualified claim as wrong. `scripts/check-publish-gating.sh` exits 0: every publish job waits for a green verdict on its own commit. |
| 7 | SLSA + cosign verifiable | TRUE, MISLEADING | **TRUE, and now says so → fixed** | `verify-release.md` listed what the checks do not prove but omitted the one that mattered. Added: provenance attests origin, not fitness; both commands passed for v1.6.11, a red commit. |
| 8 | Storage keys realm-prefixed, scans realm-bounded | TRUE | **TRUE** | Unchanged. |
| 9 | Ed25519 only; no `alg:none` | TRUE | **TRUE** | Unchanged. |
| 10 | No cross-realm token acceptance | TRUE | **TRUE** | Unchanged. |
| 11 | Rotation is the remedy for a compromised key | FALSE | **TRUE** | Task 2.9 made rotation revoke the retired key; 18.7 propagates the key epoch across nodes. |
| 12 | `want_authn_requests_signed` | FALSE — dead | **TRUE** | Consulted at `src/protocol/web/saml.rs:584`, and **fails closed**: an SP with the flag set but no `sp_certificate_pem` is refused 403. |
| 13 | `security.backup.verify_key` fail-closed | FALSE — dead | **TRUE** | `main.rs:2411-2482` decodes it and calls `with_backup_verify_key` on both construction paths; `admin.rs:5172` enforces it; `auth.rs:494` refuses an archive with no detached signature. |
| 14 | `storage.fsync` is a working knob | FALSE — dead | **TRUE** | `main.rs:1001` honours `true` in dev; `fsync: false` outside dev is a **hard validation error** (`main.rs:1039-1045`). |
| 15 | `security.http2.*` rapid-reset caps | FALSE — dead | **TRUE** | Applied at **both** `serve.rs:133` (plaintext) and `serve.rs:284` (TLS) — the listener asymmetry the audit found is closed. |
| 16 | `auth.token.magic_link_ttl` | FALSE — dead | **TRUE** | Read at `engine/mod.rs:3204` and applied to the expiry check at `:9771`. |
| 17 | WebAuthn user-verification policy | FALSE — dead | **enforcement TRUE; advertisement PARTLY FALSE → documented (D-2)** | `realm_requires_user_verification` gates completion at `engine/mod.rs:9503`. But two authentication-challenge endpoints still hard-code `"preferred"`. |
| 18 | Eight abuse guards documented "Shipped" | FALSE | **TRUE** | `ABUSE.md:7` now defines "Shipped" as *constructed from `hearth.yaml` and consulted in production*, and `:29-41` names the production call site for each of the 11 guards. |
| 19 | `private_key_jwt`, `jwt-bearer`, FAPI 2.0 Advanced | FALSE — unreachable | **TRUE** | `assertion_public_key` is writable: `PATCH /admin/applications/{id}` → `admin.rs:2609` → `engine/oauth.rs:3340-3356`, which validates it as a 32-byte base64url Ed25519 key. |
| 20 | Magic-link login | FALSE — unreachable | **TRUE** | Redemption routes `/magic-link` and `/realms/{realm}/magic-link` exist; the grant the SDKs post, `urn:hearth:grant-type:magic-link`, is handled at `oauth.rs:317/397`. |
| 21 | SP-initiated SAML SSO | FALSE — unreachable | **TRUE** | The ACS issues a real session, and `saml.rs:293` audits a completed login **only** when `issued_session_cookie(&response)` — the exact defect, inverted into the guard. |
| 22 | README documents `PUT` for 5 admin mutation routes | FALSE | **TRUE** | Every admin mutation row in the README route table reads `PATCH`. The three surviving `PUT`s are real: `/admin/webhooks/{id}`, `/admin/api/realms/{realm}/audit/config`, SCIM `Users`/`Groups`. `docs/guides/admin-api.md:458` documents the 405. |
| 23 | HSTS automatic "when TLS is enabled" | FALSE | **TRUE** | `hsts_on_forwarded_proto` (`web/security.rs:40,116`) covers the proxy-terminated shape, and `security-hardening.md:391` carries a per-deployment table. |
| 24 | `hearth --version` reports the running version | FALSE | **TRUE** | `build.rs` prefers `HEARTH_RELEASE_VERSION`, then `git describe`, and *warns loudly* on the `Cargo.toml` fallback. `check-readme-version.sh` and `check-chart-image-tag.sh` both exit 0. |
| 25 | Container images are Apache-2.0 | FALSE | **TRUE** | `Dockerfile:165` labels `Apache-2.0`; `LICENSE` and `Cargo.toml` agree. `check-dockerfile-claims.sh` exits 0. |
| 26 | The documented Docker and Helm install paths work | FALSE | **STILL FALSE → doc corrected, code not fixable here** | See below. |
| 27 | `mode=overwrite` restore is supported | FALSE | **TRUE** | Task 2.3 made it refuse rather than destroy; `docs/guides/backup.md:118` documents the refusal. |
| 28 | Cluster mode is production-ready | UNVERIFIABLE | **still UNVERIFIABLE → caveated** | Four follower bypasses closed (`reports/follower-bypass-enumeration-2026-09-21.md`), but no live three-node enumeration has been done (task 23.16 open). `docs/STATUS.md` now says so instead of a bare "✅ Shipped". |
| 29 | Performance table | UNVERIFIED | **still UNVERIFIED** | Needs a quiesced server-class host. README already states "A re-verification pass against a current HEAD SHA is pending" and refuses to publish competitor ratios. No change — the honest text was already there. |
| 30 | Protocol conformance (OIDC, SCIM, SAML, 7 RFCs) | UNVERIFIED | **FALSE in a new way → fixed** | See N-11. |

### Row 26 — the one §6 claim still false

Independently confirmed twice, on 2026-09-21:

```
$ curl -o /dev/null -w '%{http_code}' https://ghcr.io/v2/hearth-auth/hearth/manifests/v1.6.10
401
$ bash scripts/check-install-paths.sh
2 documented install path(s) fail at the first command.   (exit 1)
```

The repo and its Releases are public (both answer 200); the two **GHCR packages** are
not. Release validation now gates on an anonymous fetch, so newly published versions
will be public — but flipping the two that already exist needs a token with
`write:packages` and has not been done (task 3.4, open). I cannot fix that from here,
so the README now **withdraws** the claim rather than restating it: the `docker pull`
and `helm install` blocks carry a "Known gap" admonition saying they fail anonymously
today, what to do instead, and why.

---

## Part 2 — claims §6 never tested

21 claims, 19 false at HEAD. This is where the drift now lives. Nine of the nineteen
sit in `docs/STATUS.md` and `docs/specs/`, which are precisely the documents §9 item 4
warned operators make security decisions from.

| # | Document | Claim | Verdict | What the code does |
|---|---|---|---|---|
| N-1 | `docs/STATUS.md` roadmap | "FAPI 2.0 (PAR, JAR, JARM, realm enforcement) ❌ Not implemented" | **FALSE** | All four ship. `POST /as/par` (`oauth.rs:53`), `verify_jar` consumed on `/authorize` and PAR (`engine/oauth.rs:272,2383`), `sign_jarm_error_jwt` (`identity/mod.rs:1701`), `RealmConfig::fapi_profile` + `ClientProfile::Fapi2`. |
| N-2 | `docs/STATUS.md` roadmap | "Agent entity, Agent Card, A2A / MCP surfaces — no implementation in `src/`" | **FALSE** | `GET /.well-known/agent.json` (`http/agents.rs:39`), `http/tool_invocation.rs`, MCP scopes at `oauth.rs:197`. |
| N-3 | `docs/STATUS.md` roadmap | "Delegation chains, AATs, approval lifecycle — no implementation" | **FALSE** | `engine/aat.rs`, `engine/approval.rs`, `engine/txn.rs`, `engine/cross_realm.rs`, `engine/spiffe.rs`. `AGENT_AUTH.md`'s own banner has said "all milestones shipped" since 2026-06-21 — STATUS.md contradicted a sibling spec. |
| N-4 | `docs/STATUS.md` roadmap | "SAML 2.0 SP / IdP — no implementation" | **FALSE** | 13 modules under `src/identity/federation/saml/`; 7 routes. |
| N-5 | `docs/STATUS.md` roadmap | "SCIM 2.0 provisioning — no implementation" | **FALSE** | 10 modules under `src/protocol/scim/`. |
| N-6 | `docs/specs/SDK.md:6` | "Hearth has not shipped yet. Breaking changes are fully acceptable… No backward-compatibility work, deprecation periods, or migration guides are required." | **FALSE** | 1.0 GA shipped 2026-06-21 (`git tag v1.0.0`, CHANGELOG `[1.0.0]`). `VERSIONING.md` puts the 1.x line at active-to-2027-12-21, EOL 2028-06-21. **This was the single most load-bearing false sentence found**: it told every SDK author that none of the compatibility obligations applied to them. Withdrawn. |
| N-7 | `docs/specs/ARCHITECTURE.md:685` | "Pre-1.0-GA compatibility \| Breaking changes permitted \| …the strict rules activate at 1.0 GA" | **FALSE** | Same release ended it. A normative spec still granting "breaking permitted" post-GA is worse than a missing policy. Row rewritten as "Compatibility \| Strict SemVer, in force now". |
| N-8 | `docs/specs/SAML.md:22` | "Hearth acts **only as a SAML SP**. It is not a SAML IdP for third parties." | **FALSE, and never true** | `saml/idp.rs` and four IdP routes (`/realms/{realm}/saml/{metadata,sso,sso/init,slo-idp}`) have been registered since the initial SAML commit `8fd2f02b`. §1 rewritten with a route table for each role, plus an explicit warning that §§2–7 specify only the **SP** path — silence there is not a normative statement about IdP behaviour. |
| N-9 | `docs/specs/TESTING.md:642` | "the codebase has zero `#[ignore]` markers today, so no allow-list management is needed" | **FALSE** | **14** `#[ignore]` attributes: 4 `abuse_phase0.rs`, 7 `ldap_federation.rs`, 1 `backup.rs`, 1 `tenant_enumeration_oracle.rs`, 1 `wal_group_commit.rs`. Corrected with the real count and the note that rule I is text-based, not semantic. |
| N-10 | `docs/specs/TESTING.md:614` | the lint runs in "the `check` job in `.github/workflows/ci.yml`" | **FALSE** | `ci.yml` has no job called `check`. It runs as a `make test-quality` step in the **`quality`** job, which *is* in `required-summary`'s `needs:`. Substance right, name wrong — corrected, because a reader looking for job `check` concludes the gate does not exist. |
| N-11 | `docs/specs/TESTING.md:136-145` | "Run **official** specification test suites… OIDC Certification test suite / SAML conformance suite / SCIM compliance tests (added when the layer is implemented)… treated as required-pass in CI" | **FALSE** | All three layers shipped; **no certifying body's suite has ever been run.** What exists is seven hand-written in-repo suites (`oidc_conformance.rs`, `fapi_conformance.rs`, `fapi2_conformance.rs`, `rfc8693/8707/9728_conformance.rs`, `federation_conformance.rs`) plus `check-sdk-conformance.sh`. §7 rewritten to list exactly those and to state plainly: **do not represent Hearth as certified.** Mirrored in the README's testing-layer list. |
| N-12 | `docs/specs/AUTHZ_EXPANSION.md:3` | "claim-profile structs skeletal" | **FALSE** | `apply_claim_profile` is called on every token-issue path (`engine/mod.rs:3619,8060`, `engine/oauth.rs:859,874,3052`) and `RealmConfig.claim_profile` is populated from YAML in `main.rs:3716`. |
| N-13 | `AUTHZ_EXPANSION.md:883,1027` | "**ArcSwap hot-swap not yet wired**" | **FALSE, and self-contradictory** | `main.rs:1416` builds it; `:3428` types it `RegistrySwap`; rebuilt after each SIGHUP reconcile. The same file's §Delivery Phasing already ticked this box — the document disagreed with itself. |
| N-14 | `AUTHZ_EXPANSION.md:1026` | "`User.attributes` — runtime validation not yet done" | **FALSE** | Validated at `create_user_with_status`, `update_user_impl` and `import_user`. Same internal contradiction as N-13. |
| N-15 | `AUTHZ_EXPANSION.md:1032` | "`create_user`/`import_user` don't yet have `attributes` field on request structs" | **FALSE** | `CreateUserRequest.attributes` at `src/identity/types/user.rs:412`. |
| N-16 | `README.md` route table | `/authorize` is `POST` | **FALSE** | `get(authorize_browser_redirect).post(authorize)` — the `GET` form is the browser entry point, i.e. the one a reader most needs. |
| N-17 | `README.md` route table | `/jwks` | **incomplete** | `/certs` and `/.well-known/jwks.json` are registered aliases; an SDK author reading only this table would not find the standard path. |
| N-18 | `docs/STATUS.md` | Keycloak migration: "Integration tests (7 scenarios)" | **FALSE** | 9 `#[test]`/`#[tokio::test]` in `tests/migration_keycloak.rs`. |
| N-19 | `docs/guides/security-hardening.md:215` | points at `src/identity/engine.rs` for the adaptive-MFA fail-secure behaviour | **FALSE (dead path)** | The engine was split into `src/identity/engine/`. A security runbook pointing at a nonexistent file is a runbook nobody can check. |
| N-20 | `docs/specs/CONFIGURATION.md:570` | `webauthn_user_verification` is "the `userVerification` preference" | **incomplete** | Enforcement is unconditional; **advertisement is not** (D-2). A four-row table now names which endpoints echo the preference and which hard-code `"preferred"`. |
| N-21 | `docs/STATUS.md` roadmap | "FIDO2 / CTAP2 platform authenticator (beyond basic WebAuthn)" | **UNVERIFIABLE** | "Beyond basic WebAuthn" names no symbol, route or config key, so there is nothing to test either way. Deleted rather than restated — an untestable roadmap row is indistinguishable from a false one. Recorded here so the deletion is not silent. |

### Where the counts differed

The brief warned that this project's audit counts run understated. They did again,
but in a direction worth naming: §6's 30 rows were an accurate floor **for the
documents §6 opened**. The undercount is in coverage, not arithmetic — §6 never
opened `docs/STATUS.md`'s roadmap, `SDK.md`'s banner, `SAML.md` §1, `TESTING.md` §7
or `AUTHZ_EXPANSION.md`, and every one of those held a false claim. Two other counts
moved: the README's 4,643 tests is now 5,387, and its "five admin mutation routes
documented as PUT" is now zero.

---

## Files changed

| File | Change |
|---|---|
| `README.md` | Test count re-derived and "all green" withdrawn in favour of a statement about the merge gate · Docker/Helm anonymous-install gap disclosed · SAML described in both roles · system-realm paragraph corrected and completed · `/authorize` and `/jwks` rows fixed · conformance layer de-certified |
| `docs/STATUS.md` | Banner re-dated with provenance · LDAP + webhook rows added · cluster caveat added · 10 protocol rows added (PAR, JAR, JARM, FAPI 2.0, RFC 8693/8707, SAML SP, SAML IdP, SCIM, agent identity) · migration test count corrected · roadmap rebuilt from 8 stale rows to 3 verified ones |
| `docs/specs/SDK.md` | Pre-release "Hearth has not shipped yet" note withdrawn; replaced with the real support window |
| `docs/specs/ARCHITECTURE.md` | Pre-1.0-GA compatibility row replaced with the in-force SemVer policy |
| `docs/specs/SAML.md` | Scope + §1 rewritten for both roles, with route tables and a scope warning · `want_authn_requests_signed` enforcement documented, including the POST-binding constraint and the fail-closed branch · §2 artifact/SOAP rows made honest about *how* they are unsupported |
| `docs/specs/TESTING.md` | §7 conformance rewritten: in-repo suites listed, "official suite" promise withdrawn · `#[ignore]`-count claim corrected · CI job name corrected · Phase 1 / Phase 2+ rollout rows annotated |
| `docs/specs/CONFIGURATION.md` | `webauthn_user_verification` enforcement documented; new table of which challenge endpoints echo the preference |
| `docs/specs/AUTHZ_EXPANSION.md` | Status line re-derived; three internal contradictions resolved against the code; `engine.rs` path corrected |
| `docs/guides/verify-release.md` | "What these checks do NOT prove" now includes *that the commit passed its own test suite*, with the v1.6.11 case |
| `docs/guides/security-hardening.md` | Dead `src/identity/engine.rs` path corrected |
| `CHANGELOG.md` | One `### Fixed` bullet (operator-visible surface descriptions changed) |

No `.rs` file, no file under `openspec/`, and no workflow was touched.

---

## Code defects found, not fixed

### D-1 — `make test-quality` is red at HEAD, and it is a merge gate

```
$ bash scripts/check-test-quality.sh
✗ #[ignore] without an HEA-#### tracking issue (2):
  src/rbac/resolution_cache.rs:427
  tests/tenant_enumeration_oracle.rs:246
✗ test-quality lint: 2 violation(s)          (exit 1)
```

This is not advisory. `make check` runs `clippy fmt test-quality test`, and the CI
`quality` job runs `make test-quality` as its own step **before** `make check`;
`quality` is in `required-summary`'s `needs:`. So the CI gate this branch depends on
would fail at `333c74e6`.

Two distinct problems:

1. **Real violation** — `tests/tenant_enumeration_oracle.rs:246` is
   `#[ignore = "21.11: byte-identity across pre-auth realm shapes is not implemented
   yet; this test is the acceptance criterion for it"]`. `21.11` is an OpenSpec task
   number; rule I wants an `HEA-####`. It also trips the warn-only "not yet
   implemented" heuristic. Fix: file the issue and put its number in the message.
2. **False positive** — `src/rbac/resolution_cache.rs:427` is a *prose comment* that
   happens to contain the text `#[ignore]`. Rule I greps for `#[ignore` rather than
   parsing attributes. Fix: either reword the comment or make the rule skip comment
   lines.

Corollary worth recording: the belief that `make test-quality` sits outside
`make check` is **wrong at HEAD** — `Makefile:147` puts it in the gate list.

### D-2 — WebAuthn `userVerification` is enforced but not advertised on two endpoints

A realm configured `webauthn_user_verification: "required"` is enforced at
completion — `engine/mod.rs:9503` rejects an assertion whose UV bit is clear — so
**this is not an authentication bypass.** But two authentication-challenge endpoints
hard-code `"preferred"` in the options they hand the browser:

| Endpoint | Handler | Line |
|---|---|---|
| `POST /ui/account/passkeys/step-up-begin` | `passkey_step_up_begin` | `src/protocol/web/account.rs:1027` |
| `POST /webauthn/auth/begin` | `webauthn_auth_begin` | `src/protocol/http/mfa.rs:384` |

The registration ceremonies and the passkey *login* challenge all read the realm
config correctly (`account.rs:1074-1119`, `handlers.rs:2099-2108`), which is what
makes the two outliers look like an oversight rather than a decision. Effect: on an
authenticator that can do UV but was not asked, the browser skips the gesture and the
assertion is refused at completion — a late, opaque failure instead of a prompt.
Documented in `CONFIGURATION.md` rather than papered over.

### D-3 — the two GHCR packages are still private (not a code defect; needs a token)

Restated from Part 1 because it is the only §6 row still false. `ghcr.io` answers
`401` to an anonymous manifest fetch for both `hearth-auth/hearth` and
`hearth-auth/charts/hearth`. Flipping them needs `gh auth refresh -s write:packages`
followed by `gh api --method PATCH /orgs/hearth-auth/packages/container/<name> -f
visibility=public`. Tracked as task 3.4.

---

## What this sweep could not settle

- **Row 29, the performance table.** Every figure needs a quiesced server-class host
  with isolated cores and a performance governor. The README already states the
  re-verification is pending and already refuses to publish competitor ratios; I
  changed nothing, because inventing a hedge would be no more honest than the
  existing disclosure.
- **Row 28, cluster-mode readiness.** Four follower bypasses are closed and proven.
  Whether a fifth exists is unknown until someone stands up three nodes (task 23.16).
  `docs/STATUS.md` now says exactly that instead of an unqualified "✅ Shipped".
- **"All green."** I enumerated the suite (5,387 cases) but did not run it — the task
  forbade it. So the README no longer asserts a green result for any commit; it points
  at the CI badge and at each release's `validation-summary.txt`, both of which are
  claims someone else makes and can be checked. Given D-1, that restraint turned out
  to be the correct call: the suite's own gate is red at HEAD.
