# Hearth — Pre-GA Production Readiness Audit

**Target:** `hearth-auth/hearth` at `b291a723`, branch `feature/production-readiness-audit-8-28-26`
**Date:** 2026-08-28
**Method:** Whitebox source review with live testing against running instances.
**Status:** **COMPLETE, with 7 of 32 pieces unfinished and their findings excluded.** 25 pieces
passed adversarial review; the 7 that did not are named in §7.2, and what they leave unmeasured is in
§8.1. Do not read an absent subsystem as a clean result — read it as an unexamined one.

---

## 0. How this audit was run, and against what standard

The quality bar was set explicitly: the Trail of Bits *Kubernetes Security Assessment* of
31 May 2019. That document was obtained in full and read directly rather than from a description of
it — the primary sources were recovered from commit `5844b959` of `kubernetes/community`, because
`wg-security-audit/` was retired in September 2020 and the findings PDFs went with it.

Facts re-derived from that document and used as the bar:

- Kubernetes v1.13.4, whitebox source review, 4 consultants, 12 person-weeks over 8 calendar weeks.
- 37 findings: 5 High, 17 Medium, 8 Low, 7 Informational (Project Dashboard, p.6).
- Severity and difficulty are stated **separately** on every finding (Appendix A, pp.90–91).
- Recommendations are split **short term** / **long term** (Recommendation Summary, pp.13–17).
- Coverage is its own section, stating what was *not* examined (p.11).
- Proof-of-concept exploits live in appendices (C–E); one appendix (B) enumerates every instance of
  a single bug class.
- Documentation defects are findings with severities (#19, Appendix H).

Every finding below therefore carries a Severity **and** a Difficulty, a Target, a deployment-shape
tag, the trust boundary it crosses, a real code excerpt or command transcript, an exploit scenario
with an actor, and a short-term / long-term recommendation.

### The adversarial process

The audit was decomposed into 32 independently judgeable pieces. Each piece was worked by an auditor
and then attacked by a separate critic with fresh context. The critic:

1. Opened **every** `file:line` the auditor cited. A citation that did not resolve killed its finding.
2. Re-ran **every** repro the auditor gave. A repro that did not run killed its finding.
3. Challenged the negative results too — an unsupported "I checked this and it is sound" was killed,
   because that is the sentence an operator acts on.
4. Then placed our section beside the matching Trail of Bits section **with the labels stripped**,
   and named which one an operator would trust more, plus the single biggest remaining gap.

A piece was accepted only when the critic, judging blind, picked ours. A tie counted as a loss and
sent the piece back for another round. Findings that appear below have survived that process; the
critic's residual objection is recorded with each piece, because it is the honest limit of the work.

**The repository was not modified by this audit**, apart from this report file. Every experiment
requiring a mutated tree was run in a clone under `/scratch`. Verified with
`git status --porcelain` throughout.

---

## 1. Verdict

**NO-GO on all five deployment shapes.** Eleven blocker-class defects are confirmed by
reproduction, and only two of them require an attacker — the rest are data-integrity and
release-integrity failures that fire during ordinary operation. A clean `SIGTERM` loses acknowledged
writes, a documented restore command destroys tenants, deleted data returns without any crash, and
the release pipeline signs and publishes builds whose own test suite is failing.

This verdict is **provisional in one direction only**: 25 of 32 audit pieces cleared adversarial
review; 7 did not and their findings are excluded entirely. Further findings can only make it worse.
Nothing outstanding could overturn a single blocker below, because each is established by a
reproduction that a hostile reviewer re-ran independently.

### Per deployment shape

| # | Shape | Verdict | The decisive defects |
|---|---|---|---|
| 1 | Single node, HTTP, defaults, behind a reverse proxy — **the modal deployment** | **NO-GO** | B4 (clean `SIGTERM` loses acknowledged writes), B11 (deleted data returns with no crash), B3 (documented restore destroys the tenant), B8 (bootstrap credential in the log at default level), B9 (rotation does not revoke), B1 (tenant admin reads and overwrites a peer tenant) |
| 2 | Single node with TLS terminated by Hearth | **NO-GO** | All of shape 1, plus the TLS server does not drain in-flight requests on `SIGTERM` and still exits 0 |
| 3 | Multi-node cluster (Raft) | **NO-GO**, and should not ship as GA at all | All of shape 1, plus follower caches never receive invalidation: realm suspension, signing-key rotation, the DPoP kill-switch and the delegation JTI blocklist are all stranded on followers. Two of those are kill-switches. The project's own known-defects list scopes this to "RBAC and session caches" only |
| 4 | Embedded / library use | **NO-GO** | All of shape 1, plus B5 (SAML signature wrapping is a full authentication bypass at this shape) and no loopback guard on the embedded path |
| 5 | Migration in, and upgrade across versions | **NO-GO** | Every CLI subcommand that opens a production data directory opens it with the **development** storage config — both migration importers acknowledge success with no WAL `fsync`. Backup silently drops every TOTP secret, passkey and OTP factor while the record type says otherwise |

### On cluster mode specifically

The brief asks directly whether cluster mode is GA-quality or must ship gated behind an explicit
experimental opt-in. On the evidence gathered so far it is **not GA-quality**, and the reason is not
a missing feature — it is that a control which is sound on a leader is unsound on a follower, and the
project does not know the full extent of it. Its own known-defects list names two caches; the audit
found at least four more security-relevant paths with the same asymmetry, including two kill-switches
and key rotation. Shipping that as GA meets the brief's own definition of a blocker: *"shipping a
subsystem as GA when the evidence doesn't support it."*

The dedicated cluster-mode piece is still in adversarial review. This paragraph will be replaced by
its result, not softened by it.

### The condition that precedes all others

**The build does not currently meet the project's own definition of green.** Five of the six gates
covered by `make check` and the supply-chain targets are red at `b291a723` on a clean checkout, and
`make check` cannot complete at all — clippy aborts first, so CI has never executed `cargo fmt
--check` or the test suite on this commit. Two of the four failing tests are the project's own
regression tests for data-integrity defects, and both defects are confirmed present.

Until that is true, no other remediation can be verified, and every conclusion in this report is
caveated by it.

---

## 1A. The five things I'd fix first

Ordered by what an operator loses if it is not fixed, not by how hard it is. Effort estimates are
rough and assume someone who knows the codebase.

**1. Make the release pipeline refuse to publish a failing build. (~1 day)**
Not because it is the worst defect, but because it is the one that lets every other defect reach
users. Today the container image, Helm chart, seven SDK releases and two registry packages ship from
a commit whose suite is red, the merge landed 41 minutes before its own required check reported
failure, cosign and SLSA then attest to it, and the documented verification commands **pass**. Make
the required check actually required, remove the `continue-on-error` on both advisory gates, and gate
every publish channel on the same signal the binary channel already uses.

**2. Fix durability, then prove it with a test that can fail. (~1 week)**
WAL rotation destroys acknowledged writes under concurrent writers; nothing flushes the memtable on
the shutdown path; a clean `SIGTERM` is sufficient. Fix that. Then close the finding that explains why
nobody caught it: **no test in the repository can distinguish `fsync`-before-ack from no `fsync` at
all.** The fix is not done until that test exists and fails against the old code.

**3. Stop deleted data from coming back. (~1 week)**
Three independent paths resurrect deleted keys: the partial-compaction rename/unlink window on the
shipped default config, `reload_sst_readers()` silently dropping an unopenable SST and then discarding
tombstones with no crash at all, and realm deletion sweeping a hand-written prefix allowlist rather
than the realm's key space. The third has a fix already in the codebase — **the cluster path already
does the key-space sweep**; use it everywhere.

**4. Make `overwrite` restore safe, and make the backup CLI speak. (~2–3 days)**
`mode=overwrite` deletes the target realm and then fails to restore it: 1,160 runs, none completed,
975 left the realm destroyed or truncated, one reported exit 0. Refuse the operation rather than
half-execute it. Separately, install a `tracing` subscriber for the `backup` CLI family — today
`create`, `restore`, `verify` and `inspect` emit **zero bytes**, which is why a destructive
half-restore is silent.

**5. Audit the class of controls that parse, validate, and do nothing. (~3–4 days)**
This is a class, not a bug: `want_authn_requests_signed`, `security.backup.verify_key`,
`security.http2.*`, the WebAuthn user-verification knob, three documented WebAuthn realm policies,
`storage.fsync`, `auth.password_memory_cost`, and eight abuse-prevention guards documented as
"Shipped" that are never constructed outside their own tests. In each case an operator sets a
security control, nothing rejects the value, and the control does not exist. Add a start-up assertion
that every parsed security key reaches a consumer, and fail closed when one does not.

**Not in the five, and deliberately so:** the SAML signature-wrapping bypass and the MFA
user-verification bypass are more alarming to read, and both are genuinely severe. They are ranked
below the five above because each has a containment an operator can apply today — disable SAML
federation; set `passkey_requires_mfa: true` — whereas the five above have none.

---

## 2. Phase 0 — State of the build

All figures below were produced on a clean checkout at `b291a723`. Raw logs retained.

| Gate | Command | Result |
|---|---|---|
| Build | `cargo build --release` | **pass**, 97 s |
| Format | `cargo fmt --check` | **FAIL** (rc 1) — 7 diff hunks across 5 files |
| Lint | `cargo clippy --all-targets -- -D warnings` | **FAIL** (rc 101) — hard compile error |
| Tests | `cargo nextest run --workspace` | **FAIL** — 4736 run, 4732 passed, **4 failed**, 13 skipped, 76.2 s |
| Supply chain | `cargo deny check` | **FAIL** — `advisories FAILED, bans ok, licenses ok, sources ok` |
| Supply chain | `cargo audit` | **FAIL** — 1 vulnerability, 1 yanked crate |

### 2.1 The four failing tests

```
FAIL [0.117s] hearth::backup_http backup_restore_dry_run_returns_counts
FAIL [0.108s] hearth::backup_http backup_restore_emits_pre_restore_audit_event
FAIL [0.206s] hearth::graceful_shutdown sigterm::sigterm_does_not_abort_inflight_http_request
FAIL [0.054s] hearth-simulation tests::sst_compact_crash::simulation_c4_partial_compaction_crash_resurrects_deleted_key
```

Two of these are not ordinary test failures. They are the project's own regression tests for
previously-fixed data-integrity defects, and they are red:

- `simulation_c4_partial_compaction_crash_resurrects_deleted_key` guards against compaction
  resurrecting deleted keys after a crash. In an identity store, a resurrected deleted key is a
  deleted user, a revoked credential, or a removed role assignment coming back.
- `sigterm_does_not_abort_inflight_http_request` guards against a normal shutdown dropping requests
  that are already in flight.

A red regression test means one of two things, and both are reportable: either the defect it guards
has returned, or the guard itself has rotted and no longer defends anything. Which one it is, is
determined in the storage and durability sections below.

### 2.2 Known-vulnerable dependency in the network stack

```
Title:     h2 unbounded empty DATA frames
Date:      2026-08-17
ID:        RUSTSEC-2026-0258
URL:       https://rustsec.org/advisories/RUSTSEC-2026-0258
Solution:  Upgrade to >=0.4.16
Dependency tree:
h2 0.4.14
├── tonic 0.14.6 → hearth 1.6.9
```

`h2` is the HTTP/2 implementation this server listens on. The advisory is a remote denial of service
requiring no authentication. It was published 2026-08-17, eleven days before this audit, and the fix
is a patch-level dependency bump.

`cargo audit` additionally reports `validit 0.2.5` as **yanked**, reached through `openraft 0.9.25`
— the cluster-mode dependency.

### 2.3 The lint failure is a violation of the project's own rule

```
error: used `unwrap()` on a `Result` value
  --> src/protocol/scim/etag.rs:83:40
   |
83 |             h.insert(header::IF_MATCH, HeaderValue::from_str(v).unwrap());
   = note: requested on the command line with `-D clippy::unwrap-used`
error: could not compile `hearth` (lib test) due to 1 previous error
```

`CLAUDE.md` states that `clippy::unwrap_used` is denied and that `unwrap()` is permitted only with an
`#[allow]` plus an `// INVARIANT:` comment. This instance has neither, and it is a hard compile
error rather than a warning — meaning `cargo clippy --all-targets` cannot complete at all.

### 2.4 Three version numbers disagree

| Source | Value |
|---|---|
| `Cargo.toml` | `version = "1.6.9"` |
| Newest git tag (`--sort=-v:refname`) | `v1.6.10` |
| `git describe --tags` at HEAD | `sdk-kotlin-v1.6.10-9-gb291a723` |
| `hearth --version` from the release build | `hearth 1.6.10-9-gb291a723` |

`git describe` at HEAD resolves to a **Kotlin SDK release tag**, not a server release tag, and the
binary's self-reported version is derived from it. An operator asking a running server what version
it is gets a string traceable to an SDK release. Detailed in the day-2 section.

---

## 3. Blocker list

*Accumulating as pieces clear their critic. Each entry links to its full finding below.*

| # | Finding | Piece | Evidence |
|---|---|---|---|
| B1 | `POST /admin/backup` and `/admin/backup/restore` take the realm from a query parameter and never compare it to the caller's realm — a tenant admin exports and overwrites a peer tenant | P13 | Reproduced end to end on a fresh instance: peer-tenant export, then an overwrite-restore that reinstated a pre-rotation signing-key `kid`, printed before and after |
| B2 | The container image, Helm chart, seven SDK releases and two registry packages ship from a commit whose own suite fails four tests, two of them data-durability tests. Only the binary channel is gated. cosign and SLSA then attest to it, and both documented verification commands pass | P27 | The failing suite is reproduced in section 2.1; the merge landed 41 minutes before its one required CI context reported failure |
| B3 | `mode=overwrite` restore deletes the target realm and then fails to restore it. No attacker required — an operator running a documented command destroys a tenant | P12 | 1,160 CLI runs: none completed, all printed nothing, **975 left the realm destroyed**, truncated to an arbitrary subset of users, or unexportable. One reported exit code 0 |
| B4 | **WAL rotation destroys already-acknowledged writes under concurrent writers, and nothing flushes the memtable on shutdown.** A clean `SIGTERM` is sufficient — no crash, no attacker, no disk fault. `CLAUDE.md` requires `fsync` before ack and survival of `kill -9` | P18 | Reproduced. Compounded by finding 11: **no test in the repository can distinguish `fsync`-before-ack from no `fsync` at all** |
| B5 | **XML Signature Wrapping in the SAML assertion consumer.** `verify_signed_element` authenticates one `<saml:Assertion>`; `parse_response` consumes a different one. An attacker with any legitimate upstream account authenticates as any user. BLOCKER in embedded use (shape 4), HIGH in shapes 1–3 | P23 | Reproduced by auditor and independently by the critic: `XSW -> ACCEPTED  consumed assertion.id=_evil1  identity.email=ceo@corp.example`, where the IdP signed `mallory@corp.example` |

| B6 | The v1.6.11 container image and Helm chart were published **37 minutes before** the project's own release-validation job wrote "Release is NOT cleared to publish" | P00 | Timestamps from the workflow logs; the critic re-executed 72 of this section's commands and reproduced them |
| B7 | A crash between partial-compaction rename and unlink resurrects deleted data. **The regression test proving it was committed red** and fails on the project's own runners | P00 / P18 | `simulation_c4_partial_compaction_crash_resurrects_deleted_key`, red at HEAD; independently derived by two pieces |
| B8 | The first-run **setup token** — the highest-privilege bootstrap credential — is written to the production log at WARN **at the default level**, with no loud failure | P26 | Critic reproduced the full chain: leaked setup token → create admin → activate via leaked verification token → authenticated session. Escalated from HIGH at the critic's insistence; see §4.14 |

| B9 | **Rotating a leaked signing key does not revoke it.** The retired key mints new admin tokens for the full 24 h grace window, and neither documented mitigation stops it — so the documented remedy for a key compromise does not remedy it | P06 | The critic wrote the missing end-to-end test: honest non-admin token `403`; forged post-rotation sessionless token **`200` on `GET /admin/users`, `/admin/realms`, `/admin/audit`, `201` on `POST /admin/users`** |
| B10 | **A passkey that never proves user verification satisfies `mfa_required`**; the user-verification knob is dead code. **Remedy exists:** setting `passkey_requires_mfa: true` returns `{"redirect":"/ui/mfa-challenge"}` and issues no session | P16 | Reproduced against a live production-mode instance; the critic extended the probe to prove the stolen session was server-side valid (`GET /ui/account` → 200, rendering the victim's email) |

| B11 | **`reload_sst_readers()` silently drops any SST it cannot open, and the next partial compaction then discards tombstones it must keep.** Deleted data returns during normal operation — no crash, no restart, no error | P19 | Derived and demonstrated in §4.21. Distinct from B7, which needs a badly-timed crash; this one does not |

**Note on the shape of these eleven.** Only B5 and B10 require an attacker. B1 needs a tenant admin acting
within their own API. B8 needs an operator with log access, which in most
deployments means the log aggregator, the on-call rota, and anything that ships logs off-box. B2, B3,
B4, B6 and B7 need nobody at all — a release pipeline that attests to a failing build and publishes
37 minutes before its own gate says no, a documented restore command that destroys tenants, a clean
shutdown that loses acknowledged writes, and a compaction crash that resurrects deleted data whose
regression test was committed red.

An audit brief that expects the danger to live in the attack surface will under-weight this system's
actual failure profile. Seven of the ten blockers are integrity and process failures, not
vulnerabilities. That is the single most important structural observation in this report.

A second pattern is worth naming, because it recurs across unrelated subsystems: **controls that
parse, validate, and do nothing.** `want_authn_requests_signed` (SAML), `security.backup.verify_key`
(restore signature check), `security.http2.*` (rapid-reset caps), the WebAuthn user-verification knob,
three documented WebAuthn realm policies, `storage.fsync`, `auth.password_memory_cost`, and eight
abuse-prevention guards documented as "Shipped" that are never constructed outside their own tests.
In each case an operator sets a security control, nothing rejects the value, and the control does not
exist. That failure mode is worse than a missing feature, because it converts an operator's diligence
into false confidence.

---

## 4. Findings by subsystem

*Sections are added here as each piece clears its critic. A subsystem absent from this list has not
been completed — see the coverage ledger.*

### 4.1 Cross-realm token acceptance and admin IDOR (P13) — accepted

Ten findings survived verification. The **headline negative result is as important as the findings**
and is stated first, because it is what an operator most needs to know:

> No token minted in realm A was accepted in realm B on any entry point reachable in testing, and no
> `/admin/*` handler served or mutated a realm-B object under realm-A credentials. The cross-tenant
> breaks found are **realm-parameter** bugs, not token-binding bugs.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `POST /admin/backup` and `/admin/backup/restore` take their realm from a query parameter and never compare it to the caller's realm | Access Controls | **BLOCKER** | Low |
| 2 | `GET /admin/realms` returns every tenant to any realm admin; its gRPC twin filters, and only the gRPC behaviour is tested | Access Controls | HIGH | Low |
| 3 | `POST /realms/{name}/introspect` and `/revoke` accept unauthenticated requests; the header-form twins require client authentication | Access Controls | HIGH | Low |
| 4 | `/realms/{name}/introspect` omits `active` on the negative response, against RFC 7662 §2.2 | Data Validation | MEDIUM | Low |
| 5 | The pre-shared SCIM bearer token keeps reading a suspended or archived realm's user directory | Access Controls | MEDIUM | Low |
| 6 | Four handlers bypass the `scoped_realm` BOLA guard — two permissively, two so strictly the system operator is locked out | Access Controls | LOW | Low |
| 7 | The reserved system realm accepts role and group writes; the README says it is read-only through public APIs | Configuration | CLAIM-DEFECT | High |
| 8 | Cross-realm trust policies are stored and audited but never consulted: `check_cross_realm_policy` has no production caller | Configuration | CLAIM-DEFECT | Undetermined |
| 9 | Eight authenticated admin handlers carry no per-handler permission gate, so any sub-admin reaches them | Access Controls | LOW | Low |
| 10 | Five admin handlers answer `200` for an object absent from the caller's realm instead of `404` | Error Reporting | LOW | Low |

**Critic's residual objection, recorded verbatim as the honest limit of this section:** the
"found sound" bullets are single-node reasoning presented without a deployment-shape qualifier. Most
damagingly, the realm-status-cache claim is false on a Raft follower — `realm_status_cache` never
leaves `src/identity/engine/mod.rs`, while `src/cluster/state_machine.rs:331-370` replays entries as
raw `StorageEngine::put`. A section tagging eight of ten findings "shapes 1 · 2 · 3" therefore tells
a cluster operator a control is sound when it is not. **This is carried forward as an open input to
the cluster-mode assessment.**

### 4.2 JWT verification and algorithm pinning (P04) — accepted

> **Algorithm pinning itself is sound.** There is no `alg:none`, no HMAC/asymmetric confusion, and
> no attacker-influenced `kid` / `jku` / `x5u` anywhere on the Hearth-token verify path.

The defects are elsewhere: a path that skips validation entirely, a default that fails closed in the
wrong direction, and an unauthenticated endpoint that trusts an unverified token hint.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | The gRPC `Decide` RPC skips `validate_token`, so a refresh token — and a DPoP-bound token replayed as a plain bearer — authorizes | Access Controls | HIGH | Low |
| 2 | Omitting the `security:` YAML block sets `jwks_rps_limit` to 0, so every JWKS and discovery request 429s in production | Configuration | HIGH | Low |
| 3 | Unauthenticated `GET /end_session` acts on an unverified `id_token_hint`: it revokes any user's SSO session and mints a logout token with an attacker-chosen `sub` | Authentication | HIGH | Low |
| 4 | The JWKS publishes RS256 and ES256 keys Hearth never signs with, and four SDKs accept those algorithms | Cryptography | MEDIUM | High |
| 5 | DPoP: `alg` selects the verifier but `kty` selects the thumbprint, and the two are never cross-checked | Cryptography | LOW | High |
| 6 | Documented verification behaviour the code does not implement (`nbf`, the SDK "federation exception", JWKS key roles) | Data Validation | CLAIM-DEFECT | — |

Finding 2 deserves an operator's attention out of proportion to its severity label: an operator who
writes a minimal config with no `security:` block gets a server whose discovery and JWKS endpoints
return `429` to every relying party. Confirmed by A/B config diff on a live instance.

**Critic's residual objection:** Finding 1 is rated HIGH, but the part reproduced over the wire has
the attacker authorizing as themselves with the same `sub` / `sid` / permissions — a token-species
violation, not a privilege gain. The genuinely escalating variants (DPoP `cnf` bypass of a stolen
bound token; the pre-completion RA token) remain source-derived only. The HIGH label is not fully
earned by the evidence actually reproduced.

### 4.3 OAuth redirect handling, PKCE, and authorization codes (P09) — accepted

One structural defect produces the top three findings: **URL-bearing client fields are validated at
registration and never at update.**

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `frontchannel_logout_uri` renders into `<iframe src>` on the IdP origin — a `javascript:` scheme executes script on the identity-provider origin | Data Validation | HIGH | Low |
| 2 | `backchannel_logout_uri` is stored unvalidated and dereferenced server-side — a realm-admin SSRF sink reaching internal and metadata addresses | Data Validation | HIGH | Low |
| 3 | `update_client` never re-validates redirect URIs — the register-time scheme/fragment/wildcard/loopback allowlist is bypassable by register-then-PATCH | Data Validation | MEDIUM | Low |
| 4 | Per-code and per-token advisory-lock maps grow without bound | Denial of Service | LOW | Medium |
| 5 | Browser JAR authorize path redirects to the unvalidated outer `redirect_uri` (embedded-only; dead code on every network-facing shape) | Data Validation | Informational | High |

Three live reproductions were captured, including an access token whose `sub` equals the victim's
user id, and a server-signed logout token arriving at an attacker-controlled socket.

**Critic's residual objection:** the HIGH severity on findings 1 and 2 rests on an asserted threat
model — "multi-tenant SaaS where realm admin is an untrusted tenant" — that is not grounded in the
product's documentation. An operator running single-tenant with trusted admins cannot tell from this
section whether these are HIGH escalations or LOW hardening for their shape.

### 4.4 Reachable panics and request-level DoS (P25) — accepted

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | Audit-log pill truncation slices UTF-8 at a byte offset → whole-process crash under `panic=abort` | Denial of Service | HIGH | Low |
| 2 | `mask_phone` byte-slices an unvalidated phone number → same crash class, reachable from any required-action session | Denial of Service | MEDIUM | Medium |
| 3 | `operational.request_timeout_secs`, `max_connections` and `queue_depth` are documented but never enforced — no request timeout, no connection cap | Denial of Service | MEDIUM | Low |

Finding 1 was reproduced byte-for-byte: a panic at `realms.rs:787:34` followed by the whole process
aborting, with `/health` moving from `200` to connection-refused. Finding 3 was demonstrated with a
38-second socket transcript against a configured 5-second timeout.

**Critic's residual objection:** the BLOCKER-class variant of finding 1 — an attacker-controlled
multi-byte upstream `sub` or SAML `name_id` reaching the same crashing sink, which would convert a
tenant-admin stored DoS into a near-unauthenticated remote process kill — was left in *Unconfirmed*.
Only the low-privilege SCIM injector was proven live, so **the severity ceiling on this finding is
unanswered.**

### 4.5 Route inventory and what actually guards each route (P01) — accepted

Four of the five findings are **one bug class with one root cause**: the web router is merged as a
sibling of the API router and inherits none of the API router's guard layers. Every guard the API
surface has — the `Host` allowlist, the per-IP rate cap, the JSON parse-bomb depth limit, the
request-duration metric — stops at the boundary between the two routers.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | Web UI, admin-login and OAuth-consent routes escape the `Host` allowlist (the DNS-rebinding defence) | Access Controls | MEDIUM | Medium |
| 2 | The entire HTML surface — login, register, reset, consent, all admin CRUD — has no global per-IP request-rate cap | Denial of Service | MEDIUM | Low |
| 3 | `hearth_http_request_duration_seconds` excludes every `/ui/*` route: the admin UI is invisible to Prometheus | Logging | LOW | Low |
| 4 | The JSON parse-bomb depth guard does not run on web-UI JSON endpoints | Denial of Service | LOW | Medium |
| 5 | The README documents `PUT` for five admin mutation routes; the server implements `PATCH` and returns 405 on `PUT` | Configuration | CLAIM-DEFECT | Low |

Every surviving claim was re-executed independently by the critic and produced matching output: the
400-vs-200 host-allowlist split, a `{200: 100, 429: 250}` rate-limit distribution on the API surface
against `{200: 350}` on the UI surface, an empty `/metrics` scrape for `/ui/*`, a 400-vs-422 split on
the depth bomb, and five `405`s on the documented `PUT` routes. The fix names an exact line to change.

Sound by evidence: the dev-only affordances, the reserved-realm cluster gate, and the feature-gated
agent surface.

**Critic's residual objection:** the section declares the `/ui/*` security-header set sound without
noticing that **HSTS is silently disabled in the modal deployment shape** — a reverse proxy
terminating TLS. The one sentence in the piece that tells an operator to stop worrying is wrong for
the deployment most operators will run. Carried forward to the web-UI piece.

### 4.6 Federation, SCIM, LDAP and webhooks (P24) — accepted

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | A deeply-nested SCIM filter overflows the stack and aborts the entire multi-tenant process | Denial of Service | HIGH | Low |
| 2 | Federation JWKS, token and userinfo fetches bypass the SSRF guard, follow redirects, and have no timeout | Data Validation | MEDIUM | Medium |
| 3 | OIDC back-channel logout POSTs to a client-registered URL with no SSRF guard, redirect limit, or timeout | Data Validation | MEDIUM | Medium |
| 4 | `link_existing_accounts: auto` account-takeover risk is not disclosed where the operator sets it | Configuration | MEDIUM | Medium |
| 5 | The webhook signature has no timestamp or replay window; deliveries spawn with no global concurrency bound | Denial of Service | LOW | Medium |

Finding 1 was reproduced independently on both `/Users` and `/Groups` from a single ~6 KB
authenticated request, and the authentication precondition was proven in the negative — an
unauthenticated deep filter returns `401` and the server survives. That precondition is why the
finding is rated HIGH and not BLOCKER, and the reasoning is stated rather than assumed.

**Critic's residual objection:** findings 2 and 3 assert the SSRF payoff — a redirect actually chased
to an internal address such as `169.254.169.254` — from `ureq`'s documented `max_redirects: 10`
default, and never stand up a 302-redirect test server to demonstrate the follow end to end. That
demonstration would have been cheap, and its absence is the weakest link in the section.

### 4.7 Dev-only affordances in a production release build (P03) — accepted

The production claim itself holds, and that is stated first: **with `dev_mode` unset, every dev route
returns 404 on a running release binary.** Proven on a live instance, not argued.

The finding is about the boundary, not the routes.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | A single `dev_mode: true` config-file line — not the `--dev` flag — arms the whole dev perimeter *and* bypasses every production fail-closed gate on a release binary, with no fail-closed refusal | Configuration | HIGH | reach Medium / exploit Low |
| 2 | Dev and test endpoints, and hardcoded dev credentials, are compiled into the release binary and gated only by a runtime boolean rather than a compile-time `cfg`; the embedded/library path has no loopback guard at all | Access Controls | LOW | High |
| 3 | Two source comments assert `dev_mode` is `#[serde(skip)]`; the attribute is `#[serde(default)]`, so a maintainer reading them holds the exact false belief that hides Finding 1 | Configuration | LOW (claim-defect) | Undetermined |

Finding 1 matters because the separation between "production" and "dev" is one operator-settable YAML
key with no fail-closed cross-check. The single hard guard it does carry — a loopback bind — does not
cover the modal reverse-proxy deployment. That gap is demonstrated on a running server, not inferred.

Finding 3 is the kind of defect that keeps Finding 1 alive: the code says one thing, the comment above
it says the opposite, and the comment is the reassuring one.

This section survived a critic that resolved **105 of 106 citations exactly as described** and failed
the previous round over the single mis-anchored one.

### 4.8 Supply chain, build, and release integrity (P27) — accepted

Seventeen findings, including the audit's **second BLOCKER**. This piece took four rounds to pass.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | The container image, the Helm chart, seven SDK Release objects, and two public-registry SDK packages ship from a commit whose own suite failed four tests, two of them data-durability tests; only the binary channel is gated | Configuration | **BLOCKER** | Undetermined |
| 2 | cosign signatures and SLSA provenance are minted for a build that fails validation, and both documented verification commands pass on it | Configuration | HIGH | Low |
| 3 | No CI check blocked the audited commit's merge: one required context, zero reviews, an always-on bypass, and a merge 41 minutes before that context reported failure | Configuration | HIGH | Low |
| 4 | The Helm chart renders an image tag the image workflow never publishes | Configuration | MEDIUM | Undetermined |
| 5 | The README's Docker and Helm install paths are not anonymously reachable | Configuration | MEDIUM | Undetermined |
| 6 | The release-validation summary reports "suite did not complete" for a suite that completed with four named failures | Error Reporting | MEDIUM | Undetermined |
| 7 | The `cargo-deny` context is not required, and the `ci.yml` one is skipped on every PR that does not touch the lockfile, so a week-old advisory failure never blocked a merge; `cargo audit` is disarmed; **the unpatched `h2` is reachable pre-auth on the plaintext listener with no rapid-reset cap** | Configuration | MEDIUM | Low |
| 8 | Generated SDK types can drift from `proto/` past the PR gate; the freshness check runs only where the paths filter does not reach | Configuration | MEDIUM | Low |
| 9 | A third crypto backend and a policy-banned HTTP client are linked into the published binary; `deny.toml` encodes neither ban | Cryptography | MEDIUM | Undetermined |
| 10 | The attribution freshness key is a whole-file hash of `Cargo.lock` that includes the workspace's own version, so the release procedure trips a legal-attribution gate with nothing to attribute | Configuration | LOW | Undetermined |
| 11 | The version an operator sees is wrong in five of seven surfaces; the container image and both published SBOMs misreport it | Configuration | MEDIUM | Undetermined |
| 12 | The release-verification guide contains two commands that fail, and the README's headline install step verifies nothing an attacker could not forge | Data Validation | MEDIUM | Undetermined |
| 13 | A third-party reusable workflow holding `contents: write` + `id-token: write` is referenced by mutable tag, with an incorrect justification | Configuration | MEDIUM | High |
| 14 | The systemd crash-loop limiter is silently ignored | Configuration | LOW | Undetermined |
| 15 | The Dockerfile carries three false statements about the build it defines | Configuration | Informational | Undetermined |
| 16 | Scanner configuration overstates coverage: fifteen dead schedule conditions, advisory-only scanners, an unscanned image, and two suppressions for packages absent from the tree they name | Configuration | Informational | Undetermined |
| 17 | The shipped Docker Compose file sources the repository-root `.env` into the container's runtime environment | Data Exposure | LOW | Low |

Three of these compound into one story an operator needs stated plainly:

> The suite fails four tests. No CI context blocked the merge — the commit merged **41 minutes before**
> its one required context reported failure. The release pipeline then signed that commit with cosign,
> minted SLSA provenance for it, and published it as a container image, a Helm chart, seven SDK
> releases and two registry packages. An operator who runs the documented verification commands against
> those artefacts gets a **pass**.
>
> The attestation is working correctly and proving the wrong thing. It attests that the artefact came
> from that commit. It does not, and was never going to, attest that the commit was any good.

Finding 7 also settles a question left open in section 2.2: **the unpatched `h2` is reachable pre-auth
on the plaintext listener**, with no rapid-reset cap. RUSTSEC-2026-0258 is therefore a remotely
reachable, unauthenticated denial of service on the modal deployment, not a dormant transitive.

Finding 11 settles the version question from section 2.4: the mismatch is not cosmetic drift in one
place. The version is wrong in **five of seven** operator-visible surfaces, including the container
image and both published SBOMs.

### 4.9 Storage-layer realm isolation (P12) — accepted

The piece was set the task of **falsifying** the claim that every storage key is realm-prefixed and
every scan realm-bounded. It did not falsify the prefixing. It found something worse in the realm
*lifecycle*: deletion does not delete, and the documented restore path destroys tenants.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `delete_realm` sweeps hand-written prefix allowlists, not the realm's key space; `cred:history:` (Argon2id hashes) and six `audit:*` families survive **both** branches, `rba:*` survives one, and shipped read paths serve the survivors to the same realm ID's next occupant | Data Exposure | HIGH | Low — one documented restore request from a realm admin |
| 2 | `mode=overwrite` restore deletes the target realm and then fails to restore it | Data Validation | **BLOCKER** | N/A — no attacker; an operator running a documented command |
| 3 | Snapshot **build** enumerates realms from `known_realms`, snapshot **install** from `list_realms()` — a realm the leader has forgotten is deleted from every follower | Data Validation | MEDIUM | Medium |
| 4 | The backup consistency barrier is inert on the only storage handle `serve` installs; `ClusterStorageAdapter` also inherits the non-atomic `write_batch` default | Configuration | MEDIUM | Undetermined |
| 5 | "Encrypted at rest with per-realm keys" is asserted in three normative documents; **one KEK covers every realm** | Cryptography | CLAIM-DEFECT | N/A |
| 6 | Hot-tier eviction and promotion counters carry no realm label; `TieredConfig` has no per-realm dimension | Logging | Informational | N/A |
| 7 | A reversed scan window (`start > end`) panics inside `range_scan_inner` on both legacy SST bodies; one `GET /admin/audit` killed the process with **SIGABRT in 6 of 6 runs** | Denial of Service | HIGH | Low — one HTTP request from an authenticated realm admin |
| 8 | The whole `hearth backup` CLI family reports through `tracing` with no subscriber installed: `create`, `restore`, `verify` and `inspect` emit **zero bytes** — including when `create` fails because the server still holds the data-directory lock | Error Reporting | MEDIUM | N/A |

**Finding 2 is the audit's third BLOCKER, and it needs no attacker.** Over HTTP, an `overwrite`
restore destroys the target realm and locks its admin out. On the documented CLI path the auditor ran
it **1,160 times**:

> None completed. All 1,160 runs printed nothing. **975 left the tenant realm destroyed**, silently
> truncated to an arbitrary subset of its users, or in a state that `hearth backup create` cannot
> export. One of those runs reported exit code **0**.

Finding 8 explains why an operator would not notice: the entire `backup` CLI family writes through
`tracing` with no subscriber installed, so `create`, `restore`, `verify` and `inspect` emit zero
bytes. A destructive restore that half-executes, prints nothing, and can exit 0 is the worst
combination of properties available.

**Finding 1 is the orphan-resurrection class.** Realm deletion enumerates a hand-written allowlist of
key prefixes instead of sweeping the realm's key space. Argon2id credential hashes and six audit
families survive it, and shipped read paths hand them to whoever next holds that realm ID — in
practice the same operator after a restore.

**Finding 5 is a documentation defect with real security weight.** Three normative documents state
that data is encrypted at rest with per-realm keys. One KEK covers every realm. An operator reading
those documents will size their key-compromise blast radius wrongly.

Fixes are given as concrete changes with file:line, split short and long term — including replacing
all three hand-written prefix lists in `delete_realm` with the key-space sweep **the cluster path
already uses**.

### 4.10 SAML: signature wrapping, XXE, unsigned assertions (P23) — accepted

Cleared its critic with **159 distinct `file:line` citations, zero unresolved, and 23 repros, zero
failed** — every transcript reproduced line for line from an independently built target directory.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | **XML Signature Wrapping**: `verify_signed_element` authenticates one `<saml:Assertion>` and `parse_response` consumes a different one | Authentication | **BLOCKER** (shape 4) / **HIGH** (shapes 1–3) | Medium |
| 2 | `/ui/realms/{realm}/saml/slo-idp` is an **unauthenticated realm-key signing oracle** | Authentication | HIGH | Low |
| 3 | An attacker-controlled SAML `<NameID>` reaches a byte-slicing panic in the admin audit viewer → process abort | Denial of Service | HIGH | Low |
| 4 | `want_authn_requests_signed` and `sp_certificate_pem` are dead controls — a documented SAML security flag is a silent no-op | Configuration | HIGH | Low |
| 5 | The signed `<SubjectConfirmationData>` bindings (Recipient, bearer `NotOnOrAfter`, `InResponseTo`) are never parsed | Data Validation | MEDIUM | Medium |
| 6 | SP-initiated SAML SSO validates the assertion and then authenticates nobody — a shipped-labelled federation login that is an unfinished stub | Authentication | MEDIUM (CLAIM-DEFECT) | Low |
| 7 | Audience and Destination validation is anchored to `X-Forwarded-Host` under the example config | Configuration | MEDIUM | Medium |
| 8 | `security.allowed_hosts`, the global rate limiter and `DefaultBodyLimit` are not applied to the `/ui` route tree — **including the SAML ACS and `begin`** | Access Controls | MEDIUM | Low |
| 9 | Two SAML key spaces grow without bound; one is written by an unauthenticated, unrate-limited GET | Denial of Service | MEDIUM | Low |
| 10 | `SAML.md`, the `verify_signed_element` doc comment and the `trusted_base_url` doc comment claim protections the code does not implement | Authentication | CLAIM-DEFECT | Undetermined |

Finding 1 was reproduced by both the auditor and, independently, the critic:

```
STEP 3  XSW -> ACCEPTED  consumed assertion.id=_evil1
        identity.email=ceo@corp.example      (IdP signed mallory@corp.example)
```

The signature is verified over one element; a different element is consumed. An attacker holding any
legitimate account at the upstream IdP authenticates as any other user. Note the severity is split by
deployment shape rather than flattened — BLOCKER in embedded use, HIGH elsewhere — which is the
distinction the brief asked for and which a single label would have destroyed.

Finding 4 is the one an operator is most likely to be hurt by without knowing: `want_authn_requests_signed`
is a documented security flag that does nothing. An operator who sets it believes they have a control
they do not have.

Finding 8 independently corroborates the route-inventory root cause in section 4.5 — the `/ui` tree
escapes the API router's guards — and shows the SAML assertion consumer sits on that unguarded tree.

### 4.11 WAL durability and crash recovery (P18) — accepted

Cleared its critic with zero unresolved citations and zero failed repros. Thirteen findings across
3,252 lines. **This piece breaks the project's headline durability claim.**

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | **WAL rotation destroys already-acknowledged writes whenever two or more writers are concurrent, and nothing flushes the memtable on the shutdown path; a clean `SIGTERM` is sufficient** | Data Validation | **BLOCKER** | Low |
| 2 | Partial compaction renames its output over the tombstone-bearing SST, so a crash before the unlink resurrects any key deleted more than one WAL generation ago | Data Validation | HIGH | High |
| 3 | A single mid-segment CRC mismatch makes `open()` return `Ok` **after physically destroying** every acknowledged record that followed it | Data Validation | HIGH | High |
| 4 | A torn SST body write leaves a short file at the live `NNNNNN.sst` name; the next startup refuses to open the data directory | Data Validation | HIGH | Medium |
| 5 | One failed WAL write on the `SyncMode::None` path burns a record number and makes the whole segment permanently unopenable | Data Validation | MEDIUM | Medium |
| 6 | A write fault during WAL rotation leaves a 1–81-byte header the engine refuses to open, with no documented repair | Error Reporting | MEDIUM | Medium |
| 7 | A one-byte corruption of the WAL magic makes a *failed* open rewrite the segment in place | Data Validation | MEDIUM | High |
| 8 | The WAL write fence is permanent, unlogged, unmetered and invisible to `/readyz` | Logging | MEDIUM | High |
| 13 | Every CLI subcommand that opens a production data directory opens it with the **development** storage config — `SyncMode::None` and `dev_mode: true` — so `hearth backup restore` and both migration importers acknowledge success without a single WAL `fsync` | Configuration | MEDIUM | Undetermined |
| 9 | The TLS-terminating server does not drain in-flight requests on SIGTERM — it drops the accept loop and returns, and the process still exits 0 | Denial of Service | MEDIUM | Undetermined |
| 10 | `sigterm_does_not_abort_inflight_http_request` is red because **the harness starves its own request task**, not because the plaintext drain is broken — and the two real SIGTERM defects it appears to cover are untested | Data Validation | MEDIUM | Undetermined |
| 11 | **No test in the repository can distinguish `fsync`-before-ack from no `fsync` at all**; the WAL's own doc comment names a crash loop that does not exist | Data Validation | CLAIM-DEFECT | Undetermined |
| 12 | `storage.fsync` is documented as a working knob and is ignored in both production and dev mode | Configuration | LOW | Undetermined |

**Finding 1 is the audit's fourth BLOCKER.** `CLAUDE.md` states the WAL must be `fsync`'d before
acknowledging any write and must survive `kill -9`. Under concurrent writers, WAL rotation destroys
records that were already acknowledged, and nothing flushes the memtable on shutdown. A **clean
`SIGTERM`** is enough — no crash, no attacker, no disk fault.

**Finding 11 is why this was not caught.** No test in the repository can tell `fsync`-before-ack from
no `fsync` at all. The durability property has been asserted, documented, and never tested in a way
that could fail.

**Finding 10 answers the question section 2.1 left open.** The red `sigterm_...` test is red because
its own harness starves the request task — the guard rotted. And separately, the two genuine SIGTERM
defects that test appears to cover have no coverage at all. Both halves are reportable, and only the
second is a data-loss bug.

**Finding 2 settles the other red test.** The compaction-resurrection class is **not** closed: partial
compaction still renames its output over the tombstone-bearing SST, so a crash before the unlink
resurrects any key deleted more than one WAL generation ago. In an identity store that is a deleted
user, a revoked credential, or a removed role assignment returning.

**Finding 13 compounds blocker B3 in section 4.9.** Every CLI subcommand that opens a production data
directory opens it with the *development* storage config. `hearth backup restore` and both migration
importers report success without a single `fsync`.

### 4.12 Independent re-derivation of the build baseline (P00) — accepted

Twenty findings. The critic re-executed **72 of this section's commands** and got the same bytes,
down to a hex dump of an HTTP/2 SETTINGS frame and a line number in a CI log.

Two are BLOCKERs, and both sharpen findings already in this report.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | The v1.6.11 container image and Helm chart were published **37 minutes before** the project's own release-validation job wrote "Release is NOT cleared to publish" | Configuration | **BLOCKER** | Low |
| 2 | A crash between partial-compaction rename and unlink resurrects deleted data; **the regression test proving it was committed red** and fails on the project's own runners | Data Validation | **BLOCKER** | Medium |
| 3 | Both dependency-advisory gates are `continue-on-error` with no re-raise; the observed result is a `success` job on a **70-vulnerability scan**, one of them the unpatched HTTP/2 DoS advisory that v1.6.11 ships | Denial of Service | HIGH | Low |
| 4 | The container image and Helm chart the README tells operators to install are not anonymously readable; two of the three documented install paths fail at the first command | Configuration | HIGH | Low |
| 5 | `hearth --version` silently falls back to a stale `Cargo.toml` when `.git` is absent — **precisely the container build's condition** — while the released binary of the same release reports correctly | Configuration | HIGH | Low |
| 6 | The Helm chart's default image tag is a tag the Docker workflow never publishes, so a default `helm install` cannot pull an image | Configuration | MEDIUM | Low |
| 7 | Every published container image is labelled `AGPL-3.0-only`; the project relicensed to Apache-2.0 three months ago | Configuration | MEDIUM | Low |
| 8 | The first-run setup token is written to the production log at WARN on every boot, while the banner two lines later says it is redacted | Data Exposure | MEDIUM | Low |
| 9 | `validation-summary.txt` reports a completed 4-failure suite as "suite did not complete" because its parser cannot read the ANSI-coloured nextest output a pinned third-party action causes | Error Reporting | MEDIUM | Low |
| 10 | The only test guarding the pre-restore audit event has been red since the commit that changed the behaviour it guards | Logging | MEDIUM | Medium |
| 11 | The SIGTERM in-flight-drain regression test loses its own race in every observed run; its sibling passes vacuously | Error Reporting | MEDIUM | Low |
| 12 | Three of `ci.yml`'s SDK jobs, and every job in five other workflows, cannot fail the only required check | Configuration | MEDIUM | Low |
| 13 | `make sdk-smoke-local` fails on any checkout that has the documented `hearth.yaml`, because it boots `--dev` from the repo root with no `--config` | Configuration | MEDIUM | Low |
| 20 | The HTTP/2 rapid-reset caps are applied only on the TLS listener, and the `security.http2.*` keys that configure them are parsed, validated and never read | Denial of Service | MEDIUM | Medium |
| 14 | CHANGELOG says a release whose test suite fails "is never published"; the container, chart and four SDK packages were published | Configuration | CLAIM-DEFECT | Low |
| 15 | One advisory suppression is dead and one describes a component that does not contain the crate it suppresses | Configuration | LOW | N/A |
| 16 | README prerequisites omit `protoc`, and the end-to-end walkthrough documents a client secret and four JWT claims the server does not return | Configuration | LOW | Low |
| 17 | **`make check` cannot pass at HEAD; clippy aborts first, so CI has never executed `cargo fmt --check` or the test suite on this commit** | Configuration | Informational | Low |
| 18 | `[profile.ci]` is dead configuration; every run is fail-fast, so a red suite under-reports by a third and a real flake cannot be retried | Configuration | Informational | Low |
| 19 | The UI smoke suite's own setup step invalidates the URL its next step depends on; the test deletes itself and the run exits 0 | Error Reporting | Informational | Low |

Finding 17 deserves to be read next to its Informational label. It is not a severity claim — it is the
mechanism behind several others. Because clippy aborts first, **CI has never run `cargo fmt --check`
or the test suite on this commit at all.** Finding 3 completes the picture: the advisory gates are
`continue-on-error`, so a scan reporting 70 vulnerabilities produced a green job.

Finding 5 explains section 2.4's version puzzle at the mechanism level: `hearth --version` falls back
to a stale `Cargo.toml` when `.git` is absent, which is exactly the container build's condition.

Finding 7 is not a security defect and is worth an operator's attention anyway: every published
container image carries an `AGPL-3.0-only` label for a project that relicensed to Apache-2.0 three
months ago. That is a redistribution question, not a vulnerability.

### 4.13 Config defaults and fail-open behaviour (P02) — accepted

Twelve findings. This section is also the audit's best example of **calibration discipline**: it
states outright that no finding in it is a BLOCKER, and each HIGH carries a note explaining why both
the tier above and the tier below are wrong.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | Omitting the `security:` block sets `jwks_rps_limit` to `0`, and every JWKS and discovery request answers `429` from the first request, with nothing in the boot log | Denial of Service | HIGH | Low |
| 3 | Misspelled claim release gates are silently discarded and the claim is emitted to third-party clients; the documented Tier-3 `first_party_only: true` default is not implemented | Data Exposure | HIGH | Low |
| 4 | A `${VAR}` reference to an unset environment variable becomes the empty string, and **the empty string is then accepted as a credential** — `/metrics` opens with its warning suppressed, and a confidential OAuth client authenticates with `Basic <client_id>:` | Authentication | MEDIUM | Low |
| 5 | `security.backup.verify_key` is parsed, validated and documented as fail-closed, but is **never wired into the restore handler** — the signature check can never fire | Access Controls | MEDIUM | Low |
| 2 | The same absent block sets `reserved_slugs: []` and `slug_cooldown_days: 0`, silently disabling an abuse control | Access Controls | MEDIUM | Low |
| 6 | `PATCH /ui/admin/realms/{realm}/config` accepts misspelled keys with HTTP 200 and clears the realm's `default_required_actions` on every request that omits it | Data Validation | MEDIUM | Low |
| 7 | **`0` means "unlimited" for three rate limiters and "deny everything" for a fourth, in the same file** | Denial of Service | MEDIUM | Low |
| 8 | `hearth config validate` prints "✓ Configuration valid" for configs the server refuses to start with; the admin UI writes `hearth.yaml` behind that weaker validator | Error Reporting | MEDIUM | Low |
| 9 | Nine config snippets copied from the reference and the shipped example fail to parse, and three in-source comments assert per-realm YAML support that does not exist | Configuration | MEDIUM | Low |
| 10 | `dev_mode: true` in YAML turns off all four production fail-closed gates and is documented nowhere an operator reads; two in-source comments say it cannot | Configuration | MEDIUM | Medium |
| 11 | The first-run setup token is written to the log in full in production mode, while the startup panel deliberately redacts it | Data Exposure | MEDIUM | Low |
| 12 | The mandatory production key material is absent from the canonical config reference, published defaults contradict the reference's own tables, and a documented CLI flag does not exist | Configuration | CLAIM-DEFECT | — |

Finding 7 is the zero-valued-default class stated in one line: the same sentinel means *unlimited* for
three limiters and *deny everything* for a fourth, **in the same file**. Finding 1 is what that costs
when an operator omits a block.

Finding 5 is a dead security control, the same shape as SAML's `want_authn_requests_signed`: an
operator configures `verify_key`, the value is parsed and validated so nothing complains, and the
check it enables can never run.

### 4.14 Secret hygiene in logs, and the audit hash chain (P26) — accepted

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | First-run **setup token** is written to the log at WARN **at the default level in production**, granting first-admin takeover | Data Exposure | **BLOCKER** (escalated — see below) | Low |
| 2 | Onboarding invitation writes a live realm-admin password-reset URL to the log at WARN | Data Exposure | HIGH | Low |
| 3 | `observability.log_level: trace` dumps every outbound request head, including provider API keys, in cleartext | Data Exposure | MEDIUM | Medium |
| 4 | `verify_integrity` reports a truncated or fully erased audit log as **valid** when the chain-head record is deleted too | Logging | MEDIUM | Medium |
| 5 | Restore does not verify an imported audit event's integrity hash; it discards and re-signs it | Logging | MEDIUM | Medium |
| 6 | Every `hearth backup …` subcommand fails silently — no tracing subscriber is installed for it | Error Reporting | MEDIUM | Low |
| 7 | Failed second-factor verification is not audited; failed logins for unknown users are not audited at all | Logging | MEDIUM | Low |
| 8 | 38 protocol-layer audit writes discard their failure with no log line, bypassing `AuditFailurePolicy` | Logging | LOW | High |
| 9 | Config-driven signing-key rotation emits no audit event; the HTTP path for the same operation does | Logging | LOW | High |
| 10 | The repository's two "tamper the middle audit record" tests write to a key format the engine abandoned | Logging | LOW | Undetermined |

**On the escalation of finding 1.** The auditor rated this HIGH. The critic passed the section and
then argued the rating was *too low*:

> Finding 1 is rated HIGH but its own headline — highest-privilege bootstrap credential exposed at the
> default log level with no loud failure, demonstrated first-admin takeover — meets the brief rubric's
> BLOCKER triggers verbatim, so it must escalate to BLOCKER or justify the down-rate, or an operator
> scanning the blocker list walks past the report's worst finding.

The critic had independently reproduced the full chain: leaked setup token → create admin → activate
via leaked verification token → authenticated `hearth_ui_session`. The brief lists
"credential/secret exposure" as a BLOCKER trigger without qualification. **I have accepted the
escalation.** It is recorded here rather than silently applied, because a severity changed after the
fact should be visible.

Three separate pieces found this same defect independently and rated it differently — HIGH here,
MEDIUM as P02 finding 11, MEDIUM as P00 finding 8. That disagreement is itself worth stating: the
same log line looks like hygiene from the configuration angle and like account takeover from the
credential angle.

Findings 4 and 10 together answer the audit-chain question. `verify_integrity` reports a **fully
erased** audit log as valid when the chain-head record is deleted along with the rest, and the two
repository tests that would have caught this write to a key format the engine no longer uses. The
chain detects tampering in the middle. It does not detect erasure of the whole thing.

### 4.15 Signing-key rotation, JWKS, and key-at-rest (P06) — accepted

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | **Rotating a leaked signing key does not revoke it**: the retired key mints new admin tokens for the full 24 h grace window, and neither documented mitigation stops it | Cryptography | **BLOCKER** | Medium |
| 2 | `token.signing_key_rotation_grace_period` is never validated: a malformed value silently becomes 24 h, a negative value becomes effectively infinite | Configuration | HIGH | High |
| 3 | The fixed grace window is unrelated to token lifetime: a rotation kills every outstanding refresh token 6 days before its own `exp` | Cryptography | MEDIUM | Low |
| 4 | The server-wide OIDC RSA-2048 private key is written to storage **unencrypted** while every other key is KEK-wrapped, contradicting the CHANGELOG | Data Exposure | MEDIUM | High |
| 5 | JWKS publishes RS256 and ES256 signing keys Hearth never signs with; the ES256 private key is discarded on every restart under a 1-hour cache directive | Cryptography | MEDIUM | Medium |
| 6 | Signing-key caches are process-local and rotation has no cross-node invalidation: a second node keeps publishing and trusting the pre-rotation key | Configuration | MEDIUM | Medium |
| 7 | A KEK-configured deployment still accepts an unenveloped signing key, and enabling the KEK never re-encrypts what is already stored | Cryptography | MEDIUM | High |
| 8 | Operator documentation for rotation: a phantom CLI command, a wrong default, a dead source citation, and an undocumented config key | Configuration | CLAIM-DEFECT | Low |

Finding 1 is the blocker every incident-response plan depends on. Rotation is the documented remedy
for a leaked signing key, and it does not revoke the leaked key — it keeps minting **new administrative
credentials** for 24 hours.

**The critic did the auditor's remaining work rather than only naming it.** It objected that the proof
stopped at the engine boundary and never crossed to the admin HTTP surface — then wrote the missing
40-line test itself. Result: an honest non-admin token gets `403`, while the forged post-rotation
sessionless token gets **`200` on `GET /admin/users`, `/admin/realms`, `/admin/audit`, and `201` on
`POST /admin/users`.** The blocker is stronger after review than before it.

### 4.16 Refresh-token rotation and theft detection (P07) — accepted

Fourteen findings, from 15 pinned runs driven through the real HTTP router on a multi-threaded
runtime, with a negative control proving the harness fails loudly rather than silently reporting zero.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | Rotation is an unsynchronised read-modify-write: two concurrent presentations of one refresh token both succeed, and whichever party holds the loser is signed out with the eviction logged against the user | Timing | HIGH | n/a — no attacker required |
| 3 | Deleting an OAuth client strips the confidential-client authentication and FAPI DPoP gates from its outstanding refresh tokens, which are not revoked | Access Controls | HIGH | Low |
| 4 | **Refresh copies the presented token's RBAC claims and scope verbatim: a revoked role is re-minted on every refresh, indefinitely** | Access Controls | HIGH | Low |
| 5 | In cluster mode the revoked-JTI projection is node-local: a sessionless token revoked on one node stays valid on every other node until that node restarts | Access Controls | HIGH (shape 3 only) | Low |
| 2 | A holder of a stolen refresh token can land a concurrent redemption inside the rotation window and obtain a live chain with no theft event at that moment | Timing | MEDIUM | High |
| 6 | Every grant except `authorization_code` mints a refresh token with no grant family: it never rotates, replays forever, and theft detection can never fire | Access Controls | MEDIUM | Low |
| 7 | An RFC 7009 revocation racing a rotation is a lost update: `POST /revoke` returns 200 and the grant survives | Timing | MEDIUM | High |
| 8 | `POST /token` with `grant_type=refresh_token` and no `client_id` is never seen by the token-endpoint rate limiter | Denial of Service | MEDIUM | Low |
| 9 | `POST /revoke` writes the full bearer token into the persistent audit log as the event's `resource_id` | Data Exposure | MEDIUM | Low |
| 10 | A failing session write makes `update_user(status = Disabled)` report a success it never achieved, and the user's refresh token keeps working | Error Reporting | MEDIUM | High |
| 11 | Revoking consent for an application does not stop that application refreshing | Access Controls | MEDIUM | Low |
| 12 | The eleven `/realms/{name}/*` routes ignore `X-Realm-ID`, defeating the subdomain-to-header tenant routing the deployment guide prescribes | Access Controls | LOW | Low |
| 13 | The `oauth:session_fam:` index and the `oauth:revjti:` blocklist have no reclamation path | Denial of Service | LOW | Low |
| 14 | Six published documents and four in-tree comments state properties of refresh rotation that the code does not have | Configuration | CLAIM-DEFECT | Low |

Finding 4 answers the question the brief asked about the `embedded` permission mode, and the answer is
worse than a staleness window: a revoked role is **re-minted on every refresh, indefinitely**. There is
no window; there is a loop.

**Critic's residual objection, recorded because it rules against us on a dimension:** ToB is better
than this section on severity discipline — it rates a never-expiring credential *Low* because it is
opt-in, where this section carries four HIGHs in fourteen — and better on difficulty discipline, since
it uses a fixed four-value scale where this section wrote "n/a" for its flagship finding. The critic
also found that finding 5 is rated HIGH on a deployment shape the README labels "not
production-supported", warns about at every cluster startup, and already documents as a known defect —
and the section never tells the reader that, across 21 references to that shape.

### 4.17 Argon2id, lockout, and the X-Forwarded-For trusted-proxy logic (P15) — accepted

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `X-Forwarded-For` is read with `get()` — **first field line only** — so a client-supplied line shadows the proxy-appended one and the attacker chooses his own client IP | Data Validation | HIGH | Low |
| 2 | Forged per-request client IP × unshaped login form = unbounded pre-auth Argon2id work, with no 429, no 503, and green health checks | Denial of Service | HIGH | Low |
| 3 | `X-Forwarded-For` hops carrying a port suffix or IPv6 brackets fail to parse and collapse every client into the proxy's rate-limit bucket | Data Validation | MEDIUM | Low |
| 4 | The absent-user dummy hash is built from the engine base Argon2 config, not the realm's, so a realm that tunes Argon2 leaks account existence by timing with no lockout involved | Timing | MEDIUM | Low |
| 5 | Per-account lockout short-circuits before hashing, so a locked — therefore existing — account answers ~12 ms faster than a nonexistent one | Timing | MEDIUM | Low |
| 6 | Argon2id memory and time cost are settable arbitrarily below OWASP — from YAML *and* over the wire — with no floor and no start-up warning | Configuration | MEDIUM | Medium |
| 7 | Production forces `trust_forwarded_proto: true` on plaintext while `trusted_proxies` defaults to empty, and the one warning that would tell the operator is written **before the log subscriber exists** | Configuration | MEDIUM | Low |
| 8 | The documented global `auth.password_memory_cost` / `auth.password_time_cost` keys are a silent no-op for the base config, and both documented defaults are wrong | Configuration | CLAIM-DEFECT | Low |
| 9 | Eight abuse-prevention guards documented as "Shipped" are never constructed outside their own test modules, and six of their documented config keys make the server refuse to boot | Configuration | CLAIM-DEFECT | Low |

The user-enumeration timing signal was **measured, not asserted**: a reproducible paired-difference
oracle showing a **+88 ms** signal, and a separate 6.7× login-flood degradation with 503 shedding.

**Critic's residual objection — a real limit on findings 1 and 2:** both HIGHs depend on injecting a
separate `X-Forwarded-For` *field line* through an append-style front end. That was demonstrated with a
raw-socket stand-in plus a reading of HAProxy's documentation, never against a live proxy. Under a
merge-style proxy — the nginx negative control — **both HIGHs degrade to near-nil impact**, and the
summary table still prints HIGH without that qualifier. An operator behind nginx should read these two
findings as substantially lower risk than the label suggests.

### 4.18 MFA: TOTP, WebAuthn, and whether MFA can be skipped (P16) — accepted

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | **A passkey that never proves user verification satisfies `mfa_required`; the UV knob is dead code** | Authentication | **BLOCKER** | Low |
| 2 | Passkey enrolment requires no step-up, so a stolen session becomes a permanent MFA-free credential | Access Controls | HIGH | Low |
| 3 | The `mfa_required` gate checks factor *enrolment*, not factor *use* (federation and ROPC bypass) | Authentication | HIGH | Medium |
| 4 | One TOTP, recovery, SMS-OTP or email-OTP code can be redeemed repeatedly under concurrency | Authentication | HIGH | Low |
| 5 | **Backup silently drops every TOTP secret, passkey and OTP factor, and the record type says it does not** | Data Validation | HIGH | Low |
| 6 | SMS-OTP and email-OTP factors are invisible to the `create_session` gate and the direct browser login | Authentication | MEDIUM | Medium |
| 7 | Forced-enrolment activation has neither the CSRF check, the nonce redemption, nor the rate limit its sibling has | Data Validation | MEDIUM | Medium |
| 8 | The WebAuthn challenge store is process-global; **a challenge minted in realm A is redeemed in realm B**, and `ceremony_type` is never checked | Access Controls | MEDIUM | High |
| 9 | Three documented WebAuthn realm policies cannot be set from any operator surface; one is dead code | Configuration | MEDIUM | Undetermined |
| 10 | `mfa_methods` does not restrict which factors a user may enrol or present | Configuration | CLAIM-DEFECT | Low |

Finding 8 answers the cross-tenant passkey question directly: the challenge store is process-global, so
a challenge minted in one realm is redeemable in another.

Finding 5 compounds the restore blocker in §4.9 — an operator who restores from backup silently loses
every second factor in the realm, and the record type asserts otherwise.

**The critic falsified our own headline, and the correction is load-bearing.** The section claimed
there was *"no operator remedy"* for the blocker. The critic disproved that in one config line: with
`passkey_requires_mfa: true`, the identical probe returns `{"redirect":"/ui/mfa-challenge"}` and issues
no session at all. **There is a remedy, it is one key, and any operator reading this must know it.**
The section's own recommendation implied it while its summary flatly contradicted it.

### 4.19 Claim validation on every token-accepting path (P05) — accepted at round 4

This piece is worth reading twice, because of how it got here. Its first three rounds were rejected —
once because **three of five findings cited tests that do not exist**, and once because a negative
result was false for a twin of the endpoint it described. The critic picked Trail of Bits over it
while saying outright that ToB's section was *thinner and vaguer*. That was the correct ranking: a
thin honest document beats a rich one containing invented evidence.

Round 4 passed on this record: **689 of 689 citations resolve to code matching the description; 53 of
56 code blocks are byte-identical at the cited line with zero offsets; 30 of 30 tests and all four
live-server probes reproduced from a wiped data directory.**

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `initiate_logout_inner` accepts an **unsigned** `id_token_hint`, revokes the named session, and delivers a realm-signed back-channel logout token carrying the attacker's chosen `sub` | Authentication | HIGH | Low |
| 2 | The realm-scoped `/introspect` and `/revoke` routes read **no client credentials at all**, so an anonymous internet caller gets `active:true` with the subject and can destroy the session | Authentication | HIGH | Low |
| 3 | Device-grant, step-up-MFA, ROPC and password-reset tokens are minted with no `fid`, so `refresh_tokens` skips the branch holding client authentication *and* reuse detection | Authentication | HIGH | Low |
| 4 | Neither device-grant endpoint authenticates the client, so a party without the client secret can run the whole RFC 8628 flow under a confidential client's identity | Authentication | HIGH | Medium |
| 5 | The JTI revocation blocklist is consulted only in the `sid == "none"` branch of `introspect` and `decide`, so **a revoked delegation stays `active: true` with live permissions** | Access Controls | HIGH | Medium |
| 6 | Suspending a realm does not stop the two sessionless grants from minting fresh tokens, and neither `introspect` nor `decide` consults realm status — a suspended tenant's M2M plane keeps working | Access Controls | HIGH | Medium |
| 7 | `enroll_phone_otp_send` accepts the required-action cookie without validating it and reads the billing realm out of the unverified payload | Data Validation | HIGH | Low |
| 8 | The DPoP sender-constraint is **not enforced on `/admin/*`, SCIM, or the gRPC admin services**, so a stolen `cnf`-bound admin token is replayable as a plain Bearer for reads *and* writes | Authentication | MEDIUM | Medium |
| 9 | `decide_token_permission` omits the `token_type` check its two siblings enforce, so a refresh token the token endpoint refuses returns a live `allowed: true` | Data Validation | MEDIUM | Medium |
| 10 | `TokenClaims.nbf` documents a MUST that neither hot-path validator implements | Data Validation | CLAIM-DEFECT | Undetermined |
| 11 | Two comments on the signature-verification call describe a "global-key fallback for Phase 0 realms" the function does not implement | Data Validation | CLAIM-DEFECT | Undetermined |
| 12 | The documented follower cache-staleness defect is scoped to "RBAC and session caches", but the same mechanism strands the **DPoP-JKT kill-switch, the delegation JTI blocklist, realm suspension and signing-key rotation** — none of which the known-defects list names | Access Controls | LOW | Medium |

Finding 8 closes an item that §4.2 had to leave UNCONFIRMED: the DPoP sender-constraint bypass is real
on the admin surface, for writes as well as reads.

Finding 12 is the most valuable kind of documentation finding. The project **already documents** a
follower cache-staleness defect and scopes it to RBAC and session caches. The same mechanism also
strands four security controls the known-defects list does not mention — including two kill-switches
and key rotation. An operator who read the known-defects list would size this wrongly.

Findings 5 and 6 together mean that on the machine-to-machine plane, neither revoking a delegation nor
suspending an entire tenant reliably stops token issue or authorization.

### 4.20 Cascading deletion (P14) — accepted

This piece exhausted four rounds in an earlier batch — **winning the blind comparison every time** and
being rejected each round on evidence. Re-run with the critic's exact objection as its brief, it passed
in one round.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 5 | **Realm archival is not a freeze**: 11 of 16 mutating engine operations still write an archived realm, including `delete_user`, `set_password` and `register_client` | Access Controls | HIGH | Low |
| 1 | A consent record outlives all three client-retirement routes, and the deterministic YAML `ClientId` hands it to whatever application next claims the key | Access Controls | HIGH | High |
| 2 | Realm deletion picks one of two divergent cascades **by realm size**; each path skips key families the other deletes | Data Exposure | MEDIUM | Low |
| 3 | A process death between the `204` and the end of the cascade wedges the realm in `DeletingInProgress`, where the admin API refuses to delete it and startup reconciliation aborts | Data Validation | MEDIUM | Medium |
| 4 | Direct permission grants, org extra roles and every group-subject RBAC row survive deletion, and are **silently reactivated when the same `UserId` is re-imported** | Access Controls | MEDIUM | Medium |
| 6 | Password history, webhook secrets, org-owned agent credentials, the per-realm MFA DEK and the DPoP nonce key are swept by neither cascade | Data Exposure | MEDIUM | Low |
| 10 | Delete preconditions live in the protocol adapters, and two of four adapters skip them: gRPC `DeleteRealm` has no archival gate, and REST/gRPC application delete has no YAML-managed gate | Access Controls | MEDIUM | Low |
| 7 | Three rate-limit counters carry the subject's **plaintext email address** in the storage key and outlive both the user and the realm | Data Exposure | LOW | Low |
| 8 | `delete_user` deletes the primary record first and then refuses to retry, so a fault mid-cascade orphans the whole user permanently | Data Validation | LOW | High |
| 9 | Four published statements about cascade completeness and crash recovery are false, and the simulation test meant to catch the difference is blind to it | Configuration | CLAIM-DEFECT | — |

Finding 5 is the one to act on first. **Archival is the control an operator reaches for during an
incident** — freeze the tenant, then investigate. It is not a freeze: password changes, user deletion
and client registration all still land.

Finding 2 is a structural oddity worth stating plainly: realm deletion chooses between two different
cascade implementations **based on how big the realm is**, and the two disagree about which key
families to remove. Deletion completeness therefore depends on tenant size.

The section's severity reasoning is explicit and correct: findings 2, 4 and 6 are three statements of
"data an operator was told was erased is still on disk" and sit at MEDIUM because the residue is not
live-exploitable while the realm's signing keys are destroyed.

**Critic's residual objection, and it is a sharp one:** that very claim — "the signing keys are
destroyed, so the residue is not live-exploitable" — is the only load-bearing sentence in the section
with **no test behind it**, and the section's own finding 3 describes a state in which it is false (a
realm wedged in `DeletingInProgress` with 18 keys before and 18 after). Three MEDIUM ratings rest on
it. An operator should treat those three as potentially HIGH in the wedged-realm case.

### 4.21 Compaction, hot/cold tiering, and every `unsafe` block (P19) — accepted

Seven findings. Two are BLOCKERs, and the second is the more disturbing of the pair because it needs
no crash at all.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | Partial compaction destroys the tombstone **before** unlinking the value it shadows; a crash in that window resurrects deleted keys — **on the shipped default config** | Data Validation | **BLOCKER** | Medium |
| 2 | `reload_sst_readers()` **silently drops any SST it cannot open**, and the next partial compaction then discards tombstones it must keep — corruption with no crash and no restart | Error Reporting | **BLOCKER** | High |
| 3 | Hot-tier fill races invalidation: a delete or update that overlaps an in-flight read is **permanently invisible to `get()` for the life of the process** | Timing | HIGH | Low |
| 4 | Cold-read promotion clones the entire hot-tier map under a global mutex — O(capacity·log capacity) on a path **any unauthenticated request can drive**, and it blocks revocation | Denial of Service | HIGH | Low |
| 5 | Every memtable flush re-reads every byte of every live SST to fetch a 60-byte header | Denial of Service | MEDIUM | Low |
| 6 | The `SAFETY:` comment on the SST mmap states an invariant that `compact_partial` violates, and the crash-safety doc on `compact_ssts` is contradicted for deleted keys | Data Validation | CLAIM-DEFECT | n/a |
| 7 | The second `unsafe` block in `src/` is in a module with no production caller; its own build recipe is the truncation its SIGBUS caveat forbids | Configuration | LOW | High |

Finding 1 confirms, at the shipped default configuration, the resurrection class that §2.1 flagged as a
red regression test and §4.11 derived independently. Three pieces converged on it from three
directions.

**Finding 2 is new and worse.** `reload_sst_readers()` silently swallows an SST it cannot open. The
next partial compaction then discards tombstones it was required to keep. There is no crash, no
restart, and no error — deleted data returns during normal operation. The other resurrection paths at
least require a badly-timed crash.

Findings 3 and 4 both bear on revocation. A delete that races an in-flight hot-tier fill is invisible
to `get()` **for the life of the process** — so a revoked credential can stay readable until restart.
And cold-read promotion clones the whole hot-tier map under a global mutex on a path an
unauthenticated request can drive, which blocks revocation while it runs.

Finding 6 is the `unsafe` audit's real result: the `SAFETY:` comment on the SST mmap asserts an
invariant that `compact_partial` violates. A `SAFETY:` comment that no caller upholds is worse than
no comment, because it stops the next reader from checking.

### 4.22 state / nonce, the federation relying-party side, and client authentication (P10) — accepted

Fifteen findings. No blockers — and the section says so plainly rather than inflating to match its
neighbours. Its value is in exposing a third structural pattern, described after the table.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `POST /realms/{realm}/introspect` and `/revoke` require **no client authentication**, disable the RFC 7662 audience restriction their twins enforce, and answer on a different wire format | Authentication | HIGH | Low |
| 2 | Omitting the `security:` block — the configuration the shipped example steers you to — sets `jwks_rps_limit` to 0, so OIDC discovery and JWKS return 429 forever, and empties the reserved-slug list | Configuration | HIGH | Low |
| 5 | Discovery advertises `client_secret_basic` and DCR instructs every client to use it, but the `client_credentials` grant reads only the body | Configuration | MEDIUM | Low |
| 6 | The `device_code` grant performs no client authentication (RFC 8628 §3.4) | Authentication | MEDIUM | Medium |
| 7 | `private_key_jwt` **and** the `jwt-bearer` grant are advertised, but nothing can write the `assertion_public_key` both read; FAPI 2.0 Advanced is likewise unreachable | Configuration | MEDIUM | Low |
| 8 | Federation sends a realm-agnostic `redirect_uri` upstream while the admin UI publishes a different, relative, realm-scoped callback URL | Configuration | MEDIUM | Low |
| 9 | `POST /realms/{realm}/register` issues a `client_id` the token endpoint cannot parse, and silently drops the requested grant types | Data Validation | MEDIUM | Low |
| 10 | **Every link on the admin Identity Providers list returns 404** — the page emits the prefixed `idp_<uuid>` display form to a handler that parses a bare UUID | Data Validation | MEDIUM | Low |
| 11 | The federation confirm-to-link flow resolves the **default** realm, not the realm the login started in | Access Controls | MEDIUM | Low |
| 12 | `POST /ui/federation/confirm-link` parses a `_csrf` field and never verifies it | Data Validation | LOW | High |
| 13 | Upstream ID tokens with a multi-valued `aud` are accepted without an `azp` check (OIDC Core 3.1.3.7) | Data Validation | LOW | High |
| 14 | Provider-side `nonce` replay detection is process-local and sweeps the whole set under a global mutex on every `/authorize` | Denial of Service | LOW | Medium |
| 3 | The `apple` federation preset is silently rewritten to a generic OIDC connector; `AppleConnector` is unreachable and no config surface accepts the Apple signing key | Configuration | CLAIM-DEFECT | Low |
| 4 | The SAML SP assertion consumer accepts a signed assertion, **audits a completed login, and creates no session** | Authentication | CLAIM-DEFECT | Low |
| 15 | `callback_post` / `callback_scoped_post` are routed but can never succeed from a browser | Error Reporting | Informational | Low |

Finding 1 independently confirms, from a third direction, the unauthenticated `introspect` / `revoke`
defect already found by §4.2 and §4.19 — and adds that those routes also *disable* the RFC 7662
audience restriction their header-form twins enforce.

Finding 4 is the counterpart to the SAML blocker in §4.10. There, signature verification consumes the
wrong element. Here, the SP-side consumer verifies a signed assertion, writes an audit record saying
the login completed, and then **issues no session at all**. The audit log says a user logged in when
nobody did.

**The third structural pattern: advertised capabilities that cannot be reached.**
`private_key_jwt`, the `jwt-bearer` grant, FAPI 2.0 Advanced, `client_secret_basic` on
`client_credentials`, the Apple federation preset, SP-initiated SAML SSO, `callback_post`, and every
link on the admin Identity Providers page. Each is present in discovery metadata, documentation or the
UI, and each is unreachable.

This is distinct from the "controls that parse and do nothing" pattern in the blocker note above. That
one costs an operator false confidence in a security control. This one costs an **integrator** weeks:
they read discovery metadata, build against `private_key_jwt`, and discover at integration time that
nothing can write the key the server would need to verify it. In an identity product, discovery
metadata is an API contract, and these entries break it.

### 4.23 Web UI, sessions, and browser security (P22) — accepted at round 2 of its second run

This piece exhausted four rounds in an earlier batch, winning the blind comparison every time and
failing every time on evidence. Re-run with its last critic's objection as the brief, it passed:
**zero unresolved citations, zero failed repros, repo clean, sixteen findings surviving** — and the
critic killed **two negatives**, unsupported "found sound" claims, rather than any finding.

The objection it was sent back to fix is worth quoting, because the fix is the best single paragraph
in this audit. The earlier version sold its top three findings as *cross-site* attacks. Its own
control leg disproved that. The accepted version now opens with this, before the table:

> **Findings 1a, 2 and 3 are not cross-site attacks.** All three require attacker-controlled content
> on a host that shares Hearth's *registrable domain* — e.g. `cms.corp.example` when Hearth is
> `id.corp.example`. The control leg proves it: a top-level POST from `attacker.test` got
> `Cookie header Chrome attached: *** NOT SENT ***`. `SameSite=Lax` does exactly its job against a
> genuinely cross-site request; what defeats it is that a sibling host under the same registrable
> domain is *same-site*, and `SameSite` ignores the host label and the port. **If nothing but Hearth
> is served from your registrable domain, findings 1a, 2 and 3 collapse to server-side hygiene.**

It then says why they are still rated as they are: `auth.example.com` beside `www.example.com` and
`blog.example.com` is the modal identity deployment, and a marketing CMS is exactly the kind of
sibling an attacker gets a foothold on first. **That is a finding an operator can apply to their own
architecture in thirty seconds** — which is the whole point.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1a | Nine authenticated `/ui/admin` mutations (MFA teardown, session and passkey revocation, audit-log prune) accept the session cookie with **no CSRF token** and are drivable by a top-level form POST from a same-registrable-domain sibling origin | Access Controls | HIGH | High |
| 1b | Eight more `/ui/admin` mutations — including the whole-file `hearth.yaml` rewrite — are equally tokenless; no browser page can deliver them today, only a cookie-holding non-browser client | Access Controls | MEDIUM | High |
| 2 | `POST /required-action/UPDATE_PASSWORD` changes a password with **no CSRF token and no old-password check** | Access Controls | MEDIUM | High |
| 3 | The double-submit CSRF token is **forgeable by cookie-tossing**: `cookie_value` returns the first `hearth_ui_csrf` in the header, so a sibling host that plants a `Domain=`-scoped cookie makes the check compare an attacker-chosen value to itself | Access Controls | MEDIUM | High |
| 4 | The config editor's `visual/apply` returns `{"ok":true}` after applying only part of the posted config: **the live reconcile archives every realm the operator did not re-list** | Data Validation | MEDIUM | Undetermined |
| 5 | `hearth_ui_sms_mfa` (the HMAC-signed MFA-state cookie carrying a pending OAuth authorize) and `hearth_ui_flash` are issued with **no `Secure` attribute** on every code path, while the session, CSRF and required-action cookies correctly gain it | Data Exposure | MEDIUM | High |
| 6 | `GET /docs` — unauthenticated, **same origin as the admin console** — loads Swagger UI from `unpkg.com` with no Subresource Integrity and no CSP to constrain it | Data Validation | MEDIUM | High |
| 7 | Hearth's own `/ui` CSP **breaks the SAML HTTP-POST binding it emits**: the auto-submit is blocked by `script-src 'self'`, a manual submit by `form-action 'self'` | Configuration | MEDIUM | Low |
| 8 | **HSTS is never emitted in the modal proxy-terminated-TLS deployment**; the hardening guide states it is automatic "when TLS is enabled" and never tells a proxy operator to set it at the proxy | Configuration | CLAIM-DEFECT | Low |
| 9 | Browser-facing HTML on the API router (`GET /docs`, `GET /end_session`) ships with no CSP, no `X-Frame-Options`, no `frame-ancestors` and no `Cache-Control` | Configuration | LOW | Medium |
| 10 | Unauthenticated tenant enumeration: real vs non-existent realm is distinguishable (200 vs 404, different body length) across every `/ui/realms/{r}/*` pre-auth shape, with no rate limit on the oracle | Data Exposure | LOW | Low |
| 11 | Unauthenticated SAML IdP metadata reflects `X-Forwarded-Host` into `entityID` and the SSO/SLO endpoint URLs when `onboarding.base_url` is unset | Data Validation | LOW | Medium |
| 12 | `/ui/static/theme.css` serves an operator-pointed file's raw bytes to unauthenticated clients with no content-type or size validation | Data Exposure | LOW | High |

**Finding 8 closes the question raised in §4.5.** The route-inventory critic suspected HSTS was
silently disabled behind a TLS-terminating proxy. It is — and the hardening guide tells the operator
it is automatic. An operator following the documentation ends up with no HSTS and believes they have it.

**Finding 4 is a data-destruction path reached through the admin UI.** The config editor answers
`{"ok":true}` while the live reconcile **archives every realm the operator did not re-list** in the
posted config. Combined with §4.20 finding 5 — archival is not a freeze, but 11 of 16 mutating
operations still write an archived realm — an operator editing config in the UI can silently archive
tenants and receive a success response.

**Finding 7 is a self-inflicted interoperability break** worth noting for its shape: Hearth emits a
SAML HTTP-POST binding that Hearth's own Content-Security-Policy then blocks. Two correct-looking
subsystems, mutually incompatible.

### 4.24 Magic links, password reset, and user enumeration (P17) — accepted at round 1

Thirteen findings, two at HIGH. The critic re-extracted every citation with its own scripts rather
than the author's, re-executed every repro, and re-derived every negative result from source.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | **Password-reset tokens survive an email change, an out-of-band password change, and their own supersession** | Authentication | HIGH | Medium |
| 2 | Recovery tokens reach the operator log in cleartext — the setup token unconditionally, reset links on the default transport — and the startup banner says otherwise | Data Exposure | HIGH | Low |
| 3 | `POST /ui/forgot-password` leaks account existence through the in-request SMTP send | Timing | MEDIUM | Low |
| 4 | `POST /ui/register`'s duplicate-email arm skips Argon2id and the verification mail, making a registered address measurably **faster** | Timing | MEDIUM | Low |
| 5 | A reset token is consumed **before** the new password is validated: an 8-to-11-character password destroys the link while the page says "try again" | Error Reporting | MEDIUM | Low |
| 6 | **Magic-link login cannot complete**: no redemption route, no mail sent, and the grant all seven SDKs post is rejected | Authentication | MEDIUM | Low |
| 7 | **Admin password reset is unrecoverable**: the emailed link points at a route that does not exist | Authentication | MEDIUM | Low |
| 8 | The pre-auth `/ui/*` tree is outside the global rate limiter, the magic-link limiter is never fed, and neither endpoint's records are ever reclaimed | Denial of Service | MEDIUM | Low |
| 9 | `email.transport: log` passes production validation for a password-only realm, **silently discarding every reset email** | Configuration | MEDIUM | Low |
| 10 | Two admin actions mint reset tokens, discard them, and report "Reset email sent" | Error Reporting | MEDIUM | Low |
| 11 | `validate_magic_link` creates accounts without consulting `RegistrationPolicy` | Access Controls | MEDIUM | Medium |
| 12 | `auth.token.magic_link_ttl` is documented, parsed, capped, stored — **and never read** | Configuration | CLAIM-DEFECT | Undetermined |
| 13 | The rate-limit persistence table in `CONFIGURATION.md` is wrong on four of its five rows | Configuration | CLAIM-DEFECT | Undetermined |

**Finding 1 is the takeover path.** A reset token survives the email address changing underneath it.
Request a reset, change the account's email, and the old token still works.

**Finding 2 corroborates blocker B8 from a fourth independent direction**, and adds that reset links —
not just the setup token — reach the log on the default transport.

**Findings 6, 7 and 9 belong together**, and an operator should read them as one sentence: *the
password-recovery story does not work.* Magic-link login cannot complete at all. Admin password reset
emails a link to a route that does not exist. And `email.transport: log` passes production validation
for a password-only realm, so a realm whose only credential is a password can be configured, validated,
and started in a state where **no reset email is ever sent**. Finding 10 completes it: two admin
actions mint a reset token, discard it, and report "Reset email sent".

**The section's calibration note is worth quoting**, because it is exactly the discipline the bar
demands:

> Two of thirteen at HIGH. The two enumeration oracles (3, 4) are rated MEDIUM deliberately: the
> visible channel — status, `Location` and body — is byte-identical in both; the leak is a side
> channel that, on the host I had, needed a handful of paired samples per address rather than one
> request; and the outcome is a verified address list, not a compromise.

It then justifies that against the reference report's own choice to rate a non-constant-time password
comparison Medium. An auditor arguing its own finding *down*, with the reference standard as the
yardstick, is the behaviour this process was built to produce.

Findings 6, 7 and 12 add three more entries to the two structural patterns already named: a documented
TTL that is parsed and never read, and two advertised recovery flows that cannot complete.

### 4.25 Secret entropy and constant-time comparison (P08) — accepted at round 1

Six findings. This piece is the audit's clearest example of **a measured negative result beating an
asserted positive one**.

| # | Title | Type | Severity | Difficulty |
|---|---|---|---|---|
| 1 | `/realms/{realm}/introspect` and `/realms/{realm}/revoke` compare **no client secret at all** | Authentication | HIGH | Low |
| 2 | Omitting the `security:` key sets `jwks_rps_limit` to 0, so every discovery and JWKS endpoint returns 429 forever | Configuration | HIGH | Low |
| 3 | Client authentication runs Argon2id **only** for registered confidential clients, leaking client existence and client type by timing | Timing | MEDIUM | Low |
| 4 | Device user codes are drawn with `byte % 28` — a biased modulo — and the approval endpoint enforces **no attempt limit** and is not covered by the request shaper | Cryptography | MEDIUM | Medium |
| 5 | PAR `request_uri`, consent tickets, federation confirm tickets, SAML `RelayState` and session IDs carry **122 bits**, below the 128-bit floor RFC 9126 §7.1 makes normative | Cryptography | LOW | High |
| 6 | Nine secret-shaped comparisons use non-constant-time `==` / `!=` | Timing | LOW | High |

**Finding 6 is rated LOW on measurement, not on assumption.** The section found the nine
non-constant-time comparisons — the exact bug class the reference report's flagship timing finding
covers — and then *measured* the channel, reporting the sample count that would be required to exploit
it. At realistic sample counts it is not exploitable, so it is LOW with difficulty High.

The critic's reason for choosing our section, verbatim, is the point:

> Ours measures the timing channel and reports the sample count that makes the non-constant-time
> compare unexploitable (a proven negative result), where the matching ToB finding only asserts a
> timing attack is possible "in theory" and never checks — so an operator learns from ours whether the
> defect is live, and from theirs only that it exists.

That is the standard the brief demanded: not "we found the bug class", but "we found it, measured it,
and here is what it costs you."

Finding 4 is the one to act on: a biased `byte % 28` draw for device user codes, on an approval
endpoint with **no attempt limit** and no rate shaping.

Findings 1 and 2 are the fourth and fifth independent confirmations of defects already recorded in
§4.2, §4.13, §4.19 and §4.22. Five separate pieces, working from five different angles, reached the
unauthenticated `introspect`/`revoke` routes and the zero-valued `jwks_rps_limit`.

**A defect in our own deliverable, recorded rather than quietly fixed:** the section promises
"Appendix A/B/C" containing `r2.yaml`, `smtpsink.py` and `p08probe.py` as "everything needed to re-run
all of them" — and the file contains no appendices and none of those files. The critic had to
reconstruct the entire harness from the parameters in the prose. It confirmed every result as correct,
but **an operator cannot run a single repro from this section as written.** That is precisely the
"every command must be executable verbatim" rule, broken by our own auditor, and it is reported here
for the same reason we would report it against the project.

---

## 4A. A note on how this audit was interrupted, and what that costs the reader

The audit ran over nine days against an unstable harness. Agents were killed mid-response by
transport errors many times; session quotas were hit twice; and the working directory was **deleted
three times** — once from `/scratch` when the volume was swapped, once again later, and once from the
`~/.claude` location it had been moved to for safety.

Nothing was lost, and the mechanism is worth recording because it is the only reason this report
exists. Every section and critique was written with a tool whose calls are preserved in the subagent
transcripts under `~/.claude/.../subagents/`, which survived every wipe. Three separate recovery runs
reconstructed the corpus from those transcripts — the last recovering **37 sections and 129
critiques**, several of them newer than the copies that had been lost. The Trail of Bits corpus was
re-downloaded from the same pre-archival commit each time and verified against identical page counts.

**What this costs the reader is one thing only: a piece that appears in section 4 has been through a
critic, and a piece that does not appear has not.** Seven pieces have complete, written sections that
no critic has passed. Their findings are deliberately **absent** from this report — not summarised,
not caveated, absent. An unverified audit finding reads exactly like a verified one and gets trusted
the same, which is the failure the entire critic apparatus exists to prevent. Section 8 names each of
the seven and what is known about it.

---

## 5. The five things I'd fix first

See **§1A**, written immediately after the verdict so a reader who stops after two pages still knows
what to do on Monday. This ordering follows the reference report's own structure, which puts its
Recommendation Summary at p.13, before any finding.

---

## 6. Claim verification table

Every row below comes from a piece that **passed** adversarial review. The dedicated
claim-verification piece did not pass and is excluded entirely; what follows was found incidentally by
pieces auditing something else, which means this table is a floor, not a ceiling.

| Public claim | Status | Evidence |
|---|---|---|
| "900+ Rust tests, all green" | **FALSE** | 4736 tests run, **4 failing**, 13 skipped at `b291a723` on a clean checkout (§2.1) |
| `make check` passes | **FALSE** | Clippy aborts on a hard compile error, so `cargo fmt --check` and the test suite have **never executed** on this commit in CI (§4.12 finding 17) |
| WAL is `fsync`'d before acknowledging any write; survives `kill -9` (`CLAUDE.md`) | **FALSE** | WAL rotation destroys acknowledged writes under concurrent writers; a clean `SIGTERM` suffices. **No test in the repository can distinguish `fsync`-before-ack from no `fsync` at all** (§4.11) |
| "Encrypted at rest with per-realm keys" (three normative documents) | **FALSE** | One KEK covers every realm (§4.9 finding 5) |
| The system realm is read-only through public APIs (README) | **FALSE** | Role and group writes to the reserved realm succeed (§4.1 finding 7) |
| A release whose test suite fails "is never published" (CHANGELOG) | **FALSE** | Container image, Helm chart, seven SDK releases and two registry packages published from a red commit, 37 minutes before the validation job reported failure (§4.8, §4.12) |
| SLSA provenance and cosign signatures are verifiable | **TRUE, AND MISLEADING** | Both documented verification commands **pass** — on a build that fails validation. The attestation proves origin, not fitness (§4.8 finding 2) |
| Storage keys are realm-prefixed; scans are realm-bounded | **TRUE** | The audit set out to falsify this and could not. The isolation failures found are realm-*parameter* bugs, not key-prefix bugs (§4.9) |
| Signing is Ed25519 only; no `alg:none`, no algorithm confusion | **TRUE** | No `alg:none`, no HMAC/asymmetric confusion, no attacker-influenced `kid`/`jku`/`x5u` on the verify path (§4.2) |
| No token minted in realm A is accepted in realm B | **TRUE** | Tested across every reachable entry point: header, path form, session cookie, gRPC metadata, SCIM token (§4.1) |
| Rotation is the remedy for a compromised signing key | **FALSE** | The retired key mints new admin tokens for the full 24-hour grace window (§4.15) |
| `want_authn_requests_signed` (SAML security flag) | **FALSE — dead control** | Parsed, validated, never consulted (§4.10 finding 4) |
| `security.backup.verify_key` is fail-closed | **FALSE — dead control** | Never wired into the restore handler; the check can never fire (§4.13 finding 5) |
| `storage.fsync` is a working knob | **FALSE — dead control** | Ignored in both production and dev mode (§4.11 finding 12) |
| `security.http2.*` rapid-reset caps | **FALSE — dead control** | Parsed, validated, never read; caps apply only on the TLS listener (§4.12 finding 20) |
| `auth.token.magic_link_ttl` | **FALSE — dead control** | Documented, parsed, capped, stored, never read (§4.24 finding 12) |
| WebAuthn user-verification policy | **FALSE — dead control** | Dead code; a passkey that never proves user verification satisfies `mfa_required` (§4.18 finding 1) |
| Eight abuse-prevention guards documented "Shipped" | **FALSE** | Never constructed outside their own test modules; six of their config keys make the server refuse to boot (§4.17 finding 9) |
| `private_key_jwt`, `jwt-bearer`, FAPI 2.0 Advanced (discovery metadata) | **FALSE — unreachable** | Advertised; nothing can write the `assertion_public_key` both read (§4.22 finding 7) |
| Magic-link login | **FALSE — unreachable** | No redemption route, no mail sent, and the grant all seven SDKs post is rejected (§4.24 finding 6) |
| SP-initiated SAML SSO | **FALSE — unreachable** | Validates the assertion, audits a completed login, creates no session (§4.22 finding 4) |
| README documents `PUT` for five admin mutation routes | **FALSE** | Server implements `PATCH`; `PUT` returns 405 (§4.5 finding 5) |
| HSTS is automatic "when TLS is enabled" (hardening guide) | **FALSE** | Never emitted in the modal proxy-terminated-TLS deployment (§4.23 finding 8) |
| `hearth --version` reports the running version | **FALSE** | Wrong in five of seven operator-visible surfaces; falls back to a stale `Cargo.toml` when `.git` is absent — the container build's exact condition (§4.8, §4.12) |
| Container images are Apache-2.0 licensed | **FALSE** | Every published image is labelled `AGPL-3.0-only`; the project relicensed three months ago (§4.12 finding 7) |
| The documented Docker and Helm install paths work | **FALSE** | Not anonymously readable; two of three documented install paths fail at the first command (§4.12 finding 4) |
| `mode=overwrite` restore is a supported operation | **FALSE** | 1,160 runs: none completed, 975 destroyed or truncated the realm, one reported exit 0 (§4.9 finding 2) |
| Cluster mode is production-ready | **UNVERIFIABLE — and the evidence available points against it** | A control sound on a leader is unsound on a follower; at least four security-relevant paths have that asymmetry, including two kill-switches and key rotation, and the known-defects list names only two caches (§4.1, §4.19). The dedicated cluster piece did not clear review — see §8 |
| Performance table (sub-µs validation, `W=1.000`, 100 B/user) | **UNVERIFIED** | The dedicated piece did not clear review. Not assessed here. See §8 |
| Protocol conformance (OIDC, SCIM, SAML, seven RFCs) | **UNVERIFIED** | Same. See §8 |

---

## 7. Coverage ledger

### 7.1 Accepted — passed adversarial review (25 of 32 pieces)

Every finding in section 4 comes from this list. Each section had every `file:line` opened and every
repro re-run by a critic with fresh context, then beat the matching Trail of Bits section in a blind
comparison. "Rounds" is how many times the section was rejected and rewritten before it passed.

| § | Piece | Subsystem | Rounds | Depth |
|---|---|---|---|---|
| 4.1 | P13 | Cross-realm token acceptance, admin IDOR sweep | 1 | Read closely + live testing |
| 4.2 | P04 | JWT verification, algorithm and key selection | 2 | Read closely + live testing |
| 4.3 | P09 | `redirect_uri`, PKCE, authorization codes | 2 | Read closely + live testing |
| 4.4 | P25 | Reachable panics, request-level DoS limits | 1 | Read closely + live testing |
| 4.5 | P01 | Route inventory and per-route guards | 1 | Read closely + live probing |
| 4.6 | P24 | Federation fetching, SCIM, LDAP, webhooks | 1 | Read closely + live testing |
| 4.7 | P03 | Dev-only affordances in a release build | 2 | Read closely + live testing |
| 4.8 | P27 | Supply chain, build, and release integrity | 4 | Read closely + live artefact verification |
| 4.9 | P12 | Storage-layer realm isolation | 2 | Read closely + live testing (45 repros re-run) |
| 4.10 | P23 | SAML parser | 2 | Read closely (159 citations, 23 repros, zero failures) |
| 4.11 | P18 | WAL durability and crash recovery | 2 | Read closely + fault injection |
| 4.12 | P00 | Build baseline, independently re-derived | 3 | Read closely (critic re-ran 72 commands) |
| 4.13 | P02 | Config defaults and fail-open behaviour | 2 | Read closely + live testing |
| 4.14 | P26 | Secret hygiene in logs, audit hash chain | 2 | Read closely + live trace-level capture |
| 4.15 | P06 | Signing-key rotation, JWKS, key-at-rest | 1 | Read closely + live testing |
| 4.16 | P07 | Refresh rotation and theft detection | 3 | Read closely + 15 pinned concurrency runs |
| 4.17 | P15 | Argon2id, lockout, X-Forwarded-For | 2 | Read closely + measured timing |
| 4.18 | P16 | MFA: TOTP, WebAuthn, step-up | 1 | Read closely + live testing |
| 4.19 | P05 | Claim validation on every token path | 4 | Read closely (689 citations, zero unresolved) |
| 4.20 | P14 | Cascading deletion | 5 total | Read closely + live testing |
| 4.21 | P19 | Compaction, tiering, every `unsafe` block | 1 | Read closely + fault injection |
| 4.22 | P10 | state/nonce, federation RP side, client auth | 2 | Read closely + live testing |
| 4.23 | P22 | Web UI, sessions, browser security | 6 total | Read closely + 26 browser harness scripts |
| 4.24 | P17 | Magic links, password reset, enumeration | 1 | Read closely + measured timing |
| 4.25 | P08 | Secret entropy, constant-time comparison | 1 | Read closely + measured timing |

Two pieces needed a second run after exhausting four rounds: cascading deletion (§4.20) and the web UI
(§4.23). Both had been *winning* the blind comparison and failing on evidence — the intended
behaviour, and the reason those two sections are among the strongest here.

### 7.2 Not accepted — findings excluded from this report (7 of 32 pieces)

Each has a complete written section. None passed a critic. **Nothing from them appears anywhere in
this report.** See §8 for what is known about each.

| Piece | Subsystem | Rounds failed | Last recorded reason |
|---|---|---|---|
| P11 | Device grant, DCR, introspection, permission modes | 2 | Evidence defects |
| P20 | Unbounded growth, backup round-trip, format versioning | 3 | Evidence defects |
| P21 | Cluster mode GA-readiness | 2 | Evidence defects |
| P28 | Seven SDKs: verify or decode-and-trust | 1 | Evidence defects |
| P29 | Test-suite quality and the mutation spot-check | 2 | Evidence defects |
| P30 | Public claim verification, performance methodology | 2 | One repro did not reproduce; two negative results false. **791 citation occurrences across 413 distinct file:line pairs, zero unresolved** |
| P31 | Day-2 upgrade, versioning, deployment artefacts, first-run | 2 | Evidence defects |

### 7.3 Never examined

No piece was assigned to: LDAP beyond the surface covered in §4.6; the gRPC management API beyond the
`Decide` and admin paths reached by §4.2 and §4.19; the organisations subsystem; the agent-identity
surface (DPoP, token exchange, MCP authorisation, approval lifecycle) beyond the token paths in §4.19;
the email transports other than through the config and recovery paths; the fuzz targets; the load-test
harness. **Unexamined surface area in an identity product is itself a finding**, and this paragraph is
the honest statement of it.

---

## 8. What I could not verify, and why

This section is load-bearing. Read it before acting on section 6.

### 8.1 The seven unaccepted pieces

Each has a written section that a critic read and rejected. I am not reporting their findings, but I
can say what the outstanding question is, because a reader needs to know what is *unmeasured* rather
than *measured-and-clean*:

1. **Cluster mode GA-readiness (P21).** The direct question the brief asked — GA or experimental — has
   no critic-passed answer. What is established, from two *accepted* pieces (§4.1, §4.19), is that a
   control sound on a leader is unsound on a follower, and that at least four security-relevant paths
   have that asymmetry including two kill-switches and key rotation. That is why §1 recommends gating
   cluster mode regardless. But the systematic enumeration, the failover and split-brain test count,
   and the operator-documentation walkthrough are **not** done.
2. **The performance and conformance claims (P30).** The published performance table and every
   protocol-conformance claim are **unverified**. This is the largest single gap in section 6. The
   piece failed on one non-reproducing repro and two false negative results — not on citations, of
   which 413 distinct pairs resolved cleanly — so its material is likely substantially sound and is
   still excluded.
3. **The mutation spot-check (P29).** The brief's sharpest instrument — comment out five
   security-critical checks and see whether anything goes red — has no passed result. **We therefore
   cannot say whether this test suite can fail.** Given §4.11 established that no test can distinguish
   `fsync`-before-ack from no `fsync` at all, this gap should worry a reader more than most.
4. **The seven SDKs (P28).** Whether each SDK verifies a token or decodes and trusts it is
   **unanswered**. §4.2 established that four SDKs accept RS256 and ES256 — algorithms the server
   never signs with — but the per-SDK verify/decode matrix is not done. An SDK that decodes without
   verifying would be a critical finding, and nobody has confirmed or excluded that.
5. **Backup round-trip and on-disk format versioning (P20).** What a backup silently drops is known
   only in fragments from other pieces (§4.18: every TOTP secret, passkey and OTP factor). The
   systematic round-trip diff, restore-into-a-different-version, and truncated/corrupted-backup tests
   are not done.
6. **Day-2 upgrade and the cold first-run (P31).** The brief calls the cold first-run "the single most
   informative hour in the whole audit". It has no passed result. Whether v1.6.x data can be read by
   the current build is **unknown**.
7. **Device grant, DCR, introspection, permission modes (P11).** Whether dynamic client registration
   is open to the internet by default is **unanswered**.

### 8.2 Limits inherent to the method

- **Every finding here is from one machine, one architecture, one filesystem.** Timing measurements,
  the concurrency races, and the crash-recovery results would need re-running elsewhere before being
  treated as universal.
- **No external service was reached.** No official OIDC or SCIM conformance suite was run, no real
  upstream IdP was federated with, no real SMTP or SMS provider was used, and no container registry
  was pulled from anonymously (that failure is itself §4.12 finding 4).
- **Cluster findings are single-process reasoning.** No multi-node cluster was stood up. The follower
  cache asymmetry is derived from source, not observed on a real follower.
- **The blind comparison is a judgement, not a measurement.** A critic with fresh context compared two
  anonymised documents and picked one. That is a strong signal — it caught invented test references, a
  false "no operator remedy" claim, and three severity misratings — but it is not a metric, and two
  critics could disagree.
- **Severity is calibrated against the brief's rubric and the reference report, by agents.** Where a
  rating is contested, the contest is recorded in-line rather than resolved silently. §4.14 documents
  one severity that was escalated after a critic argued it was too low.

### 8.3 What would close these gaps

In rough order of value: run the mutation spot-check against a green baseline; stand up a three-node
cluster and enumerate every cache the state machine bypasses; produce the per-SDK verify/decode matrix;
run one official conformance suite; do the cold first-run with a transcript. The first two are the ones
that would most change the verdict's confidence, not its direction.

---

## 9. Residual risk statement

**Assume every blocker in section 3 is fixed. What would still worry me about this system holding real
credentials for two years?**

**1. The defect class, not the defects.** Eleven blockers were found, and only two need an attacker.
The rest are integrity failures that fire during ordinary operation — a clean shutdown, a documented
restore, a normal compaction, a release. Fixing eleven instances does not fix the property that
produced them: **operations that report success while not having succeeded.** A restore that destroys
a realm and exits 0. A CLI family that emits zero bytes. A config editor answering `{"ok":true}` after
applying part of a config. A release pipeline signing a failing build. A SAML consumer auditing a login
that never happened. Two admin actions reporting "Reset email sent" after discarding the token. That is
one habit of mind appearing in six subsystems, and it will produce new instances.

**2. Controls that parse, validate, and do nothing.** Nine were found in unrelated subsystems. This is
worse than a missing feature because it converts an operator's diligence into false confidence: they
set the control, nothing rejects the value, and the control is not there. Until there is a start-up
assertion that every parsed security key reaches a consumer, assume more exist.

**3. The tests cannot be trusted to catch regressions of the things that were fixed.** No test can
distinguish `fsync`-before-ack from no `fsync`. Two regression tests for data-integrity defects were
**committed red** and stayed red. A third is red because its own harness starves the request task.
Both advisory gates are `continue-on-error`. And the mutation spot-check that would measure this never
cleared review. A fix without a test that fails against the old code is a fix that will be undone.

**4. Documentation drift is systemic, and operators make security decisions from documentation.**
Section 6 has more FALSE rows than TRUE. Three normative documents assert per-realm encryption at rest
that does not exist. `docs/STATUS.md` and the README disagree with the code and with each other. In an
identity product this is not cosmetic: an operator sizes their key-compromise blast radius, their HSTS
posture, and their MFA guarantees from these documents.

**5. The follower problem is probably larger than four paths.** Two accepted pieces found four
security-relevant controls stranded on Raft followers, including two kill-switches and key rotation,
against a known-defects list naming two caches. Nobody has enumerated the rest. Until someone does, a
multi-node deployment has an unknown number of controls that work on one node and silently do not work
on the others.

**6. Seven of thirty-two pieces did not clear review, and the audit does not know what is in them.**
Most consequentially: nobody has confirmed that the SDKs verify tokens rather than decoding them, and
nobody has confirmed that the test suite can fail.

**What I would tell an operator considering this in two years' time:** the cryptographic core is
sound — algorithm pinning holds, realm key-prefixing holds, no cross-realm token acceptance was found
across every entry point tested. The danger here has never been the cryptography. It is that the system
reports success it has not achieved, and that its tests are not currently able to tell anyone
otherwise.
