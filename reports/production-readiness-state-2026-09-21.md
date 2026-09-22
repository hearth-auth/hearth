# Where Hearth actually stands

Written 2026-09-21, at the end of a day that closed 60 backlog items and opened
33 new ones. That ratio is the thing worth explaining, so it comes first.

---

## 1. The short answer

**Not production ready.** One reason outranks all the others:

> `arc-swap` 1.9.2 corrupts the heap under the `load`+`rcu` pattern, and six
> files still use it on `validate_token`, `lookup_session` and every storage
> read. Measured today: **3 failures in 150 loaded runs — two `SIGSEGV`, one
> `free(): invalid size`.** Zero in 150 after swapping the primitive.

Everything else on the blocking list is ordinary engineering or a decision.
That one is a memory-safety fault on the authorization path.

**But the eleven blockers from the August audit are all closed.** That is real
and it is measured, not felt — see §2.

---

## 2. Why it feels like you are not getting closer

You are getting closer. The number that tracks it went the wrong way today, and
here is the actual mechanism.

### The backlog grows when a new instrument is used for the first time

Four instruments were pointed at this system **for the first time ever** today:

| Instrument | Never run before | What it found |
|---|---|---|
| OpenID Foundation conformance suite | correct — `TESTING.md` said so plainly | Hearth cannot pass **any** OIDC Core certification profile |
| A real three-node cluster | correct | A cold cluster **could not start at all** |
| The mutation spot-check, end to end | correct | The `hearth.admin` permission check had **zero** coverage |
| A cold first-run from the README | correct | 17 findings, incl. a backup command that could not run in production |

None of those findings were created today. They were all already true. The
backlog did not get worse; the **measured surface** got bigger.

That is why it feels like a treadmill. Every audit that points a *new*
instrument at the system finds a fresh population of defects, and the fixes you
already shipped are invisible in the count because they were never counted as
"done" against anything.

### The test that tells you which it is

Today's four new instruments **now exist and are repeatable**. The conformance
run has a recorded configuration. The three-node harness is a test file. The
mutation runner is a CI job. The cold first-run has a transcript.

So there is a falsifiable prediction:

> The next audit that uses only **existing** instruments should find far fewer
> new defects than today did.

If that turns out false, the problem is deeper than measurement. If it turns out
true — and the evidence below says it will — then you have been converting
unknown unknowns into known ones at a high rate, which is exactly what this
phase is supposed to look like.

### The evidence that fixes do stick

* **All eleven August blocker-class defects are closed.** Cross-tenant backup
  export, a restore that destroyed tenants, acknowledged writes lost on clean
  `SIGTERM`, XML Signature Wrapping in SAML, a release pipeline signing a red
  build, deleted data resurrecting, the setup token in production logs, a
  rotated signing key that kept minting admin tokens, a passkey that satisfied
  MFA without proving user verification, SSTs silently dropped. Gone.
* **Sections 1–22 of the backlog are complete**, except the GHCR package
  visibility, which needs a browser.
* **5538 tests pass**, up from 4,643 claimed and unverified in August.
* Four merge gates are green and each has a red case proving it can fail.

### The honest caveat

**Every count in the original audit was a floor.** Not once did a
re-measurement find fewer:

| Audit said | Actually |
|---|---|
| 4 authoritative caches a follower bypasses | **7**, of 47 process-local items |
| 7 unbounded HTTP egress paths | **13**, in 12 files |
| 2 organisation role-leak paths | **3** |
| 4 unvalidated LDAP filter interpolations | **8** |
| ~34 protocol-layer audit call sites | **40** |

So "324 of 331 closed" means 98% of the **known** defects are gone. It does not
mean 98% of the defects are gone.

---

## 3. What was fixed today

Grouped by defect class, because the classes repeat and the classes are the
useful thing to know.

### 3.1 "Reports success it never achieved" — the dominant class

Found more than a dozen times. Each one told a caller something had happened
that had not.

* **The load-test harness computed a pass/fail verdict and discarded it.** 15 of
  29 archived reports have a failure rate ≥ 0.99. All exited 0.
* **`hearth backup create` created a typo'd `--data-dir`**, exported nothing and
  exited 0; `backup verify` then said *"OK — all checksums match (0 files
  verified)"* and also exited 0.
* **`backup verify` walked the tar, not the manifest**, so a deleted member was
  never visited — "OK, 15 files verified" over 14 files.
* **Session-limit eviction audited the number of *attempts* as `"evicted"`** and
  admitted the new session anyway, so a failing revocation took the realm over
  its limit while the audit log recorded the limit as enforced.
* **`POST /revoke`'s refresh arm answered 200** while the session stayed live.
* **The Kotlin SDK's publish job was green 43 times and shipped nothing** — the
  `publishing` block declared a publication and no repository, so `gradle
  publish` had zero targets and exited 0.
* **Assigning a role to a nonexistent organisation answered 201** and wrote a
  scope that could never grant anything.
* Three terminal security actions returned `Ok` after losing their mandatory
  audit record.

**Now structural:** `tests/audit_discard_guard.rs` walks `src/` and refuses a
discarded mandatory audit write or a discarded `revoke_session`. It parses the
`FailOperation` list **out of** `AuditAction::failure_policy` rather than
copying it, so it cannot go stale.

### 3.2 A control that exists but is not wired

* **`flush_approval_webhook_outbox_inner` had zero callers.** So the documented
  "durable at-least-once" approval webhook was at-*most*-once, and every
  undelivered request leaked an outbox row permanently.
* **`revoke_agent`, `suspend_agent` and `reactivate_agent` were reachable from
  no protocol at all** — no REST route, no gRPC method, no console page. Twelve
  controls honour the state; nothing could enter it.
* **The MCP scope validator had zero production callers.**
* **A DPoP replay cache duplicated a durable check and was used by nothing** —
  and a comment claimed the protocol layer delegated all DPoP enforcement to it.

### 3.3 Validation that disagrees with the running server

* A **CIDR** in `trusted_proxies` passed validation and was **discarded** at
  runtime — producing an empty proxy list, which is exactly the state validation
  refuses two checks earlier.
* `config validate` checked `HEARTH_KEK` but not `HEARTH_MASTER_KEY`, so it said
  ✓ on a config `serve` then refused.
* `${VAR}` was substituted inside **YAML comments**, so `hearth.example.yaml` —
  the file `hearth config example` itself emits — failed its own validation.
  Measured: **15 errors before, 3 after**, and all three remaining are genuine.

### 3.4 Claims that were not true

* **The README and `VISION.md` were publishing a throughput figure that
  `PUBLISHED_FIGURES.md` formally retracted on 2026-07-30** — and both cite that
  file as their source of record, two dozen lines above the table.
* **The landing page said "OIDC Core 1.0 conformant"** while `TESTING.md` said
  no conformance suite had ever been run and ended *"Do not represent Hearth as
  certified."*
* **The landing page's "<1 ms p99 validate_token"** was a target typeset as a
  measurement, naming the wrong plane. The published figure is 1.31 µs p50 at
  the engine plane.
* `docs/STATUS.md` listed SAML 2.0, SCIM 2.0, FAPI 2.0 and the whole agent
  surface as unimplemented roadmap. All four ship.
* `SDK.md` still said *"Hearth has not shipped yet"*. 1.0 GA was 2026-06-21.

### 3.5 Security fixes

* **Four cluster kill-switches did not bind on other nodes.** A realm suspended
  on node A, a token revoked on A, a DPoP key blocked on A — none took effect on
  B until it restarted. Closed by a replicated control epoch.
* **A revoked agent's capability token kept working** for its five-minute life.
* **gRPC reflection accepted any `Bearer x`** — it checked the header existed,
  never that the token was valid.
* **A suspended organisation kept granting** on five paths.
* **The first admin's email-verification token was logged in full at WARN.**
* **PBKDF2, bcrypt, argon2 and scrypt let the stored hash choose the server's
  CPU and memory cost.** `i=4294967295` meant 4.3 billion HMAC rounds per login
  attempt; argon2's `m` was bounded only by `u32::MAX`, a 4 TiB allocation.
* **Five outbound HTTP paths had no timeouts at all.** Four run on a Tokio
  *worker* thread — including the breach check on password-set and the captcha
  verify on login, where the deliberate fail-open branch could never fire.
* **Device-code redemption had no advisory lock** and deleted the code *after*
  minting tokens, discarding the result.
* **SAML account linking was unreachable**, so a SAML login by an existing user
  silently created a *second* account under a synthetic address.

### 3.6 Durability and backup

* **The WAL's `fsync`-before-ack had no test that could distinguish it from no
  `fsync` at all.** The old test's own comment pointed at a crash loop that does
  not exist. Now proven by failure injection.
* **A backup omitted the system realm**, so a restore left nobody able to log in.
* **Eleven entity families did not round-trip.** Ten now do — group
  memberships (where group-derived permissions were silently vanishing),
  organisation memberships, consents, agents, IdPs and federation links,
  webhooks, SAML SPs, SCIM mappings, invitations, retiring signing keys.
  Sessions stay out deliberately, and the reason is now written down.
* **`restore` never ran `verify`**, so a checksum-mismatched archive restored
  cleanly.

### 3.7 Cluster

* **A cold multi-node cluster could not start at all.** `serve` wrote the global
  signing key through Raft before any leader existed, so every node exited and
  the bootstrap endpoint was unreachable.
* **The only partition test passed with partitioning hardwired off.** It is real
  now, and the repository has its **first** split-brain test.
* **The cached audit chain head forked the HMAC chain** when leadership flapped.
* **`transfer_leadership` never moved leadership** — three independent faults,
  including a 5-second budget below openraft's own 4.5–6.0 s floor.

### 3.8 The gates themselves

* **`required-summary`'s loop was a denylist** of `failure`/`cancelled` — fail-open
  by construction, since any other result read as fine. Now an allowlist.
* **`make test-quality` was RED at HEAD** and is a merge gate.
* **The mutation spot-check is now a CI job** with four security-critical guards,
  each proven to go red. It found a real gap on first use.

---

## 4. What is still blocking production readiness

Ranked. Only the first is an engineering blocker in the strict sense.

### 4.1 BLOCKER — `arc-swap` on the hot path *(task 26.5, reopened)*

Six files still use it in code: `identity/engine/mod.rs` (realm-status, session
and token-claims caches), `identity/engine/sharded_cache.rs`,
`storage/{memtable,engine,tiered,block_cache}.rs`.

Those are `validate_token`, `lookup_session` and every storage read.

* **No upgrade exists.** 1.9.2 is newest; its `RwLock` strategy is
  `#[cfg(feature = "internal-test-strategies")]` and its own docs say it is not
  for production.
* **A read lock is forbidden there** by `CLAUDE.md`'s hot-path rules.
* **So it needs epoch-based reclamation** — `crossbeam-epoch` is the
  recommendation — which is a new dependency needing a policy justification.

Evidence: `reports/arc-swap-use-after-free-2026-09-21.md`.

**This task was marked done while the fault was live.** The four sites that
moved off the crate were the ones that were never hot. Worth knowing, because it
means the ledger can be wrong in the direction that flatters it.

### 4.2 Cluster mode is not GA

Single-node is unaffected by everything here.

* The repository had **zero** split-brain tests until today; it now has one.
* `transfer_leadership` is a **step-down, not a handover** — openraft 0.9.25 has
  no public API for targeted transfer (`Trigger::transfer_leader` arrived in
  0.10). *(task 26.60)*
* `VISION.md` already calls clustering experimental. That is still the honest
  label.

### 4.3 It cannot pass OIDC certification *(task 26.55 — your decision)*

Not a formality. Signing ID tokens with EdDSA alone fails a condition that
**every** OP certification profile runs, and the assertion has no relaxing
variant. Passing means reversing `CLAUDE.md`'s "Ed25519 only" rule and adding
RSA key generation, rotation and JWKS work.

Measured: 38 conditions passed, 1 failed, 1 warned.

### 4.4 The documented install path does not work *(task 3.4 — needs your browser)*

Both GHCR packages are private. A stranger cannot run the README's own
`docker pull` or `helm install`. Re-verified today: the anonymous token endpoint
returns nothing and the manifest answers 403.

```bash
gh auth refresh -s read:packages,write:packages
gh api --method PATCH /orgs/hearth-auth/packages/container/hearth -f visibility=public
gh api --method PATCH /orgs/hearth-auth/packages/container/charts%2Fhearth -f visibility=public
```

CI keeps it that way afterwards, given a `PACKAGES_ADMIN_TOKEN` secret.

### 4.5 Two SDKs have never published an artifact *(task 26.53)*

* **Kotlin** — root cause found and fixed, **not verified end to end** because it
  needs release credentials. `io.hearth` is a 404 on Maven Central.
* **PHP** — Packagist is registered against a **separate repository** serving
  only `dev-main`, so a tag here reaches it never.

### 4.6 Two standards decisions *(tasks 26.43, 26.56 — yours)*

* Should `/introspect` require a confidential client? The helper is shared with
  `/revoke`, where public clients are legitimate.
* An unregistered discovery parameter costs a permanent conformance warning and
  nothing reads it — but removing it is outward-facing and a normative spec
  mandates it.

I started to "fix" both and stopped after reading *why* the code is shaped that
way. The `/introspect` behaviour is a deliberate timing-oracle defence.

---

## 5. The thing that would actually end this

**There is no written definition of production-ready anywhere in this
repository.** I looked.

That is the real reason it feels endless. Without exit criteria, "production
ready" is whatever the next audit says — and an audit's job is to find things.
There is no state the system can reach that makes an auditor say "stop".

The August audit gave a verdict (*NO-GO on all five deployment shapes*) and
eleven blockers. **You cleared all eleven.** Nobody wrote down what the next
verdict would need, so clearing them produced no visible finish line.

### A concrete proposal

Write the criteria down, per deployment shape, and make them falsifiable. For
example:

**Single-node, self-hosted — ready when:**

1. No known memory-safety fault on any request path. *(blocked by §4.1)*
2. The README's install commands work for someone with no credentials.
   *(blocked by §4.4)*
3. A backup taken by the documented procedure restores to a working system,
   proven by a test that logs in afterwards. *(done today)*
4. Every merge gate has a red case proving it can fail. *(done today)*
5. Every published performance or conformance claim traces to a run in
   `PUBLISHED_FIGURES.md` or a report. *(done today)*
6. A cold first-run from the README works without reading source. *(done, with
   17 findings fixed)*

**Multi-node — additionally:**

7. A split-brain test and a partition test that both fail when the property
   breaks. *(done today)*
8. Failover exercised over the real transport. *(done today)*
9. Leadership handover works, or the documentation says it does not.
   *(the second, today)*

**Certified — additionally:**

10. An OIDC certification profile passes. *(blocked by §4.3)*

On that list, single-node is **two items** from ready, and both are named
above. One needs a dependency decision; the other needs three commands in a
browser.

That is a much shorter distance than "331 tasks" suggests — and it is the
distance you have actually been closing.

---

## 6. Appendix — today's numbers

| | |
|---|---|
| Backlog | 324 done, 7 open (was 270 total this morning) |
| Commits | 88 |
| Reports written | 12 |
| Test suite | 5538 passed, 0 failed, 14 skipped |
| `clippy --workspace --all-targets -D warnings` | clean |
| `cargo fmt --check` | clean |
| `make test-quality` | 0 violations |
| Red-test gate | 6 rules, all passing, each with a red case |
| Mutation spot-check | 4 guards, 4 proven red under mutation |
| Vacuous proofs caught by running the mutation | 3 |

The last row is the one I would keep. Three tests that looked green were proving
nothing, and each was caught by deleting the guard and watching what happened —
not by reading the test.
