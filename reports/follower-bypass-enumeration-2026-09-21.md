# What a follower does not see

Task 24.6 (audit 2026-08-28 §4.1 objection, §4.15#6, §4.16#5, §4.19#12, §9 item 5).

The audit's own note said "two accepted pieces found four, including two
kill-switches and key rotation, against a known-defects list naming two caches".
**The real count is five, not four.** Four were live when this pass started;
the fifth, key rotation, was closed by task 18.7. The fourth live one — the
session cache — was found only while fixing the first three, because the test
for revocation kept failing after the revocation path itself was fixed.

All four are now closed by one replicated control epoch (see **Fix**).

## How to read this

`serve` **always** installs a `ClusterStorageAdapter`, so every `self.storage`
write is a Raft command that reaches every node. Process-local state is
therefore only dangerous when it is **authoritative** — when a cache MISS is
treated as a decision rather than as a reason to go and look.

That is the whole test:

| Shape | Safe? |
|---|---|
| Cache miss falls through to storage | Safe. The cache is an accelerator. |
| Cache miss means "allow" | **Bypass.** The follower never learns. |
| Cache miss means "deny" | Safe but slow. Fails closed. |

The hot path forbids a storage read (no syscalls, no locks, no `.await`), so a
fall-through is not available to the three entries below. They need the
**replicated-epoch** pattern that task 18.7 already built for signing keys: an
ordinary storage row under the system realm, bumped by the mutating node,
observed by every other node on its next read, which then drops its caches.

## Live bypasses

### B-1 — realm suspend and archive (`realm_status_cache`)

`src/identity/engine/mod.rs:584` declares it; `populate_realm_status_cache`
(:1534) fills it **once at startup**; four `rcu` call sites (:5935, :6097,
:6191, :6322) update it on whichever node served the status change.

The read is at :8194, on the token-validation path, and its own comment says
absence "fail-open matches the original behavior".

**Failure scenario.** An operator suspends a compromised tenant on node A.
The realm row replicates, so node B's storage agrees the realm is suspended.
Node B's `realm_status_cache` still says `Active`, because nothing on node B
ran an `rcu`. Node B keeps validating that realm's tokens until it restarts.
Suspension is a kill-switch; it does not work on any node but the one that
received the request.

### B-2 — token revocation (`revoked_jti_cache`)

`src/identity/engine/mod.rs:808` declares it. `is_token_jti_revoked` (:4758-4773)
reads **only** the cache — there is no storage fallback on any branch.

**Failure scenario.** `POST /revoke` on node A writes `oauth:revjti:<jti>`
(replicates) and inserts into node A's cache. Node B never inserts. Node B
keeps accepting the revoked token for the rest of its lifetime. The durable
row is right there in node B's own storage and nothing reads it until the next
start-up scan.

Note this is the *same* endpoint that, until commit `cd1ccbaa`, also reported
success when the write failed. The two defects compounded: a client could be
told a token was dead when it was neither written nor propagated.

### B-3 — DPoP key blocklist (`blocked_dpop_jkt_cache`)

`src/identity/engine/mod.rs:794` declares it; `populate_blocked_dpop_jkt_cache`
(:1632) fills it **once at startup**; insert at :1703 and remove at :1721 run on
the serving node only. The read is at :8228, on the token-validation hot path,
and its own comment confirms the shape: "single atomic `load()`, no syscall".
A miss means "not blocked", so it allows.

**Failure scenario.** An operator blocks a stolen DPoP key on node A. Node B
keeps honouring proofs signed with that key until it restarts. This is the
second of the two kill-switches the audit named.

### B-4 — session revocation (`session_cache`)

Found while fixing B-2, not by the sweep: the revocation test stayed red after
the revoked-identifier cache was propagating correctly.

`lookup_session` (:3885) returns a **cached live session without consulting
storage** — the comment says so: "Hot path: check the in-process session cache
(zero I/O, one atomic load)". Only the miss path reads storage.

**Failure scenario.** Revoking a session on node A, or disabling a user (which
enforces the disable *by* revoking their sessions), leaves node B returning that
session as live from its own cache. Access tokens embed their claims at issue
time, so session revocation is the only thing that enforces a disable at all.

This is also why B-2's fix was not enough on its own: revoking an access token
that carries a session id goes through the session, never through the
revoked-identifier blocklist.

## Already covered

| State | Cover |
|---|---|
| `realm_signing_keys` (:547) | Task 18.7 — `realm_key_epoch` (:577), `sync_realm_key_epoch` (:4425) |
| `realm_retiring_keys` (:563) | Same epoch |
| `token_claims_cache` (:762) | Flushed by the same epoch sync, plus its own generation counter (:4347) |

## Per-node by design — NOT defects

These are process-local and should stay that way. Recording them so a future
sweep does not "fix" them into a distributed-coordination problem.

| State | Why per-node is right |
|---|---|
| `session_limit_locks`, `jti_locks`, `token_redemption_locks`, `approval_locks`, `txn_locks`, `code_exchange_locks`, `grant_family_locks` | In-process mutexes that serialise a read-modify-write. Cross-node atomicity comes from `put_if_absent` through the cluster adapter, not from these. |
| `attempt_trackers`, `mfa_attempt_trackers`, `magic_link_rate_trackers`, `password_reset_rate_trackers`, `registration_email_rate_trackers`, `ip_login_rate_trackers` | Rate limiting. Six families rehydrate from the WAL at boot (`restore_attempt_trackers_from_wal`); task 20.16 documents which. Per-node counting is a weaker limit, not a bypass. |
| `registration_ip_rate_trackers` | The one family that is memory-only, documented as such by 20.16. |
| `mfa_dek_cache`, `dpop_nonce_cache`, `realm_saml_keys` | Key material derived from replicated rows. A miss re-derives; it does not decide. |

## Fix

**Implemented.** One `u64` row, `sys:control:epoch`, under the system realm.
Bumped by realm status change, token revocation, session revocation and DPoP
key blocking. Observed at the top of `validate_token`, which then reloads the
realm-status, revoked-identifier and DPoP caches and drops the session and
claims caches. It replicates with the rows it describes, so it needs no new
transport, and it is a plain storage row rather than a `StorageEngine` trait
default — a default would silently no-op, because `serve` always installs a
`ClusterStorageAdapter`.

**One placement detail that cost a debugging cycle.** The sync must run BEFORE
the token-claims cache lookup, not inside signature verification where the
signing-key epoch's sync sits. A warm claims-cache hit returns without ever
reaching verification — which is exactly the case where the token is most
likely to be one an operator has just revoked. The key epoch had the same hole;
both are now reconciled at the entry point.

**Cost.** One small storage read per validation, which finds the epoch
unchanged and returns. On an actual bump, the reload is a full repopulate: two
of the three caches are bounded by realm and blocklist size, and the revoked
identifiers are not, so a revocation elsewhere costs this node one blocklist
scan. Revocations are rare relative to validations, and the alternative — a
storage read per validation on the hot path — is forbidden.
