# RFC: Session-Version (`sv`) Revocation Hybrid

**Issue:** HEA-930  
**Status:** Draft  
**Author:** CTO  
**Date:** 2026-05-28

---

## 1. Problem

Hearth's `embedded` token mode ([HEA-921](../issues/HEA-921)) validates access tokens locally — zero network hops, sub-millisecond verification. The cost is eventual consistency: a revoked session (logout, admin revoke, password change, role/group change) does not immediately invalidate tokens already in the wild. Tokens remain valid until expiry (typically 15–60 min).

This is acceptable for most use cases but fails hard for high-sensitivity scenarios:
- Immediate logout (user or admin-initiated).
- Compromised-credential response: admin revokes a session and needs the attacker locked out in seconds, not minutes.
- Role change that narrows permissions: a demoted user should not hold elevated permissions for the remainder of their token's lifetime.

The current escape hatch (`access_token_authorization: introspection`) fixes this by calling Hearth per-request, but that re-introduces a network hop and creates a Hearth availability dependency on every API request.

**Goal:** sub-second revocation freshness for `embedded` mode, with no per-request network hop.

---

## 2. Concept

Add a `sv` (session-version, `u64`) claim to issued JWTs. Maintain a server-side `current_version[session_id]` map. Resource servers locally cache a `min_version[session_id]` map refreshed by polling (or subscribing to) a compact delta feed. Token validation is:

```
valid = sig_ok(token) && token.sv >= local_min_version[token.sid]
```

Revocation increments the server's `current_version`; the delta feed propagates the increment to resource servers within the poll interval. Tokens whose `sv` is below the current min are rejected without any call to Hearth.

The freshness window is the poll/push interval, configurable per resource server (default: 5 s). Compare: `introspection` mode has a 0 s window but a per-request cost; `embedded` mode has a ∞ window with no per-request cost; `sv` mode sits between them.

---

## 3. Claim shape

### 3.1 New JWT field

```json
{
  "sub": "user_01HXYZ...",
  "sid": "sess_01HGHI...",
  "sv":  7,
  "exp": 1700000900,
  ...
}
```

- `sv` is a monotonically-increasing `u64`, starting at `1` when a session is created.
- `sv` is always present in access tokens issued while `sv` tracking is enabled (realm config flag).
- `sv` is NOT present in client-credentials tokens (those are sessionless).
- `sv` is NOT present in refresh tokens — refresh tokens are single-use and rotation-validated independently.

### 3.2 Semantics

A token is **session-version valid** iff:

```
sv_in_token >= min_accepted_sv[session_id]
```

Where `min_accepted_sv` is the cached minimum acceptable version held by the resource server. Initial value = `1` (every session starts at version 1, so any `sv ≥ 1` is valid until a bump occurs).

`min_accepted_sv[session_id]` is set to `current_sv[session_id] + 1` after a revocation-triggering event, effectively invalidating all tokens that carried the previous version.

---

## 4. Bump triggers

The session version is incremented on:

| Event | Bump? | Notes |
|-------|-------|-------|
| Logout (user-initiated) | Yes | Session is also invalidated; `sv` bump ensures in-flight tokens are rejected before they expire |
| Admin session revoke | Yes | Same as logout |
| Password change | Yes | Existing sessions across all devices should lose trust |
| Role assignment change | Yes | Permission set in existing token may now be incorrect |
| Group membership change | Yes | Same |
| MFA step-up completion | No | Step-up promotes the session to a higher AMR level; `sv` is not the right lever here — a new token with updated claims is issued instead |
| Email change | No | No security impact on existing sessions |
| Token refresh | No | Refresh issues a new token with the current `sv`; no bump needed |

Bumping does NOT terminate the session record or invalidate refresh tokens — those are separate mechanisms. The `sv` bump only causes resource servers to reject tokens carrying the old version.

---

## 5. Storage key layout

Session-version state lives in the `ssv:` prefix namespace, separate from session records (`ses:`).

```
ssv:{realm_id}:{session_id}  →  u64 (current version, WAL-backed)
ssv:{realm_id}:seq           →  u64 (global monotonic bump sequence, used by delta feed)
ssv:{realm_id}:delta:{seq:020}  →  {session_id, new_min_sv, bumped_at}
```

**Rationale:**
- Separating `ssv:` from `ses:` keeps the hot-path session lookup unaffected.
- The `delta:` log is append-only and size-bounded: entries expire after `max_token_ttl` (resource servers holding older versions would have seen those tokens expire anyway).
- `seq` is a realm-scoped monotonic counter, not a global one, to preserve multi-tenancy isolation.

**Delta entry shape (CBOR/JSON):**
```json
{
  "seq":         14201,
  "session_id":  "sess_01HGHI...",
  "min_sv":      8,
  "bumped_at":   1700000900
}
```

---

## 6. Delta feed wire format

### 6.1 Endpoint

```
GET /oauth/session-versions?since=<seq>&realm=<realm_id>
Authorization: Bearer <resource-server-token>
```

- `since` — the last sequence number the caller has seen (exclusive). First call uses `since=0`.
- Returns all delta entries with `seq > since`, up to a configurable page size (default: 1000).
- Response includes `next_seq` for the caller to use on the next poll.

**Response 200:**
```json
{
  "realm":    "<realm_id>",
  "next_seq": 14205,
  "deltas": [
    { "seq": 14201, "session_id": "sess_...", "min_sv": 8,  "bumped_at": 1700000900 },
    { "seq": 14202, "session_id": "sess_...", "min_sv": 3,  "bumped_at": 1700000901 }
  ]
}
```

**Response 204:** No new deltas since the given `since` value.

**Response 400:** `since` references a sequence older than the retention window → resource server must flush its cache and re-fetch the current snapshot.

### 6.2 Snapshot endpoint (for cache recovery)

```
GET /oauth/session-versions/snapshot?realm=<realm_id>
```

Returns the complete `{session_id → min_sv}` map for the realm at the current instant, plus `current_seq`. Used on resource server startup or after a stale-poll error.

**Response 200:**
```json
{
  "realm":       "<realm_id>",
  "current_seq": 14205,
  "versions": {
    "sess_01...": 1,
    "sess_02...": 8
  }
}
```

The snapshot may be large for high-session-count realms. Gzip compression is mandatory for this endpoint.

### 6.3 Authorization

Resource servers authenticate to these endpoints with a **service-to-service access token** scoped to `hearth.sv_feed` permission. This is a new reserved permission, not granted to regular user roles.

---

## 7. Push vs. pull tradeoff

| | Pull (polling) | Push (SSE/WebSocket) |
|-|----------------|----------------------|
| Complexity | Low — stateless HTTP | Medium — connection lifecycle |
| Freshness | Bounded by poll interval | Near-real-time |
| Fault tolerance | Missed polls retry automatically | Reconnect logic required |
| Back-pressure | Implicit (poller sets its own pace) | Must be explicit |
| Firewall/proxy compat | High | Medium (SSE requires persistent connection) |
| Hearth server load | Predictable (N pollers × 1 RPS each) | Unpredictable fan-out on burst revoke |

**Decision: start with polling; add SSE as an opt-in upgrade.**

Polling with a 5 s interval satisfies the "sub-second" goal only if we define the SLA as "revocation reflected within N seconds on the resource server side, where N is configurable by the resource server operator." The default 5 s is a reasonable balance. Operators requiring tighter windows (1 s) can configure more aggressive polling at higher Hearth load cost.

SSE (`GET /oauth/session-versions/stream?realm=<realm_id>`) is deferred to a follow-on issue. The polling architecture is a superset: any resource server can switch from polling to SSE without changing its local min-version cache logic.

---

## 8. Resource server validation flow

```
incoming request → extract bearer token
    ↓
jwt_verify(token.signature, realm_jwks)  ← existing
    ↓ OK
check token.exp > now                    ← existing
    ↓ OK
if token.sv is present:
    min = local_cache.get(token.sid)    ← HashMap lookup, ~10 ns
    if token.sv < min:
        → 401 Unauthorized ("token_revoked")
    ↓ OK
    if local_cache.age > stale_threshold:
        → 401 Unauthorized ("session_version_cache_stale") OR
          fallback_to_introspection()   ← operator choice
check token.permissions                  ← existing
```

### 8.1 Fail-closed behavior

If the resource server's version cache has not been refreshed within `stale_threshold` (default: 60 s), it MUST either:
- Reject all sv-bearing tokens with `session_version_cache_stale` error, OR
- Fall back to per-request introspection (the `decision` mode from HEA-921).

This is the **fail-closed guarantee**: a resource server that cannot reach Hearth does not silently degrade to stale-embedded behavior indefinitely.

The `stale_threshold` MUST be > the poll interval to avoid flapping. Recommended: `stale_threshold = poll_interval × 3`.

### 8.2 Tokens without `sv`

Tokens issued by Hearth instances that predate the `sv` feature, or where `sv` tracking is disabled, will not carry an `sv` claim. Resource servers MUST treat absent `sv` as: skip the session-version check entirely. This maintains backward compatibility.

---

## 9. DPoP interaction

DPoP (Demonstrating Proof of Possession, RFC 9449) binds a token to a client's ephemeral key pair. The `sv` claim is part of the signed JWT payload and is therefore covered by the Ed25519 signature that DPoP verification already validates. No additional interaction required — DPoP and `sv` compose transparently.

---

## 10. MFA / step-up interaction

Step-up authentication issues a **new token** with updated `amr` claims rather than mutating the existing session's `sv`. This is intentional: step-up is an upgrade (adding authentication factors), not a revocation event. The new token carries the same `sv` as the current session version — it just has enriched `amr`. If an operator wants to force re-authentication of all existing tokens after adding MFA, they can bump `sv` explicitly via the admin API (see § 11.1).

---

## 11. Admin API surface

### 11.1 Manual bump

```
POST /admin/sessions/{session_id}/sv-bump
Authorization: Bearer <admin-token>
X-Realm-ID: <realm_id>
```

Increments `current_sv[session_id]` by 1 and appends to the delta log. Returns `{"new_min_sv": <n>}`. Used for emergency revocation of a specific session without full session termination.

### 11.2 Realm-wide bump (not-before analog)

```
POST /admin/realms/{realm_id}/sv-bump-all
Authorization: Bearer <admin-token>
```

Bumps every active session in the realm. Analogous to Keycloak's not-before policy. Response includes count of affected sessions. This is a heavy operation; it generates O(active_sessions) delta entries.

---

## 12. Realm config flag

```yaml
realms:
  acme:
    session_version:
      enabled: true
      delta_retention_seconds: 3600   # keep deltas for 1 hour
      snapshot_compression: gzip      # required for snapshot endpoint
```

When `enabled: false` (default for backward compat), no `sv` claim is added, no delta log is written, and the delta feed endpoints return 404. Operators opt-in per realm.

---

## 13. SDK changes (sketch — detailed in child issues)

```ts
// SDK initialization gains an optional sv cache config
const hearth = createHearth({
  baseUrl: "...",
  realmId: "...",
  getToken: () => currentAccessToken,
  sessionVersions: {
    enabled: true,
    pollIntervalMs: 5000,
    staleThresholdMs: 60000,
    onStale: "reject",  // "reject" | "introspect"
  },
});
```

SDKs that enable `sessionVersions` MUST:
1. Fetch the snapshot on startup.
2. Poll `/oauth/session-versions?since=<seq>` at `pollIntervalMs` intervals.
3. Apply delta entries to the local `HashMap<SessionId, u64>`.
4. On `hasPermission` / token verification calls, apply the sv check from § 8.
5. Expose `hearth.sessionVersionCacheAge()` for health checks.

Go SDK uses the same shape via a `SessionVersionConfig` struct.

---

## 14. Open questions (resolved below)

| Question | Resolution |
|----------|------------|
| Use `u64` or `u32` for `sv`? | `u64` — overflow is a correctness hazard; 64-bit costs nothing in JSON |
| Retention window size? | Default 1 hour (== typical max token TTL); configurable |
| Snapshot compression? | gzip mandatory; Brotli optional |
| Per-session or per-user bump? | Per-session (granular); per-user is "bump all sessions for user", a convenience wrapper |
| Impact on JWT size? | ~8 bytes per token (`"sv":7,`) — negligible |
| Push (SSE) in scope for this RFC? | No — deferred to follow-on issue |

---

## 15. Acceptance criteria for implementation child issues

### Server (HEA-930-server)
- [ ] `sv` claim emitted in access tokens when `session_version.enabled = true`.
- [ ] Version bumped on: logout, admin revoke, password change, role assignment change, group membership change.
- [ ] Delta log append-only, WAL-backed, TTL-expired.
- [ ] `GET /oauth/session-versions` delta feed endpoint.
- [ ] `GET /oauth/session-versions/snapshot` snapshot endpoint (gzip).
- [ ] `POST /admin/sessions/{id}/sv-bump` and `POST /admin/realms/{id}/sv-bump-all`.
- [ ] `hearth.sv_feed` permission seeded in realm bootstrap.
- [ ] All bump triggers covered by integration tests.
- [ ] Realm config `session_version.enabled` gate implemented.

### Per-SDK (HEA-930-sdk)
- [ ] TS SDK: `sessionVersions` config block, poll loop, cache, sv check on token validation.
- [ ] Go SDK: equivalent `SessionVersionConfig`, poll goroutine, cache, sv check.
- [ ] Fail-closed: `stale_threshold` exceeded → `reject` or `introspect` path.
- [ ] Unit tests with mocked delta feed (no live server).
- [ ] Integration test: bump session version → resource server rejects old token within poll interval.

### Docs (HEA-930-docs)
- [ ] `AUTHORIZATION.md` § 15 Future Work section updated (this RFC merged).
- [ ] Operator guide: when to enable `sv`, polling config, stale threshold tradeoffs.
- [ ] `CHANGELOG.md` entry.

---

## 16. Prior art

- **Keycloak not-before policy**: per-realm, per-client, per-user timestamp floors. Similar idea but coarser-grained (time-based, not per-session versioned).
- **CAEP / Shared Signals Framework** (OpenID): push-based event stream for security events including session revocation. Heavier protocol; designed for identity provider → identity provider federation.
- **Google's `iam.serviceAccounts.signJwt` + access-bound tokens**: access-token binding to a session context with fast invalidation via a comparable version check.
- **Stripe's bounded JWTs**: all Stripe API tokens embed an epoch; revocation bumps the epoch, fast-invalidating the entire cohort without per-token tracking.
