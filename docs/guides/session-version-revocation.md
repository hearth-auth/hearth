# Session-version (`sv`) revocation

**Audience:** operators configuring sub-TTL revocation freshness for resource servers using
`embedded` token mode.

Hearth's default `embedded` mode validates access tokens entirely in-process — zero network
hops, sub-microsecond verification. The trade-off is eventual consistency: a revoked session
stops issuing new tokens immediately, but access tokens already issued remain valid until
they expire (typically 15–60 min, governed by `access_token_ttl`).

Session-version revocation closes that window. When enabled, every access token carries an
`sv` (session-version) claim. Resource servers maintain a local `min_version[session_id]`
cache refreshed by background polling. Revocation increments the server-side version;
resource servers reject tokens whose `sv` is below the cached minimum — no network hop
required on the hot path.

---

## When to enable

Enable `session_version` when:

| Scenario | Use sv? |
|---|---|
| Any in-flight token must be invalidated in seconds, not minutes | **Yes** |
| Compromised-credential response (admin revokes, attacker must lose access fast) | **Yes** |
| Role demotion must take effect before the token expires | **Yes** |
| You can tolerate stale permissions up to `access_token_ttl` | No — keep default `embedded` |
| `introspection` mode is already in use (per-request network call) | No — sv adds no value |
| Tokens are client-credentials (sessionless) | No — `sv` is never emitted for client-credentials tokens |

If you only need immediate revocation for a small fraction of sessions, the
`POST /admin/sessions/{id}/sv-bump` endpoint lets you bump a single session on demand
without enabling the feature realm-wide.

---

## Quick-start: enabling sv for a realm

Add to `hearth.yaml` (or realm config):

```yaml
realms:
  acme:
    session_version:
      enabled: true
      delta_retention_seconds: 3600   # keep delta entries for 1 hour (default)
```

When `enabled: true`:
- All new access tokens issued for this realm carry an `sv` claim.
- The delta feed endpoints (`/oauth/session-versions`) become active.
- The `hearth.sv_feed` permission is seeded automatically via `seed_realm` and must be
  granted to any service account that polls the delta feed.

When `enabled: false` (the default), no `sv` claim is added and the delta feed endpoints
return 404. Tokens issued while disabled have no `sv` claim; resource servers skip the
version check for those tokens transparently.

---

## Poll interval and stale threshold tradeoffs

```
Revocation window  ≈  poll_interval_ms
False-rejection risk  starts at  stale_threshold_ms
```

SDK configuration (TypeScript example):

```typescript
const hearth = createHearth({
  baseUrl: "https://auth.example.com",
  realmId: "acme",
  getToken: () => currentAccessToken,
  sessionVersions: {
    enabled: true,
    pollIntervalMs: 5000,       // fetch deltas every 5 s
    staleThresholdMs: 60000,    // reject sv tokens if cache > 60 s old
    onStale: "reject",          // "reject" | "introspect"
  },
});
```

Go SDK:

```go
client := hearth.NewClient(hearth.ClientConfig{
    BaseURL: "https://auth.example.com",
    RealmID: "acme",
    SessionVersions: &hearth.SessionVersionConfig{
        Enabled:          true,
        PollInterval:     5 * time.Second,
        StaleThreshold:   60 * time.Second,
        OnStale:          hearth.OnStaleReject,
    },
})
```

### Choosing values

| Parameter | Guidance |
|---|---|
| `pollIntervalMs` | Set to your required revocation window. 5 s is a good default. Lower values increase Hearth load linearly (N pollers × 1 RPS each). |
| `staleThresholdMs` | **Must be > `pollIntervalMs`.** Recommended: `pollIntervalMs × 3`. Too small → spurious rejections on brief Hearth hiccups. Too large → stale cache extends the revocation window. |
| `onStale` | `"reject"` is the safe default. Use `"introspect"` only if your service can tolerate the fallback latency and has a live path to Hearth. |
| `delta_retention_seconds` | Match or exceed `access_token_ttl`. A resource server holding a cache older than the retention window will receive a 400 from the delta feed and must fetch a fresh snapshot. Default 3600 s (1 hour) is safe for typical 15–60 min token TTLs. |

---

## Bump trigger table

The session version is incremented automatically on:

| Trigger | Bumped? | Notes |
|---|---|---|
| User-initiated logout | Yes | Session also invalidated; bump ensures in-flight tokens are rejected before expiry |
| Admin session revoke | Yes | Same effect as logout |
| Password change | Yes | All existing sessions across devices lose trust |
| Role assignment added or removed | Yes | Token may carry stale permissions |
| Group membership added or removed | Yes | Token may carry stale permissions |
| MFA step-up completion | No | Step-up issues a new token with updated `amr` claims; existing sessions are not revoked |
| Email change | No | No security impact on existing sessions |
| Token refresh | No | Refresh issues a new token carrying the current `sv`; no bump needed |
| DPoP key rotation | No | DPoP binding is verified separately; `sv` is unaffected |

---

## The `sv-bump-all` use case

`POST /admin/realms/{realm_id}/sv-bump-all` increments every tracked session in the realm
simultaneously. This is analogous to Keycloak's not-before policy and is appropriate for:

- **Credential breach response**: immediately invalidate all active sessions realm-wide.
- **Forced re-authentication after policy change**: e.g., MFA enforcement rollout — after
  enabling mandatory MFA, bumping all sessions forces users to re-authenticate through the
  new MFA-required flow.
- **Key rotation evacuation**: if a signing key is compromised, bump-all ensures no
  outstanding tokens with that key can be used even before the key is rotated out of the
  JWKS.

The endpoint returns `{"affected": <count>}`. It generates O(active_sessions) delta entries;
resource servers will pick them up on their next poll cycle.

> **Warning:** bump-all triggers a wave of re-authentications. In production, consider
> bumping a small test cohort first and monitoring error rates before applying realm-wide.

---

## Fail-closed behavior

If a resource server's version cache has not been refreshed within `stale_threshold`, the
SDK **must not silently fall back** to treating all tokens as valid. Two behaviors are
available:

### `onStale: "reject"` (default, recommended)

All sv-bearing tokens are rejected with a `session_version_cache_stale` error until the
cache is refreshed. Resource servers return `401` to callers. Sessions resume automatically
once polling recovers.

This is the **fail-closed** guarantee: a network partition between the resource server and
Hearth does not silently grant access to potentially-revoked tokens.

### `onStale: "introspect"`

The SDK falls back to per-request introspection calls (`POST /realms/{realm}/introspect`).
This restores the security guarantee at the cost of re-introducing network hops.

Use this only when:
- Your service's SLA tolerates the introspection latency (p99 < 500 μs on-LAN).
- A graceful degradation path is preferred over hard 401s during brief Hearth maintenance.

**Never** set `stale_threshold` equal to or less than `poll_interval`. This causes
the cache to appear stale on the first missed poll, triggering spurious errors.

---

## DPoP interaction

DPoP (RFC 9449) binds a token to an ephemeral client key pair. The `sv` claim is part of
the signed JWT payload and is therefore covered by the Ed25519 signature that DPoP
verification already validates. DPoP and `sv` compose transparently — no additional
configuration is needed on either the server or the resource server.

---

## MFA / step-up interaction

Step-up authentication issues a **new token** with updated `amr` (Authentication Methods
Reference) claims — it does not bump `sv`. This is intentional: step-up is an upgrade, not
a revocation event. The new token carries the same `sv` as the current session version.

If you want to force re-authentication of all existing tokens after enabling MFA for a
realm, use `sv-bump-all` (see above). This invalidates the pre-MFA tokens without
terminating session records, so users are prompted to log in through the new MFA flow on
their next request.

---

## Delta feed reference

Resource servers use two endpoints to maintain their version cache:

### Delta feed (incremental)

```
GET /oauth/session-versions?realm=<realm_id>&since=<seq>
Authorization: Bearer <service-account-token with hearth.sv_feed>
```

- `since` — last sequence number seen (exclusive). Use `0` on first call.
- Returns up to 1000 delta entries with `seq > since` and the `next_seq` to use on the next
  call. Returns 204 when no new deltas exist.
- Returns 400 when `since` is older than the retention window — resource server must
  re-fetch the snapshot.

### Snapshot (startup / recovery)

```
GET /oauth/session-versions/snapshot?realm=<realm_id>
Authorization: Bearer <service-account-token with hearth.sv_feed>
```

Returns the complete `{session_id → min_sv}` map for the realm at the current instant,
gzip-compressed. Use on:
- Resource server startup (before the first poll).
- After receiving a 400 from the delta feed (cache too stale to recover incrementally).

The snapshot may be large for realms with many active sessions. The SDK handles
snapshot fetching automatically; you do not need to call this endpoint directly.

---

## Admin bump endpoints

| Endpoint | Effect |
|---|---|
| `POST /admin/sessions/{id}/sv-bump` | Increment `sv` for a single session |
| `POST /admin/realms/{id}/sv-bump-all` | Increment `sv` for every tracked session in the realm |

Both require `hearth.admin` permission. `sv-bump` returns `{"new_min_sv": <n>}`.
`sv-bump-all` returns `{"affected": <count>}`.

---

## Monitoring

Expose `hearth.sessionVersionCacheAge()` (TS) or `client.SessionVersionCacheAge()` (Go)
in your health-check endpoint. Alert when the cache age exceeds `pollIntervalMs × 2`.

An age exceeding `staleThresholdMs` means sv-bearing tokens are currently being rejected
(or introspection fallback is active, depending on `onStale`). This is a hard availability
signal, not a soft warning.

---

## See also

- [`SESSION_VERSION_RFC.md`](../specs/SESSION_VERSION_RFC.md) — full design rationale,
  storage key layout, push vs. pull tradeoff analysis, claim shape.
- [`AUTHORIZATION.md § 14`](../specs/AUTHORIZATION.md#14-session-version-sv-revocation) —
  normative spec for `sv` claim semantics and fail-closed contract.
- [`permission-delivery.md`](./permission-delivery.md) — choosing between `embedded`,
  `introspection`, and `decision` modes.
