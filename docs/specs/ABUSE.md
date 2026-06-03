# Hearth Abuse Prevention — Normative Specification

**Status:** Active  
**Parent plan:** HEA-1114 (`docs/plans/HEA-1114-abuse-prevention.md`)  
**Revision:** 1 (foundation, plan phase A/D-1)

---

## 1. Purpose

This document is the normative specification for Hearth's abuse-prevention plane. It governs:

- The `AbusePolicy` trait contract.
- The `AbuseGuard` middleware wiring.
- The YAML configuration surface.
- Fail-open vs fail-closed behaviour.
- The threat model this plane is designed to address.

All implementations MUST comply with this document. Implementations SHOULD be independently verifiable against the test scenarios in `docs/specs/TEST_SCENARIOS.md`.

---

## 2. Threat Model

The abuse-prevention plane addresses **volumetric and pattern-based attacks** against the authentication API surface. Specifically:

| Threat | Description | Target endpoints |
|--------|-------------|-----------------|
| **Credential stuffing** | Automated replay of breached username/password pairs | `/token`, `/authorize` |
| **Password spraying** | Low-rate guessing across many accounts | `/token`, `/authorize` |
| **Token endpoint flooding** | High-rate client-credentials or device-flow requests | `/token`, `/device_authorization` |
| **Registration abuse** | Automated account creation at scale | `/users`, `/register` |
| **Enumeration** | Timing or error-code fingerprinting of valid accounts | All authenticated endpoints |

**Out of scope for this plane:** application-layer DDOS (handled by upstream WAF/L4), JWT forgery (handled by `storage/` signing), permission escalation (handled by `rbac/`).

---

## 3. Fail-Open vs Fail-Closed

### 3.1 Default: Fail-Open

The default behaviour is **fail-open**: if the abuse guard cannot evaluate a policy (missing realm header, internal error, unconfigured policy), it MUST allow the request to proceed.

**Rationale:** The abuse plane is a defense-in-depth layer. Making it a hard availability dependency would allow a misconfiguration or transient error to take down the authentication service entirely. Availability is prioritised over marginal security improvement at this layer.

### 3.2 Opt-In: Fail-Closed

Individual realms may opt into fail-closed mode via `abuse.fail_closed: true` in their YAML configuration. In fail-closed mode:

- A policy evaluation error MUST block the request with `429 Too Many Requests`.
- The response body MUST NOT reveal the reason for the block.
- The reason MUST be logged at `WARN` level with realm ID and client IP.

### 3.3 Unauthenticated Endpoints

Endpoints that carry no `X-Realm-ID` header (e.g. `/health`, `/readyz`, `/jwks`, `/.well-known/openid-configuration`) are **always** allowed through, regardless of fail-closed configuration. The guard short-circuits to `Allow` when no realm can be identified.

---

## 4. `AbusePolicy` Trait Contract

```rust
pub trait AbusePolicy: Send + Sync {
    fn check(&self, req: &AbuseRequest<'_>) -> AbuseDecision;
}
```

### 4.1 Invariants

All `AbusePolicy` implementations MUST satisfy:

| Rule | Rationale |
|------|-----------|
| **Synchronous** — MUST NOT `.await` | Enforces hot-path compliance |
| **Zero heap allocation** — MUST NOT call `Box::new`, `Vec::new`, `format!`, etc. | Hot path budget ≤ 5 µs p99 |
| **No syscalls** — MUST NOT read files, sockets, or memory-mapped regions | Hot path budget |
| **No locks on read path** — MUST NOT acquire mutexes or write-locks | Hot path budget |
| **Deterministic** — same `AbuseRequest` MUST produce the same `AbuseDecision` | Testability |
| **Total** — MUST NOT panic or return an error; embed errors in `AbuseDecision` | Safety |

### 4.2 `AbuseDecision`

```rust
pub enum AbuseDecision {
    Allow,
    Block   { reason: &'static str },
    Challenge { reason: &'static str },
}
```

- `Allow` — request proceeds to the next middleware.
- `Block` — request is rejected with `429 Too Many Requests`. Reason is logged, not returned to caller.
- `Challenge` — semantically equivalent to `Block` at the transport layer in this phase. Reserved for future step-up authentication flows.

The `reason` field MUST be a `&'static str` string literal from a controlled table. It MUST NOT contain user-controlled input or PII.

### 4.3 `AbuseRequest`

```rust
pub struct AbuseRequest<'a> {
    pub realm_id: &'a RealmId,
    pub client_ip: IpAddr,
    pub endpoint:  &'static str,
}
```

The `endpoint` field is a normalised label (e.g. `"token"`, `"authorize"`) mapped from the axum `MatchedPath`. It is always a `&'static str` from the `abuse_endpoint_label` table.

---

## 5. `AbuseGuard` Middleware

### 5.1 HTTP

The `abuse_guard` axum middleware is applied as a `route_layer` **before** `track_metrics`:

```
request
  └─ abuse_guard (route_layer)
       └─ track_metrics (route_layer)
            └─ TraceLayer (layer)
                 └─ route handler
```

Because it is a `route_layer`, it runs only for matched routes — not for 404 fallbacks.

**Extraction order:**
1. `X-Realm-ID` header → parsed as UUID → `RealmId::new()`.
2. `ConnectInfo<SocketAddr>` extension → client IP. Falls back to `127.0.0.1:0` when unavailable (test harnesses, proxy modes without connect-info).
3. `MatchedPath` extension → normalised endpoint label via `abuse_endpoint_label()`.

**Response on block:**
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"error":"too_many_requests","error_description":"Request rate limited."}
```

### 5.2 gRPC

`GrpcState` carries `abuse: Arc<dyn AbusePolicy>` (defaults to `NoopAbusePolicy`). Service-level gRPC interceptors may call `guard_check()` using metadata headers for per-call enforcement. Full gRPC middleware wiring is a follow-up phase.

---

## 6. YAML Configuration

### 6.1 Schema

```yaml
realms:
  <realm-slug>:
    abuse:
      enabled: true        # default: true when block present; opt-in for existing realms
      fail_closed: false   # default: false (fail-open)
```

### 6.2 Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable abuse-prevention checks for this realm. When `false`, the guard skips the check entirely (noop bypass). |
| `fail_closed` | bool | `false` | When `true`, policy evaluation errors block the request. When `false`, errors allow the request through. |

### 6.3 Backward Compatibility

Realms that do **not** include an `abuse:` block in their YAML (`Option<AbuseYaml> = None`) are treated as **not enrolled**. No enforcement is applied. This preserves backward compatibility for existing realm configurations.

New realms created via YAML after this feature ships SHOULD include `abuse: { enabled: true }` for immediate protection.

---

## 7. Hot-Path Budget

The hot-path budget for `AbuseGuard.check()` is **≤ 5 µs p99** summed across all enabled features per request. This is measured end-to-end from the guard entry point (header extraction) through `AbusePolicy::check()` and back.

### 7.1 Budget Allocation (Phase 0, noop only)

| Component | Budget |
|-----------|--------|
| Header extraction (`X-Realm-ID` parse) | ~200 ns |
| UUID parse | ~50 ns |
| ConnectInfo extraction | ~20 ns |
| MatchedPath label lookup | ~10 ns |
| `NoopAbusePolicy::check()` | ~5 ns |
| **Total** | **< 500 ns** |

Future concrete implementations (rate-limiter, threat-score lookup) must be benchmarked and MUST NOT exceed the 5 µs budget. Memory-mapped atomic counters and lock-free data structures are the expected implementation path.

---

## 8. Extension Points

Future phases (plan HEA-1114 §4) extend this foundation:

| Phase | Capability | Issue |
|-------|-----------|-------|
| B | Per-IP / per-realm sliding-window rate limiter | HEA-1188 |
| C | Breach credential cross-check | HEA-1189 |
| D | Threat-score aggregator + `Challenge` flow | HEA-1190 |

Each phase introduces a new `AbusePolicy` implementation that wraps the previous one (decorator pattern), preserving the single-entry-point trait contract.

---

## 9. Security Considerations

- **Reason strings are internal.** `AbuseDecision::Block { reason }` reason strings MUST only be logged server-side. They MUST NOT appear in HTTP responses.
- **No PII in logs.** `realm_id` and `client_ip` are the only logged fields on a block event.
- **Side-channel resistance.** The guard MUST respond with identical HTTP 429 bodies for `Block` and `Challenge` to prevent callers from distinguishing the two states.
- **Constant-time path.** The noop policy takes a constant ~5 ns regardless of realm or endpoint. Future policies MUST be designed to avoid timing oracles.

---

*Last updated: HEA-1187 (foundation phase)*
