## Security Behaviors

Code-derived inventory of security-relevant enforced behaviors in Hearth, cross-referenced against `docs/specs/` and the security sweeps HEA-1717 and HEA-1749. Paths are repo-relative to `/home/brad/Code/personal/hearth`. Line numbers are from the working tree at audit time and may drift.

| Security behavior | Enforcement entry point (fn) | File:line | Spec/sweep reference |
|---|---|---|---|
| **Ed25519-only JWT signing** — tokens signed with `EdDSA`/Ed25519 via `ring`; no HS256/`alg:none` | `SigningKey::sign` / `validate_token_with_time` (verifies `alg`, `typ`, Ed25519 sig before decode) | `src/identity/tokens.rs:444` (SigningKey), `src/identity/tokens.rs:896` (validate) | CLAUDE.md Security §Signing; OIDC.md; token_adversarial.rs HS256-forgery test |
| **JWT signature verify on hot path** — realm-key Ed25519 verify + serde parse, with global-key fallback | `Engine::validate_token` | `src/identity/engine/mod.rs:6742` (verify at `:6917`) | AUTHORIZATION.md; HEA-1771 zero-alloc |
| **Argon2id password hashing** — OWASP params, off hot path; HMAC-SHA256 pepper pre-hash | `hash_password` | `src/identity/credentials.rs:281` (Argon2id ctor `:255`, pepper `:262`) | CLAUDE.md §Password hashing; credentials.rs module doc |
| **Client-secret hashing (raw secrets)** — client secrets hashed with Argon2id before storage | `hash_raw_secret` / `verify_raw_secret` | `src/identity/credentials.rs:535`, `:553` | OIDC.md; oauth.rs `:257` |
| **Legacy hash upgrade** — bcrypt/scrypt/PBKDF2-SHA256 verified natively, auto-upgraded to Argon2id on login | password-verify path in engine | `src/identity/engine/mod.rs:5979` (`needs_algo_upgrade` `:5982`) | Keycloak/Auth0 migration; MEMORY import notes |
| **PKCE mandatory (public clients / FAPI2)** — authorize rejected without `code_challenge`; `method` must be `S256` | authorize handler PKCE gate | `src/identity/engine/oauth.rs:526`, `:606`, `:2442`, `:2470` | HEA-501; OIDC.md FAPI2; HEA-1749 A2 |
| **PKCE verifier check at token exchange** — `code_verifier` required + must match stored challenge | code-exchange PKCE validation | `src/identity/engine/oauth.rs:831` (mismatch `:844`) | OIDC.md §PKCE |
| **DPoP proof validation (RFC 9449)** — `typ=dpop+jwt`, alg/jwk/htu/htm/iat, no private key, JTI replay cache, jkt blocklist | `validate_dpop_proof` | `src/identity/dpop.rs:252` (typ check `:280`) | AGENT_AUTH.md; HTTP call sites `src/protocol/http/auth.rs:860`, `oauth.rs:1176/2252`, `tool_invocation.rs:198` |
| **DPoP JTI replay cache** — one-time proof JTIs stored `agt:dpop:jti:{jti}` with expiry; reaped | store + cleanup scan | `src/identity/mod.rs:2289`, `src/identity/cleanup.rs:462` | AGENT_AUTH.md |
| **Token exchange (RFC 8693)** — `grant_type=…token-exchange`; act-chain depth ≤10, caller binding | `token_exchange` HTTP + gRPC | `src/protocol/http/oauth.rs:1093`, `src/protocol/grpc/oauth.rs:93` | AGENT_AUTH.md M2; HEA-1753 R4; MAX_ACT_CHAIN_DEPTH=10 |
| **SSRF guard (connect-time DNS)** — validates `ureq` connect-time resolved addrs; blocks private/rebind on all webhook egress | `SsrfResolver::resolve` | `src/webhook/ssrf.rs:184` (agent build `:216`) | HEA-1762 SSRF TOCTOU; HEA-1749 |
| **Audit hash-chain (HMAC-SHA256)** — per-realm keyed chain `HMAC-SHA256(realm_key, prev_hash‖event)`; signed chain head detects tail truncation | `AuditEngine::append` (hash compute `:170`, chain-head MAC `:199`) | `src/audit/engine.rs:374` | HEA-1756 R7; MEMORY audit-chain note |
| **Cross-realm BOLA scoping (scoped_realm)** — admin handlers force path realm to match caller's authorized realm | `scoped_realm` | `src/protocol/http/admin.rs:240` (11 call sites) | HEA-1629 BOLA; HEA-1717 (verified complete) |
| **SAML `InResponseTo` binding** — response bound to issued AuthnRequest ID; mismatch rejected; DOCTYPE/XXE rejected | `parse_response` / response verify | `src/identity/federation/saml/response.rs:121` (InResponseTo mismatch `:392`, DOCTYPE reject `:560` test) | HEA-1751 R2 SAML hardening; HEA-1749 S1 |
| **SAML assertion signature verify** | `verify_assertion_signature` | `src/identity/tokens.rs:924` | HEA-1751 R2 |
| **MFA/session policy gate** — realm `mfa_required` blocks session issuance when user lacks MFA (TOTP/passkey) | `mfa_required` policy resolve + session gate | `src/identity/oidc.rs:630`; tests `tests/realm_auth_policy.rs:301` | HEA-1752 R3 MFA bypass |
| **Client auth on token endpoint** — confidential clients must present valid secret (Argon2id verify) or private_key_jwt; FAPI2 forbids secret | `authenticate_oauth_client_inner` / `authenticate_client_inner` | `src/identity/engine/oauth.rs:2999` (verify `:3018`); private_key_jwt `:1398` | HEA-1755 R6 token client-auth; OIDC.md |
| **CSP + security headers** — CSP, X-Frame-Options DENY, nosniff, COOP/COEP, HSTS(TLS), Permissions-Policy on all `/ui/**` | `SecurityHeadersService::call` (`SecurityHeadersLayer`) | `src/protocol/web/security.rs:32`/`:57` | HEA-1757 R8 (object-src/form-action); A-40; tests/web_csp.rs |
| **JTI revocation** — revoked token/client-cred JTIs blocklisted (`oauth:revjti:{jti}`), checked on validate | `is_token_jti_revoked` | `src/identity/engine/mod.rs:3703` (checked at `:3690`, `:6881`) | HEA-1771 C-2; HEA-1753 R4; MEMORY OAuth note |
| **Refresh-token theft detection** — grant-family `current_refresh_hash`; mismatch revokes family + session | rotate_grant_family / refresh binding | `src/identity/engine/oauth.rs` (RefreshBindContext) | HEA-1755 R6; MEMORY OAuth note |

### Notes / cross-references

- **Hot-path constraints** (zero-alloc, no locks) on `validate_token` are enforced by benches (`benches/validate_token.rs`) and HEA-1771, not a runtime check.
- **DPoP nonce** generation is stateless per-realm HMAC-SHA256 over sliding 5-min windows (`src/identity/dpop.rs`, nonce secret `agt:dpop:nonce-secret`).
- **Config-level guards**: `src/config/validate.rs:954/1781` reject `confidential:true` without a `client_secret` and vice-versa (startup-time BOLA/misconfig prevention).
- **Key-at-rest**: Ed25519 signing keys and DPoP nonce secrets are AES-256 KEK-wrapped (`src/identity/key_encryption.rs`, `src/storage/key_registry.rs` — 0o600 + HMAC-SHA256 integrity framing).

### Behaviors located with high confidence

All 20 targeted behaviors have a concrete enforcement entry point above. One partial: the **refresh-token theft / grant-family rotation** binding is confirmed by MEMORY + `RefreshBindContext`/`rotate_grant_family` references but the exact fn line was not pinned during this pass — see `src/identity/engine/oauth.rs` grant-family rotation code and HEA-1755.
