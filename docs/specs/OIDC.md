# OIDC Implementation Spec

Normative specification for Hearth's OpenID Connect and OAuth 2.1 implementation.
RFC 2119 keywords (MUST, SHOULD, MAY) apply throughout.

---

## 1. Core OIDC / OAuth 2.1

Hearth implements:

- **OpenID Connect Core 1.0** — authorization code flow, ID token issuance, UserInfo endpoint
- **OAuth 2.1** (draft) — authorization code + PKCE, client credentials, refresh token
- **OpenID Connect Discovery 1.0** — `/.well-known/openid-configuration` per realm
- **RFC 7517 / 7518 / 7519** — JOSE, JWA, JWT
- **RFC 7591** — Dynamic Client Registration
- **RFC 7636** — PKCE (S256 always; `plain` rejected when FAPI profile is active)

### Signing algorithms

| Key type | Algorithms | Notes |
|----------|-----------|-------|
| Ed25519 | EdDSA | Default realm signing key |
| P-256 | ES256 | Accepted for client `private_key_jwt`; published at `/certs` |
| RS256 | RS256 | Interop-only; EdDSA preferred |

HS256 and `alg:none` MUST NOT be used. Hearth rejects tokens signed with these algorithms.

### Endpoints (per realm)

| Endpoint | Path |
|----------|------|
| Discovery | `/realms/{realm}/.well-known/openid-configuration` |
| Authorization | `/realms/{realm}/authorize` |
| Token | `/realms/{realm}/token` |
| UserInfo | `/realms/{realm}/userinfo` |
| JWKS | `/realms/{realm}/certs` |
| PAR | `/realms/{realm}/par` |
| DCR | `/realms/{realm}/register` |
| RP-initiated logout | `/realms/{realm}/logout` |

---

## 2. FAPI 2.0 Security Profile

Hearth implements **FAPI 2.0 Security Profile** (Final, 2024) at two levels:

- **Baseline** — PAR mandatory, PKCE S256 mandatory, `private_key_jwt` mandatory
- **Advanced** — Baseline + JAR mandatory, JARM mandatory, DPoP mandatory

FAPI 2.0 shipped in commit eeca42f (PR #128). The `fapi_profile` realm-level YAML key is
tracked in [HEA-1040](/HEA/issues/HEA-1040) and is pending wire-up; the feature is available
via Admin API PATCH in the interim.

> **Operator guide:** [docs/guides/fapi2.md](../guides/fapi2.md) — enable, configure, test,
> and validate FAPI 2.0 compliance including copy-paste curl examples for PAR, JAR, JARM,
> and DPoP.

### 2.1 Normative constraints

When `fapi_profile` is set to `baseline` or `advanced`, Hearth MUST:

1. **Reject** authorization requests not submitted via PAR (`/par`).
2. **Reject** PKCE methods other than `S256`.
3. **Reject** `token_endpoint_auth_method` values of `client_secret_basic` or
   `client_secret_post`.
4. **Reject** client registrations that include a `client_secret`.
5. **Reject** `response_type` values other than `code`.

When `fapi_profile` is set to `advanced`, Hearth additionally MUST:

6. **Reject** PAR requests that do not include a signed `request` JWT (JAR, RFC 9101).
7. **Reject** token requests that do not include a valid `DPoP` proof header (RFC 9449).
8. **Force** `response_mode=jwt` (JARM); reject other response modes.

### 2.2 PAR (RFC 9126)

- PAR endpoint: `/realms/{realm}/par`
- `request_uri` TTL: 60 seconds (non-configurable)
- `request_uri` MUST be single-use; Hearth invalidates it on first use
- PAR response: `201 Created` with `{ "request_uri": "urn:hearth:par:{realm}:{token}", "expires_in": 60 }`

### 2.3 JAR (RFC 9101)

- `request` parameter accepted at `/par` and (for non-FAPI realms) at `/authorize`
- JWT MUST be signed with a key registered in the client's JWKS (`kid` header required)
- JWT `aud` MUST match the PAR or authorize endpoint URL
- JWT `exp` MUST be within 60 seconds of `iat`; Hearth rejects expired request objects

### 2.4 JARM

- Activated by `response_mode=jwt` in the PAR body (or `response_mode=form_post.jwt`)
- Hearth signs the JARM JWT with the realm's Ed25519 key; verifiable at `/realms/{realm}/certs`
- JARM JWT MUST include: `iss`, `aud`, `exp`, `code` (success) or `error` (failure), `state`
- Clients MUST verify `iss`, `aud`, `exp`, and `state` before accepting the authorization code

### 2.5 DPoP (RFC 9449)

- DPoP proofs accepted at `/realms/{realm}/token` and resource server pass-through validation
- Supported DPoP key types: P-256 (ES256), Ed25519 (EdDSA)
- Hearth issues DPoP-bound tokens with `cnf.jkt` (JWK SHA-256 thumbprint) in the payload
- Token type in response: `"token_type": "DPoP"` (not `"Bearer"`)
- Clock skew tolerance: ±30 seconds on `iat`

### 2.6 Client authentication

Under any FAPI profile, only `private_key_jwt` is accepted. The JWT MUST:

- Be signed with ES256 or EdDSA
- Have `iss` and `sub` equal to the `client_id`
- Have `aud` equal to the token endpoint URL
- Have `exp` ≤ 60 seconds from `iat`
- Contain a unique `jti` (Hearth rejects replayed `jti` values within the `exp` window)

---

## 3. Session Management

- **RP-initiated logout** (OIDC Session Management §5): `POST /realms/{realm}/logout`
- **Back-channel logout** (OIDC Back-Channel Logout 1.0): fan-out to registered
  `backchannel_logout_uri` endpoints on session termination
- **Front-channel logout**: iframe-based fan-out via `frontchannel_logout_uri`

---

*This spec is authoritative for Hearth's OIDC/OAuth 2.1/FAPI behavior. Implementation lives
in `src/protocol/oidc/` and `src/identity/`. Discrepancies between this spec and the code
are bugs — file an issue against the relevant layer.*
