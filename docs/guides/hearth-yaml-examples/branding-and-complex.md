# Branding & Complex Scenarios — Examples 39–41

`hearth.yaml` snippets for custom branding, high-security/financial-services hardening, and a
full enterprise kitchen-sink reference configuration.
Return to the [example index](./index.md) for a full list of all examples.

---

## Example 39 — Custom branding

**Audience:** operators who want to replace Hearth's default logo and theme with their own
product branding, with per-realm overrides for multi-surface deployments.

```yaml
branding:
  product_name: "Acme Auth"
  logo_url: "https://cdn.example.com/logo.svg"
  theme: ocean               # ember (dark, default) | ocean | midnight | forest | cloud | slate

realms:
  customer-portal:
    web:
      theme: cloud             # light theme for the customer-facing login page
      product_name: "Acme Customer Portal"
      custom_css: |
        :root { --ht-accent: #c04000; }   /* brand-specific accent override */

  internal-tools:
    web:
      theme: midnight
      product_name: "Acme Internal"
```

- `branding.logo_url` accepts HTTPS URLs or absolute local paths (e.g.
  `/opt/hearth/branding/logo.svg`). The file must be readable by the Hearth process.
- `branding.theme` sets the global default; per-realm `web.theme` overrides it for that
  realm's login and account pages only.
- `custom_css` is injected after Hearth's compiled stylesheet. Use CSS custom properties
  (`--ht-*`) from `ui/tailwind.config.js` to override tokens without breaking the layout.
- Available themes: `ember` (dark, default), `ocean` (dark), `midnight` (dark),
  `forest` (dark), `cloud` (light), `slate` (light).
- Dark-mode-only (`ember`, `ocean`, `midnight`, `forest`) and light themes (`cloud`, `slate`)
  are mutually exclusive per realm. Hearth has no automatic light/dark toggle.

---

## Example 40 — High-security / financial services

**Audience:** operators in regulated industries (finance, healthcare, government) who need
short-lived tokens, strict password policy, mandatory MFA, invite-only registration, and
aggressive rate limiting.

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path: "/etc/hearth/tls/server.key"

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

email:
  transport: sendgrid
  from: "Auth <auth@example.com>"
  sendgrid:
    api_key: "${SENDGRID_API_KEY}"

token:
  access_token_ttl: "5m"          # very short-lived; force frequent re-validation
  refresh_token_ttl: "8h"         # session-length window; no remember-me

auth:
  session_ttl: "8h"
  mfa_required: true
  mfa_methods:
    - totp
  password_policy:
    min_length: 16
    require_uppercase: true
    require_number: true
    require_special: true
    not_username: true
    not_email: true
    history_depth: 24              # reject last 24 passwords
    max_age_days: 90               # force reset every 90 days
  registration:
    mode: invite_only              # no self-registration; accounts created by admins only
  rate_limit:
    max_failed_logins: 5
    lockout_duration: "30m"

observability:
  log_level: warn
  log_format: json
```

- `token.access_token_ttl: "5m"` minimizes the window for a stolen bearer token. Pair this
  with refresh token rotation (enabled by default) so legitimate clients transparently
  re-issue tokens without user interaction.
- `password_policy.history_depth: 24` prevents users cycling through a small set of
  passwords to bypass `max_age_days`. Both settings are enforced at password-change time.
- `rate_limit.max_failed_logins: 5` with `lockout_duration: "30m"` exceeds NIST SP 800-63B
  guidance; tune to your threat model.
- Add `auth.mfa_methods: [webauthn]` alongside `totp` to support phishing-resistant
  WebAuthn / passkey second factors in addition to TOTP.
- Registering an application for this realm? Set `require_consent: false` only for
  first-party apps; all third-party integrations must go through consent.

### FAPI 2.0 with this configuration

The `hearth.yaml` above sets the server-side prerequisites for FAPI 2.0 compliance (TLS required,
short-lived tokens, MFA, no self-registration). FAPI 2.0 client registration and realm-level FAPI
profile enforcement are configured via the Admin API — not via `hearth.yaml` today.

After bringing up the server with this config, register a FAPI 2.0 client:

```bash
# Register a FAPI 2.0 client (no client_secret; JWKS required)
curl -s -X POST "https://auth.example.com/admin/applications" \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: <realm-uuid>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Open Banking Client",
    "profile": "fapi2",
    "redirect_uris": ["https://tpp.example.com/callback"],
    "grant_types": ["authorization_code"],
    "jwks": "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\",\"kid\":\"k1\",\"x\":\"<base64url-public-key>\"}]}",
    "authorization_signed_response_alg": "EdDSA"
  }'
```

See [fapi2.md](../fapi2.md) for the complete FAPI 2.0 flow (PAR, JAR, JARM, DPoP).

---

## Example 41 — Full enterprise kitchen sink

**Audience:** operators who need to validate a complete production configuration covering
multiple realms, MFA, social login, SCIM, SAML, custom RBAC, branding, SMTP, TLS, and
observability in a single file. Use as a template, not as a copy-paste-and-go config.

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"
  default_realm: consumer

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true
  hot_tier_capacity: 200000
  compaction:
    enabled: true
    interval_secs: 3600

email:
  transport: smtp
  from: "Acme Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

branding:
  product_name: "Acme Auth"
  logo_url: "https://cdn.example.com/logo.svg"
  theme: ember

observability:
  log_level: info
  log_format: json
  otlp:
    endpoint: "http://otel-collector.internal:4317"
    service_name: "hearth-prod"
    headers:
      x-honeycomb-team: "${HONEYCOMB_API_KEY}"

metrics:
  enabled: true

onboarding:
  base_url: "https://auth.example.com"
  notification_email: "ops@example.com"

token:
  access_token_ttl: "15m"
  refresh_token_ttl: "7d"

auth:
  session_ttl: "24h"

realms:
  # ── Consumer realm: open registration, Google login, SPA client ────────────
  consumer:
    session_ttl: "24h"
    web:
      theme: ocean
      product_name: "Acme — Consumer"
    auth:
      mfa_required: false
      registration:
        mode: open
    federation:
      link_existing_accounts: confirm
      providers:
        google:
          type: google
          client_id: "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
    applications:
      consumer-app:
        name: "Consumer Web App"
        redirect_uris:
          - "https://app.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
        require_consent: false
        declared_scopes:
          - openid
          - profile
          - email

  # ── Enterprise realm: invite-only, MFA, SCIM, SAML, RBAC, orgs ────────────
  enterprise:
    session_ttl: "8h"
    web:
      theme: midnight
      product_name: "Acme — Enterprise"
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn
      registration:
        mode: invite_only
      password_policy:
        min_length: 14
        require_uppercase: true
        require_number: true
        require_special: true
        not_username: true
        history_depth: 12
        max_age_days: 90
      rate_limit:
        max_failed_logins: 5
        lockout_duration: "30m"
      token:
        access_token_ttl: "5m"
        refresh_token_ttl: "1d"
    scim:
      bearer_token: "${SCIM_ENTERPRISE_TOKEN}"
    saml_service_providers:
      workday:
        entity_id: "https://wd5.myworkday.com/acme/login-saml2.htmld"
        acs_url: "https://wd5.myworkday.com/acme/login-saml2.htmld"
        nameid_format: emailAddress
        sign_assertions: true
        attribute_map:
          email: "wd:Worker_AuthenticationAlias"
          display_name: "wd:Worker_PreferredName"
    federation:
      link_existing_accounts: confirm
      providers:
        microsoft:
          type: microsoft
          display_name: "Microsoft (Acme)"
          # Pin to your tenant to prevent cross-tenant token acceptance.
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
          client_id: "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
    permissions:
      - name: doc.read
        display_name: "Read Documents"
        category: content
      - name: doc.write
        display_name: "Write Documents"
        category: content
      - name: admin.users
        display_name: "Manage Users"
        category: administration
    roles:
      - name: editor
        scope_kind: organization
        permissions:
          - doc.read
          - doc.write
      - name: enterprise-admin
        scope_kind: realm
        permissions:
          - doc.read
          - doc.write
          - admin.users
    scopes:
      - name: docs
        display_name: "Documents"
        permissions:
          - doc.read
          - doc.write
    claims:
      mappings:
        - claim: roles
          source: roles_from_assignments
        - claim: org_id
          source: org_context
    organizations:
      acme-corp:
        name: "Acme Corporation"
        config:
          max_members: 500
      beta-customer:
        name: "Beta Customer Inc"
    applications:
      enterprise-portal:
        name: "Enterprise Portal"
        redirect_uris:
          - "https://enterprise.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
        require_consent: false
        declared_scopes:
          - openid
          - profile
          - email
          - docs
      m2m-service:
        name: "Internal Automation Service"
        confidential: true
        client_secret: "${M2M_CLIENT_SECRET}"
        grant_types:
          - client_credentials
        declared_scopes:
          - docs
```

- Each realm is an isolated identity namespace with its own signing key, user store, and
  session pool. Cross-realm SSO is not automatic.
- `auth.token.*` inside a realm overrides global `token.*` TTLs for that realm only.
- `scim.bearer_token` and `saml_service_providers` can coexist; each handles a different
  enterprise integration path (SCIM = provisioning, SAML = authentication).
- `federation.providers.microsoft.issuer` pins to a single Azure AD tenant. Omitting the
  tenant-specific issuer allows tokens from _any_ Microsoft tenant — a security risk for
  B2B deployments.
- `claims.mappings` with `source: org_context` injects the user's active organization ID
  (`oid` claim) so downstream services can make org-scoped authorization decisions without
  querying Hearth.
- YAML-declared organizations (`organizations:`) are reconciled at startup; membership and
  invitations remain runtime-only and are managed via the Admin API or Admin UI.

---

*Re-check these pages when `src/config/types.rs`, `src/identity/federation/`, or
`src/identity/types/` change public API surface (new YAML keys, renamed variants).*
