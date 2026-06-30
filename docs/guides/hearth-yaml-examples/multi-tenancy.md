# Multi-Tenancy — Examples 25–27

`hearth.yaml` snippets for multi-realm deployments, B2B organizations, and per-realm SCIM and
branding configuration.
Return to the [example index](./index.md) for a full list of all examples.

Realms in Hearth are isolated identity namespaces: separate user stores, signing keys,
session pools, and OAuth clients. Declare them under the top-level `realms:` map; the key
becomes the realm's slug and display name.

A few structural notes:
- `realms.<name>.session_ttl` is a top-level override on the realm (not under `auth:`).
- `realms.<name>.auth.*` controls MFA, password policy, allowed methods, and rate limits.
- `realms.<name>.web.theme` selects the UI color theme for that realm's login pages.
- When `realms:` is present in YAML, Hearth manages realms declaratively: realms in storage
  but absent from YAML are archived automatically. When `realms:` is absent, realms are
  created via the API or the onboarding flow.

---

## Example 25 — Two realms (consumer + internal)

**Audience:** operators running a product with separate public-facing and internal/employee login
surfaces that need different session lifetimes, MFA postures, and visual themes.

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  default_realm: consumer    # bare /ui/* URLs serve the consumer realm login page

realms:
  consumer:
    session_ttl: "24h"         # top-level per-realm override
    web:
      theme: ocean             # ember (default) | ocean | midnight | forest | cloud | slate
    auth:
      mfa_required: false
      registration:
        mode: open

  internal:
    session_ttl: "8h"
    web:
      theme: midnight
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn
      registration:
        mode: disabled         # admins provision internal accounts
```

- `session_ttl` at the realm level (not under `auth:`) overrides the global `auth.session_ttl`
  default.
- Realm slugs become the routing token: the consumer login page is at
  `/ui/realms/consumer/login`.
- `server.default_realm: consumer` makes `/ui/login` resolve to the consumer realm — useful
  when only one realm needs a vanity URL.
- Available themes: `ember` (dark, default), `ocean`, `midnight`, `forest`, `cloud` (light),
  `slate` (light).

---

## Example 26 — Single realm with organizations (B2B)

**Audience:** operators building a B2B SaaS product where a single Hearth realm serves multiple
customer organizations. Organizations group users and gate invite-based registration.

```yaml
oidc:
  issuer: "https://auth.example.com"

email:
  transport: smtp
  from: "Hearth Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

onboarding:
  base_url: "https://auth.example.com"

realms:
  default:
    auth:
      registration:
        mode: invite_only       # users join only via org invitation

    organizations:
      acme-corp:
        name: "Acme Corporation"
        description: "Primary enterprise customer"
        config:
          max_members: 500      # hard cap; further invitations are rejected

      starter-co:
        name: "Starter Co"
        config:
          max_members: 10
```

- Organization slugs (the YAML map keys: `acme-corp`, `starter-co`) are reconciled with storage
  at startup. Changing a slug in YAML creates a new organization — the old one is not deleted
  automatically.
- `config.max_members` is optional; omit it for unlimited membership.
- Members and invitations are runtime-only: invite users via the Admin API or UI, not YAML.
- `registration.mode: invite_only` works with organizations: Hearth validates the invitation
  token against the target organization and adds the user as a member on acceptance.

---

## Example 27 — Full B2B SaaS (multi-realm, per-realm SCIM + branding + auth policy)

**Audience:** operators building a product that serves both external customers
(`customer-portal` realm) and internal staff (`internal-tools` realm), with SCIM provisioning
for enterprise customers, strict MFA for internal users, and separate branding for each surface.

```yaml
oidc:
  issuer: "https://auth.example.com"

email:
  transport: sendgrid
  from: "Auth <auth@example.com>"
  sendgrid:
    api_key: "${SENDGRID_API_KEY}"

onboarding:
  base_url: "https://auth.example.com"

branding:
  product_name: "MyApp"
  theme: ember                  # global default; realms can override

server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"
  default_realm: customer-portal

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

realms:
  customer-portal:
    session_ttl: "12h"
    web:
      theme: ocean
      product_name: "MyApp Customer Portal"
    auth:
      mfa_required: false
      registration:
        mode: invite_only
    scim:
      bearer_token: "${SCIM_CUSTOMER_TOKEN}"   # SCIM provisioning for enterprise customers

    organizations:
      example-enterprise:
        name: "Example Enterprise"
        config:
          max_members: 1000

  internal-tools:
    session_ttl: "8h"
    web:
      theme: midnight
      product_name: "MyApp Internal"
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn
      registration:
        mode: disabled
      token:
        access_token_ttl: "5m"     # short-lived tokens for internal services
        refresh_token_ttl: "1d"
    scim:
      bearer_token: "${SCIM_INTERNAL_TOKEN}"
```

- Each realm is a fully isolated identity namespace: separate signing keys, user stores,
  sessions, and OAuth clients. Cross-realm SSO is not automatic — users must log in to each
  realm separately.
- `scim.bearer_token` enables the SCIM 2.0 provisioning endpoint at
  `/scim/v2/realms/<realm-slug>/`. Tokens are hashed with Argon2id before storage; the
  plaintext value is never persisted.
- `realms.<name>.web.product_name` scopes the UI title and email subjects to that realm's
  branding without affecting the global `branding.product_name`.
- `auth.token.access_token_ttl` / `auth.token.refresh_token_ttl` under a realm override the
  global `token.*` TTLs for that realm only.
- Add a `federation:` block to `customer-portal` to let enterprise customers log in via their
  corporate IdP (SAML/OIDC) without creating Hearth passwords.

---
