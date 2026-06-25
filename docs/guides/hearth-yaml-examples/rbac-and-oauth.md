# RBAC & OAuth — Examples 28–33

`hearth.yaml` snippets for custom permissions, role hierarchies, OAuth scope bundles, SPA and
M2M client registration, SSO consent bypass, and real-time decision mode.
Return to the [example index](./index.md) for a full list of all examples.

Custom permissions and roles are declared per-realm under `realms.<name>.permissions` and
`realms.<name>.roles`. Scope bundles map OAuth scope strings to permission sets. OAuth
applications are declared under `realms.<name>.applications`.

A few structural notes:
- Roles reference permission names, not definitions. A permission must exist in `permissions:`
  (or be a Hearth seed permission) before a role can reference it.
- `scope_kind: realm` (the default) issues the permission in the JWT for the whole realm.
  `scope_kind: organization` includes the active org context — use for per-customer isolation.
- `parents:` wires up role inheritance; child roles inherit all parent permissions.
- Public clients (`confidential: false`, the default) need no `client_secret`. Confidential
  clients (`confidential: true`) require `client_secret` — hashed with Argon2id, never stored
  in plaintext.

---

## Example 28 — Custom permissions + roles

**Audience:** operators who need fine-grained access control beyond Hearth's built-in
seed roles (`realm.admin`, `realm.member`, `org.owner`, `org.member`).

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    permissions:
      - name: invoice.read
        display_name: "Read Invoices"
        description: "View invoices and line items"
        category: billing
      - name: invoice.write
        display_name: "Write Invoices"
        category: billing
      - name: invoice.approve
        display_name: "Approve Invoices"
        category: billing
      - name: report.run
        display_name: "Run Reports"
        category: analytics

    roles:
      - name: billing-viewer
        description: "Can read but not modify invoices"
        scope_kind: realm           # realm (default) | organization | any
        permissions:
          - invoice.read
          - report.run

      - name: billing-admin
        description: "Full billing control at realm level"
        scope_kind: realm
        parents:
          - billing-viewer          # inherits invoice.read + report.run
        permissions:
          - invoice.write
          - invoice.approve

      - name: org-billing-manager
        description: "Org-scoped billing role — one per customer org"
        scope_kind: organization    # org context included in the JWT
        permissions:
          - invoice.read
          - invoice.write
```

- Permissions are defined once and referenced by name in roles and scope bundles.
- `parents:` is resolved in two passes at startup so role order in the YAML list does not
  matter — parents may appear after their children.
- `scope_kind: organization` roles are only meaningful when the realm has organizations and the
  access token was issued with an active org context (`?org_id=<id>` on the authorization
  request).
- Hearth's seed permissions (`user.read`, `user.write`, `user.impersonate`, `session.revoke`)
  are always available; you do not need to redeclare them.

---

## Example 29 — OAuth scope bundles

**Audience:** operators who want clients to request coarse OAuth scopes (`billing`) while
Hearth expands them into fine-grained permissions inside the JWT.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    permissions:
      - name: invoice.read
        display_name: "Read Invoices"
      - name: invoice.write
        display_name: "Write Invoices"
      - name: report.run
        display_name: "Run Reports"

    scopes:
      - name: billing:read
        display_name: "Billing (read-only)"
        description: "View invoices and billing data"
        permissions:
          - invoice.read

      - name: billing
        display_name: "Billing (full access)"
        description: "Create, update, and approve invoices"
        permissions:
          - invoice.read
          - invoice.write

      - name: analytics
        display_name: "Analytics"
        permissions:
          - report.run
```

- A client that requests `scope=billing:read openid` receives a token with
  `permissions: ["invoice.read"]` embedded at issuance time — no runtime permission check
  needed.
- Scope bundles do not enforce that the _user_ has the underlying permissions; they only gate
  which permissions flow into the token for that authorization request. Assign roles to users
  for enforcement.
- `declared_scopes` on an application controls which scopes that client may request.

---

## Example 30 — Public OAuth client — SPA

**Audience:** operators registering a browser-based single-page application that uses
PKCE-protected authorization code flow with public credentials.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    applications:
      my-spa:
        name: "My Single-Page App"
        redirect_uris:
          - "https://app.example.com/callback"
          - "https://app.example.com/silent-renew"
        grant_types:
          - authorization_code
          - refresh_token
        # confidential: false  (default — public clients have no client_secret)
        declared_scopes:
          - openid
          - profile
          - email
          - billing:read
```

- Hearth requires PKCE (`code_challenge` + `code_verifier`) for all public clients; the
  `authorization_code` flow without PKCE is rejected.
- `silent-renew` as a redirect URI supports token refresh via a hidden iframe in the browser.
- List only scopes the SPA actually needs in `declared_scopes`; requesting an undeclared scope
  at runtime is rejected.

---

## Example 31 — Confidential OAuth client — M2M

**Audience:** operators registering a backend service that authenticates to Hearth with its
own credentials (machine-to-machine), not on behalf of a user.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    applications:
      billing-service:
        name: "Billing Microservice"
        confidential: true
        client_secret: "${BILLING_CLIENT_SECRET}"   # Argon2id-hashed before storage
        grant_types:
          - client_credentials
        declared_scopes:
          - billing
          - analytics
```

- `client_credentials` tokens are not tied to a user session. They carry the scopes
  requested at the time of the grant and are revocable via the token revocation endpoint.
- `client_secret` is stored as an Argon2id hash; the plaintext value is never persisted.
  Rotate it by changing the env var and restarting (or via the Admin API).
- Add `authorization_code` alongside `client_credentials` if the service also performs
  user-delegated flows.

---

## Example 32 — First-party SSO — no consent

**Audience:** operators whose app is first-party (they own both the auth server and the
client app), so the OAuth consent screen adds friction without adding security.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    applications:
      main-app:
        name: "Main Application"
        redirect_uris:
          - "https://app.example.com/callback"
        grant_types:
          - authorization_code
          - refresh_token
        require_consent: false   # skip the consent screen — first-party only
```

- `require_consent: false` means users are redirected directly to the `redirect_uri` after
  login without being shown the scope-grant screen.
- Only use this for apps you fully control. Third-party clients must go through consent so
  users can see what data they are granting access to.
- The field is named `require_consent`; setting it to `false` disables the prompt (double
  negative — read it as "require consent? no").

---

## Example 33 — Decision-mode client with `POST /oauth/authorize`

**Audience:** operators deploying a backend microservice where permission changes must
take effect immediately, without waiting for a token refresh cycle. Typical use cases:
financial services, healthcare, or any flow where access can be revoked mid-session.

In decision mode, Hearth issues JWTs that carry only identity claims. The resource server
calls `POST /oauth/authorize` on every protected request to get a live binary allow/deny.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    permissions:
      - name: payment.initiate
        display_name: "Initiate Payments"
        category: finance
      - name: payment.approve
        display_name: "Approve Payments"
        category: finance

    roles:
      - name: payment-initiator
        permissions: [payment.initiate]
      - name: payment-approver
        permissions: [payment.approve]
        parents: [payment-initiator]     # approvers can also initiate

    applications:
      payments-service:
        name: "Payments Service"
        confidential: true
        client_secret: "${PAYMENTS_CLIENT_SECRET}"
        grant_types:
          - client_credentials
        access_token_authorization: decision
```

The resource server (pseudocode) verifies each incoming request like this:

```bash
# Resource server checks permission before processing a payment
curl -X POST https://auth.example.com/oauth/authorize \
  -H "Authorization: Bearer ${REQUEST_ACCESS_TOKEN}" \
  -H "X-Realm-ID: ${REALM_UUID}" \
  -H "Content-Type: application/json" \
  -d '{"permission": "payment.initiate"}'
# → {"allowed": true}  or  {"allowed": false}
```

For org-scoped checks (user must have the permission within a specific org context):

```bash
curl -X POST https://auth.example.com/oauth/authorize \
  -H "Authorization: Bearer ${REQUEST_ACCESS_TOKEN}" \
  -H "X-Realm-ID: ${REALM_UUID}" \
  -H "Content-Type: application/json" \
  -d '{"permission": "payment.initiate", "organization_id": "${ORG_UUID}"}'
```

Key notes for resource server implementors:

- **Fail-closed:** any non-`{"allowed": true}` response — including network errors, timeouts,
  and `5xx` — MUST be treated as a denial. Never fail open.
- **Circuit-break:** wrap the call in a circuit breaker with a short timeout (e.g. 200 ms) to
  prevent a Hearth slowdown from stalling your entire request path.
- **Do not cache:** the purpose of decision mode is zero-latency revocation. Caching
  `allowed: true` even briefly undermines that guarantee.
- **Not for browsers:** `POST /oauth/authorize` is an internal endpoint. Route only
  service-to-service traffic to it; do not expose it to the internet.

---
