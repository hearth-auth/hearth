# Hearth Configuration Reference

This document is the exhaustive reference for `hearth.yaml`. For deployment-level concerns (NTP, cluster startup order, snapshot tuning) see [deployment.md](../guides/deployment.md).

---

## Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cluster` | object | — | Cluster engine settings. Omit for single-node mode. |
| `realms` | map | — | Named authentication realms. Each realm is an independent tenant. |

---

## `cluster`

See [deployment.md §cluster](../guides/deployment.md) for the full `cluster:` field reference and worked examples.

---

## `realms.<name>`

Each key under `realms:` names a realm. Hearth boots with a built-in `default` realm when no `realms:` block is present.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `display_name` | string | same as key | Human-readable name shown in the admin UI and login pages. |
| `issuer` | string | derived | OIDC issuer URL for this realm. Defaults to `https://<host>/<name>`. |
| `federation` | object | — | Social login / external IdP connectors. See below. |

---

## `realms.<name>.federation`

Configures social login and enterprise SSO connectors for a realm.

### Top-level federation fields

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `link_existing_accounts` | `disabled \| confirm \| auto` | `confirm` | How Hearth handles a federated identity whose email already belongs to a local account. `disabled`: reject the login and show an error. `confirm`: show the user a confirmation prompt before linking. `auto`: silently link without user interaction. |
| `providers` | map | — | Named map of IdP connector configurations. Each key becomes the provider identifier used in redirect URIs (`/oauth/callback/<name>`). |

### `realms.<name>.federation.providers.<name>`

Each entry under `providers:` configures one external identity provider.

#### Common fields

All provider types support these fields:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | `oidc \| google \| microsoft \| apple \| github \| saml` | yes | Connector protocol. `google`, `microsoft`, `apple`, and `github` are pre-configured OIDC variants that supply default endpoints; `oidc` requires explicit endpoint configuration; `saml` uses SAML 2.0. |
| `display_name` | string | no | Label shown on the login button. Defaults to the provider key name. |
| `client_id` | string | yes (non-SAML) | OAuth client ID issued by the IdP. Supports `${ENV_VAR}` substitution. |
| `client_secret` | string | yes (non-SAML) | OAuth client secret. Supports `${ENV_VAR}` substitution — strongly recommended over inline secrets. |

#### OIDC / OAuth 2.0 fields

Used when `type` is `oidc`, `google`, `microsoft`, `apple`, or `github`. For the pre-configured types (`google`, etc.) all endpoints are set automatically; supply only the fields you need to override.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `issuer` | string | — | IdP issuer URL. When set, Hearth fetches `<issuer>/.well-known/openid-configuration` and derives the endpoints below automatically. |
| `authorization_endpoint` | string | from discovery | Authorization URL. Required when `issuer` is absent and `type: oidc`. |
| `token_endpoint` | string | from discovery | Token exchange URL. |
| `userinfo_endpoint` | string | from discovery | User-info URL for claim retrieval. |
| `jwks_uri` | string | from discovery | JWKS endpoint for verifying IdP-signed ID tokens. |
| `scopes` | list of strings | `["openid","email","profile"]` | OAuth scopes to request. Appended to the authorization request. |
| `claim_mappings` | map | — | Map of Hearth claim names to IdP JWT claim paths. Example: `email: "upn"` reads the user's email from the IdP's `upn` claim. |

#### SAML 2.0 fields

Used when `type: saml`. OAuth fields (`client_id`, `client_secret`, OIDC endpoints) are not applicable for SAML.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `sso_url` | string | yes | IdP Single Sign-On URL. Hearth POSTs SAMLRequests here. |
| `entity_id` | string | yes | IdP entity ID (`EntityDescriptor/@entityID`). Must match the value in the IdP metadata exactly. |
| `idp_certificate_pem` | string | yes | PEM-encoded X.509 certificate used to verify IdP-signed assertions. Supports `${ENV_VAR}`. |
| `attribute_map` | map | — | Map of Hearth claim names to SAML attribute names. Example: `email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"`. |
| `slo_url` | string | no | IdP Single Logout URL. When set, Hearth participates in IdP-initiated SLO. |
| `sign_authn_requests` | bool | `false` | When `true`, Hearth signs outbound AuthnRequests with the realm's signing key. |
| `want_assertions_signed` | bool | `true` | When `true`, Hearth rejects unsigned or invalidly-signed assertions from the IdP. Disable only for IdPs that cannot sign assertions. |

### Reconciliation behavior

When a federated user authenticates:

1. Hearth matches the incoming identity to an existing local account by email.
2. If no match exists, a new local account is created and linked to the provider.
3. If a match exists, `link_existing_accounts` controls the outcome (see above).
4. On subsequent logins, the previously-linked account is used directly regardless of `link_existing_accounts`.

### Example

```yaml
realms:
  default:
    federation:
      link_existing_accounts: confirm

      providers:
        google:
          type: google
          display_name: "Sign in with Google"
          client_id: "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
          scopes: ["openid", "email", "profile"]

        github:
          type: github
          display_name: "Sign in with GitHub"
          client_id: "${GITHUB_CLIENT_ID}"
          client_secret: "${GITHUB_CLIENT_SECRET}"

        corp-saml:
          type: saml
          display_name: "Corporate SSO"
          sso_url: "https://idp.corp.example.com/sso/saml"
          entity_id: "https://idp.corp.example.com"
          idp_certificate_pem: "${CORP_SAML_CERT_PEM}"
          slo_url: "https://idp.corp.example.com/slo/saml"
          sign_authn_requests: true
          want_assertions_signed: true
          attribute_map:
            email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
```

For more complete worked examples including multi-realm setups and claim mapping patterns, see [hearth-yaml-examples.md Part 4](../guides/hearth-yaml-examples.md#part-4-federation).
