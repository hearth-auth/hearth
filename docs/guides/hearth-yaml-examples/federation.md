# Social Login & Federation — Examples 13–18

`hearth.yaml` snippets for configuring federated identity providers (Google, GitHub, Microsoft,
Apple, and generic OIDC connectors).
Return to the [example index](./index.md) for a full list of all examples.

---

:::note `hearth.yaml` is the source of truth for federation providers.
The Admin UI's Identity Providers page is a **read-only inspection surface** — you cannot add,
edit, or delete connectors from the UI. To add or modify a provider, update `hearth.yaml` and
either restart the server or send `SIGHUP` to hot-reload. Removing a provider key from YAML
removes the connector; users who authenticated via that provider retain their local identity but
can no longer use the federated login.

This is an intentional "config-as-code" design: federation connectors contain secrets and
endpoint URLs that belong in version-controlled config files, not in a database modified through
a UI.
:::

Federation providers are configured per-realm under `realms.<name>.federation.providers`. Each
provider entry is keyed by the operator-assigned name that appears in the login URL as
`?idp=<name>`.

---

## Example 13 — Google Sign In

**Audience:** operators adding Google as a social login provider for consumer or workspace apps.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm    # require local re-auth before linking (safe default)
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
```

- Register your OAuth app at [https://console.cloud.google.com](https://console.cloud.google.com) and set the redirect URI to
  `https://auth.example.com/v1/federation/callback`.
- `link_existing_accounts: confirm` (the default) requires the user to authenticate with their
  existing password before Hearth links the Google identity to their account.

---

## Example 14 — Google + GitHub (two providers)

**Audience:** operators who want users to choose their preferred social login method.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
        github:
          type: github
          client_id:     "${GITHUB_CLIENT_ID}"
          client_secret: "${GITHUB_CLIENT_SECRET}"
```

- Each provider key (`google`, `github`) becomes the `?idp=` value in the login URL and is
  shown as a button label on the login page (overridable with `display_name`).
- GitHub uses OAuth 2.0, not OIDC — Hearth handles the protocol difference automatically.

---

## Example 15 — Microsoft Azure AD (tenant-specific)

**Audience:** operators authenticating Microsoft 365 / Entra ID users from a specific tenant.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        azure:
          type: microsoft
          display_name: "Microsoft (Contoso)"
          # Pin to your tenant to prevent cross-tenant token acceptance.
          # Replace {tenant-id} with your Azure AD tenant GUID or domain.
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
          client_id:     "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
```

- Without `issuer`, the `microsoft` preset accepts tokens from *any* Azure AD tenant — a
  security risk for single-tenant applications. Always set `issuer` in production.
- Azure maps the user's UPN to the `email` claim differently than standard OIDC. If email is
  not populated, add `claim_mappings: { email: "upn" }` to the provider block.

---

## Example 16 — Apple Sign In

**Audience:** operators building iOS/macOS apps or web apps that need "Sign in with Apple".

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      providers:
        apple:
          type: apple
          client_id:     "${APPLE_CLIENT_ID}"      # your App ID or Services ID
          client_secret: "${APPLE_CLIENT_SECRET}"  # JWT signed with your Apple private key
```

- Apple requires `client_secret` to be a short-lived JWT (ES256) signed with your Apple
  private key — not a static string. Generate it with the Apple developer tools and store it
  in the environment variable. It expires in at most 6 months.
- Register the redirect URI `https://auth.example.com/v1/federation/callback` in your Apple
  Services ID configuration.

---

## Example 17 — Generic OIDC connector (Okta / PingFederate)

**Audience:** operators integrating with an enterprise IdP that speaks OIDC but is not one of
the built-in presets.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        okta:
          type: oidc
          display_name: "Okta"
          # All four endpoint fields are required for type: oidc.
          issuer:                  "https://your-domain.okta.com"
          authorization_endpoint:  "https://your-domain.okta.com/oauth2/v1/authorize"
          token_endpoint:          "https://your-domain.okta.com/oauth2/v1/token"
          jwks_uri:                "https://your-domain.okta.com/oauth2/v1/keys"
          client_id:     "${OKTA_CLIENT_ID}"
          client_secret: "${OKTA_CLIENT_SECRET}"
          # Optional: override the default openid+email+profile scope set.
          scopes:
            - openid
            - email
            - profile
            - groups
```

For PingFederate, substitute Ping's well-known URLs. If the IdP uses non-standard claim names,
add a `claim_mappings` block:

```yaml
          claim_mappings:
            email: "upn"           # map Hearth's "email" field to the "upn" claim
            name:  "display_name"
```

- `type: oidc` requires all four endpoint fields (`issuer`, `authorization_endpoint`,
  `token_endpoint`, `jwks_uri`). For presets (`google`, `microsoft`, etc.) these are inferred.
- The optional `userinfo_endpoint` may be added for IdPs that return richer profile data there.

---

## Example 18 — Auto account-linking

**Audience:** operators who trust their federation providers' email verification and want a
frictionless first-login experience without a re-authentication prompt.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: auto    # link on verified email match without re-auth prompt
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
```

`link_existing_accounts` controls what happens when a federated email matches a local account:

| Value | Behavior |
|-------|----------|
| `disabled` | Never link — always JIT-provision a new account |
| `confirm` | Require local credential re-auth before linking (default; Keycloak-equivalent) |
| `auto` | Link immediately on verified email match — no re-auth step |

- Use `auto` only when you trust the upstream provider to verify email addresses (Google and
  Microsoft do; GitHub does not verify by default).
- `auto` removes the phishing-protection gate. A compromised upstream account can silently
  access the linked local account.

---
