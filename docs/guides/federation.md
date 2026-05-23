# Federation and social login

This guide walks through connecting external identity providers (IdPs) to Hearth — Google, GitHub, Microsoft Azure AD, Apple, generic OIDC, and SAML 2.0. Each section covers the prerequisite steps on the IdP side, the `hearth.yaml` snippet, and how to verify the connection.

## 1. How federation works in Hearth

Hearth's federation configuration lives entirely in `hearth.yaml`. The admin UI is **read-only** for federation settings — changes must be made in the config file.

**Callback URL** — all providers share the same redirect URI pattern:

```
https://<hearth-host>/ui/federation/callback/<provider-name>
```

The `<provider-name>` is the key you give the provider in `hearth.yaml` (e.g. `google`, `github`, `corp-azure`).

**Applying changes without downtime** — send `SIGHUP` to reload `hearth.yaml` without restarting:

```bash
kill -HUP $(pidof hearth)
```

**Account lifecycle** — when a federated user authenticates for the first time, Hearth creates a local account and links it to the provider. The `link_existing_accounts` setting (§8) controls what happens when the incoming email already belongs to a local account.

---

## 2. Google Sign In

### On the Google side

1. Open [Google Cloud Console](https://console.cloud.google.com/) → **APIs & Services** → **Credentials**.
2. Click **Create credentials** → **OAuth client ID**.
3. Set **Application type**: `Web application`.
4. Under **Authorized redirect URIs**, add:
   ```
   https://<hearth-host>/ui/federation/callback/google
   ```
5. Copy the **Client ID** and **Client Secret**.

### In `hearth.yaml`

```yaml
realms:
  default:
    federation:
      providers:
        google:
          type: google
          display_name: "Sign in with Google"
          client_id: "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
```

**`GOOGLE_CLIENT_ID`** and **`GOOGLE_CLIENT_SECRET`** must be set in the environment before starting Hearth. The `${ENV_VAR}` substitution prevents secrets from appearing in the config file.

### Verify

1. Reload with `SIGHUP` (or restart).
2. Visit your login page — a **Sign in with Google** button should appear.
3. Complete the OAuth flow and confirm Hearth issues a session.

---

## 3. GitHub OAuth

> **Note:** GitHub does not implement OIDC. Hearth uses GitHub's OAuth 2.0 API directly (`type: github`). GitHub does not return an `id_token`, so Hearth calls the GitHub `/user` and `/user/emails` APIs to retrieve the user profile.
>
> GitHub accounts with unverified primary email addresses will be rejected. Ensure the GitHub account has a verified primary email.

### On the GitHub side

1. Go to **Settings** → **Developer settings** → **OAuth Apps** → **New OAuth App**.
2. Set **Authorization callback URL**:
   ```
   https://<hearth-host>/ui/federation/callback/github
   ```
3. Copy the **Client ID** and generate a **Client secret**.

### In `hearth.yaml`

```yaml
realms:
  default:
    federation:
      providers:
        github:
          type: github
          display_name: "Sign in with GitHub"
          client_id: "${GITHUB_CLIENT_ID}"
          client_secret: "${GITHUB_CLIENT_SECRET}"
```

---

## 4. Microsoft Azure AD

### On the Azure side

1. Open **Azure Portal** → **Azure Active Directory** → **App registrations** → **New registration**.
2. Under **Redirect URI**, select **Web** and add:
   ```
   https://<hearth-host>/ui/federation/callback/microsoft
   ```
3. Copy the **Application (client) ID**.
4. Under **Certificates & secrets**, create a **New client secret** and copy the value.
5. Note your **Tenant ID** from **Overview** → **Directory (tenant) ID**.

### In `hearth.yaml`

**Single-tenant** (restrict to your org — recommended):

```yaml
realms:
  default:
    federation:
      providers:
        microsoft:
          type: microsoft
          display_name: "Sign in with Microsoft"
          client_id: "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
```

Setting `issuer` to your tenant-specific URL pins the token issuer to your organization. Tokens from other tenants will be rejected. **Always set this in production.**

**Multi-tenant** (allows any Azure AD account — use only if intentional):

```yaml
issuer: "https://login.microsoftonline.com/common/v2.0"
```

### Azure AD and the `upn` claim

Azure AD includes a `upn` (User Principal Name) claim that may differ from `email` for some accounts. If users' email addresses come from `upn`, add a `claim_mappings` entry:

```yaml
claim_mappings:
  email: "upn"
```

See §9 for full claim-mapping documentation.

---

## 5. Apple Sign In

> **Note:** Apple requires an **ES256-signed JWT** as the `client_secret`, not a static credential. The JWT must be regenerated before it expires (maximum validity: 6 months). See [Apple's documentation](https://developer.apple.com/documentation/accountorganizationsandworkforce/generating-a-client-secret) for the generation procedure.

### On the Apple side

1. In the [Apple Developer Portal](https://developer.apple.com/account/), go to **Certificates, IDs & Profiles** → **Identifiers**.
2. Register a **Services ID** (this is your `client_id`).
3. Enable **Sign in with Apple** for the Services ID and add your redirect URL:
   ```
   https://<hearth-host>/ui/federation/callback/apple
   ```
4. Create a **Key** with Sign in with Apple enabled and download the `.p8` file.
5. Generate the JWT `client_secret` using the key, Key ID, Team ID, and Services ID. Store the generated JWT in `APPLE_CLIENT_SECRET`.

### In `hearth.yaml`

```yaml
realms:
  default:
    federation:
      providers:
        apple:
          type: apple
          display_name: "Sign in with Apple"
          client_id: "${APPLE_CLIENT_ID}"        # Your Services ID
          client_secret: "${APPLE_CLIENT_SECRET}" # The generated ES256 JWT
```

Rotate `APPLE_CLIENT_SECRET` before it expires and send `SIGHUP` to pick up the new value.

---

## 6. Generic OIDC (Okta, PingFederate, etc.)

Use `type: oidc` for any OIDC-compliant provider that is not one of the pre-configured types.

### Using OIDC discovery (recommended)

If the provider exposes a discovery document at `<issuer>/.well-known/openid-configuration`, supply only `issuer`:

```yaml
realms:
  default:
    federation:
      providers:
        okta:
          type: oidc
          display_name: "Sign in with Okta"
          client_id: "${OKTA_CLIENT_ID}"
          client_secret: "${OKTA_CLIENT_SECRET}"
          issuer: "https://<your-okta-domain>/oauth2/default"
```

Hearth fetches the discovery document at startup and on `SIGHUP` to resolve the authorization, token, userinfo, and JWKS endpoints.

### Explicit endpoints (when discovery is unavailable)

Supply all four endpoints manually:

```yaml
realms:
  default:
    federation:
      providers:
        pingfed:
          type: oidc
          display_name: "Corporate SSO"
          client_id: "${PING_CLIENT_ID}"
          client_secret: "${PING_CLIENT_SECRET}"
          authorization_endpoint: "https://sso.corp.example.com/as/authorization.oauth2"
          token_endpoint: "https://sso.corp.example.com/as/token.oauth2"
          userinfo_endpoint: "https://sso.corp.example.com/idp/userinfo.openid"
          jwks_uri: "https://sso.corp.example.com/pf/JWKS"
```

### Custom scopes

Override the default `["openid", "email", "profile"]` scope set:

```yaml
scopes: ["openid", "email", "profile", "groups"]
```

---

## 7. SAML 2.0 federation

Hearth acts as the **Service Provider (SP)** in SAML flows. The IdP initiates or receives SAML assertions at Hearth's ACS (Assertion Consumer Service) URL.

**Hearth's SP metadata endpoint:**

```
https://<hearth-host>/ui/federation/saml/<provider-name>/metadata
```

Provide this URL to your IdP admin to import Hearth's SP metadata automatically. The metadata includes the ACS URL, entity ID, and (if `sign_authn_requests: true`) Hearth's signing certificate.

**ACS URL** (use this if your IdP requires it explicitly):

```
https://<hearth-host>/ui/federation/callback/<provider-name>
```

### In `hearth.yaml`

```yaml
realms:
  default:
    federation:
      providers:
        corp-saml:
          type: saml
          display_name: "Corporate SSO"
          sso_url: "https://idp.corp.example.com/sso/saml"
          entity_id: "https://idp.corp.example.com"
          idp_certificate_pem: "${CORP_SAML_CERT_PEM}"
          slo_url: "https://idp.corp.example.com/slo/saml"       # optional
          sign_authn_requests: true
          want_assertions_signed: true
          attribute_map:
            email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
```

### SAML field reference

| Field | Required | Description |
|-------|----------|-------------|
| `sso_url` | yes | IdP Single Sign-On URL. Hearth POSTs SAMLRequests here. |
| `entity_id` | yes | IdP entity ID. Must match `EntityDescriptor/@entityID` in IdP metadata exactly. |
| `idp_certificate_pem` | yes | PEM-encoded X.509 cert used to verify IdP-signed assertions. |
| `attribute_map` | no | Hearth claim name → SAML attribute name mapping. See §9. |
| `slo_url` | no | IdP Single Logout URL. When set, Hearth participates in IdP-initiated SLO. |
| `sign_authn_requests` | no (default: `false`) | Sign outbound AuthnRequests with the realm's signing key. |
| `want_assertions_signed` | no (default: `true`) | Reject unsigned or invalidly-signed assertions. Disable only if the IdP cannot sign assertions. |

### Storing the IdP certificate

The IdP certificate is PEM text (begins with `-----BEGIN CERTIFICATE-----`). The safest approach is to export it as an environment variable with newlines preserved:

```bash
export CORP_SAML_CERT_PEM="$(cat idp-cert.pem)"
```

Then reference it in config as `"${CORP_SAML_CERT_PEM}"`.

---

## 8. Account-linking policy

The `link_existing_accounts` setting controls what happens when a federated user's email matches a Hearth account that was created through a different method (e.g. password signup or a different provider).

```yaml
realms:
  default:
    federation:
      link_existing_accounts: confirm   # disabled | confirm | auto
```

| Value | Behavior |
|-------|----------|
| `disabled` | Reject the login and show an error. Use this if account merging must not happen automatically. |
| `confirm` | Show the user a confirmation prompt before linking. The user must acknowledge that the existing account will be linked. **(Default)** |
| `auto` | Silently link without user interaction. Use only when the IdP is trusted to provide authoritative email addresses. |

> **Security note for `auto`:** If an attacker can register an IdP account with a victim's email address, `auto` linking grants them access to the victim's Hearth account. Only use `auto` when the IdP performs verified email validation (e.g. corporate Azure AD with domain restrictions).

This setting applies globally to all providers in the realm. Once two accounts are linked, all future logins from that provider go to the linked account regardless of this setting.

---

## 9. Custom claim mappings

Use claim mappings when the IdP uses non-standard claim names.

### OIDC: `claim_mappings`

`claim_mappings` maps Hearth's internal claim names to the field names present in the IdP's JWT or userinfo response.

```yaml
providers:
  microsoft:
    type: microsoft
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
    issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
    claim_mappings:
      email: "upn"           # read email from Azure's 'upn' claim
      name: "displayName"    # read display name from 'displayName' claim
```

### SAML: `attribute_map`

`attribute_map` maps Hearth's internal claim names to SAML attribute names as they appear in the IdP's assertion.

```yaml
providers:
  corp-saml:
    type: saml
    sso_url: "https://idp.corp.example.com/sso/saml"
    entity_id: "https://idp.corp.example.com"
    idp_certificate_pem: "${CORP_SAML_CERT_PEM}"
    attribute_map:
      email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
      name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
      groups: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
```

> **Footgun:** `claim_mappings` is for OIDC providers; `attribute_map` is for SAML. They are not interchangeable. Swapping them silently fails — the user can authenticate but the mapped claim will be empty.

---

## 10. Keycloak → Hearth federation mapping

| Keycloak concept | Hearth equivalent | Notes |
|-----------------|-------------------|-------|
| **Identity Provider** | `federation.providers.<name>` | The provider key is used in the callback URL |
| **IdP type: OpenID Connect v1.0** | `type: oidc` | Supply `issuer` for discovery |
| **IdP type: SAML v2.0** | `type: saml` | Supply `sso_url`, `entity_id`, `idp_certificate_pem` |
| **IdP type: Google** | `type: google` | Pre-configured, no endpoints needed |
| **IdP type: GitHub** | `type: github` | Pre-configured; GitHub is OAuth2, not OIDC |
| **Discovery Endpoint URL** | `issuer` | Hearth fetches `<issuer>/.well-known/openid-configuration` |
| **Client ID** | `client_id` | Supports `${ENV_VAR}` substitution |
| **Client Secret** | `client_secret` | Supports `${ENV_VAR}` substitution |
| **Default Scopes** | `scopes` | Default: `["openid","email","profile"]` |
| **Mapper: OIDC claim → attribute** | `claim_mappings` | `hearth_claim: "idp_claim_name"` |
| **Mapper: SAML attribute → attribute** | `attribute_map` | `hearth_claim: "saml_attribute_urn"` |
| **First Login Flow: account linking** | `link_existing_accounts` | `disabled`, `confirm`, or `auto` |
| **Sync mode** | — | Hearth re-reads claims on every login; no explicit sync mode needed |
| **Trust email** | — | Hearth trusts email from all configured providers; restrict via `link_existing_accounts: disabled` if needed |

---

## 11. Auth0 Connection → Hearth federation mapping

| Auth0 concept | Hearth equivalent | Notes |
|--------------|-------------------|-------|
| **Social Connection: Google** | `type: google` | Pre-configured |
| **Social Connection: GitHub** | `type: github` | Pre-configured |
| **Social Connection: Microsoft** | `type: microsoft` | Pre-configured; set `issuer` for tenant-pinning |
| **Social Connection: Apple** | `type: apple` | Pre-configured; JWT `client_secret` required |
| **Enterprise Connection: OIDC** | `type: oidc` | Supply `issuer` or explicit endpoints |
| **Enterprise Connection: SAML** | `type: saml` | Supply `sso_url`, `entity_id`, `idp_certificate_pem` |
| **Connection Name** | provider key in `federation.providers` | Used in the callback URL |
| **Client ID / Client Secret** | `client_id` / `client_secret` | Supports `${ENV_VAR}` |
| **Scopes** | `scopes` | List of OAuth scopes to request |
| **Attribute Mapping (OIDC)** | `claim_mappings` | Map Hearth claim → IdP JWT claim name |
| **Attribute Mapping (SAML)** | `attribute_map` | Map Hearth claim → SAML attribute URN |
| **Action: link accounts** | `link_existing_accounts` | `disabled`, `confirm`, or `auto` |
| **Connection enabled/disabled** | remove/add the provider block | Hearth reloads on `SIGHUP` |
| **Verified email required** | — | GitHub requires verified primary email; others inherit IdP guarantee |

---

## Complete example

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

        github:
          type: github
          display_name: "Sign in with GitHub"
          client_id: "${GITHUB_CLIENT_ID}"
          client_secret: "${GITHUB_CLIENT_SECRET}"

        microsoft:
          type: microsoft
          display_name: "Sign in with Microsoft"
          client_id: "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
          claim_mappings:
            email: "upn"

        okta:
          type: oidc
          display_name: "Sign in with Okta"
          client_id: "${OKTA_CLIENT_ID}"
          client_secret: "${OKTA_CLIENT_SECRET}"
          issuer: "https://<your-okta-domain>/oauth2/default"

        corp-saml:
          type: saml
          display_name: "Corporate SSO"
          sso_url: "https://idp.corp.example.com/sso/saml"
          entity_id: "https://idp.corp.example.com"
          idp_certificate_pem: "${CORP_SAML_CERT_PEM}"
          sign_authn_requests: true
          want_assertions_signed: true
          attribute_map:
            email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
```

---

## See also

- [Configuration reference](../specs/CONFIGURATION.md) — full `hearth.yaml` field reference for `federation`
- [Getting started](./getting-started.md) — client registration and OAuth flows
- [Deployment guide](./deployment.md) — production setup and SIGHUP reload
