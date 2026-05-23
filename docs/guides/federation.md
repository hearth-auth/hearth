# How to Configure Federation and Social Login

**Reader:** operators deploying Hearth who want to let users log in via an external identity
provider (Google, GitHub, Microsoft, Apple, a generic OIDC provider, or a SAML 2.0 IdP).

**What you need:** shell access to `hearth.yaml`, a running Hearth instance, and credentials
from the upstream IdP you are connecting.

---

## How federation works in Hearth

Federation in Hearth is **config-as-code**. Identity provider connectors are declared in
`hearth.yaml` under `realms.<name>.federation.providers` and reconciled into storage at
startup. The Admin UI **Identity Providers** page is **read-only** — you can inspect active
providers there, but you cannot add, edit, or delete them through the UI.

To change federation configuration:

1. Edit `hearth.yaml`.
2. Restart Hearth (`systemctl restart hearth`) or send `SIGHUP` to hot-reload without
   dropping existing connections:

   ```bash
   kill -HUP $(pidof hearth)
   ```

> **Keycloak operators:** in Keycloak you manage federation connectors interactively in the
> Admin Console. In Hearth that workflow moves to `hearth.yaml`, giving you a declarative,
> version-controllable source of truth. The mental-model shift is: Keycloak's **Identity
> Providers** UI → Hearth's `federation.providers` YAML block.

> **Auth0 operators:** Auth0's **Connections** (Social/Enterprise) map to
> `realms.<name>.federation.providers`. The connection slug in Auth0 becomes the provider key
> in Hearth, which also becomes the `?idp=` URL parameter on the login page.

### Login URL structure

When Hearth is configured with one or more providers, the login page renders a button for each
provider. Buttons are labeled with the provider key (overridable via `display_name`). The URL
that initiates federation is:

| Realm type | URL |
|---|---|
| Default realm | `https://auth.example.com/ui/federation/begin?idp=<name>` |
| Named realm | `https://auth.example.com/ui/realms/<realm>/federation/begin?idp=<name>` |

After the upstream IdP completes authentication it redirects back to the Hearth callback:

| Realm type | Redirect URI to register at the IdP |
|---|---|
| Default realm | `https://auth.example.com/ui/federation/callback` |
| Named realm | `https://auth.example.com/ui/realms/<realm>/federation/callback` |

Substitute `auth.example.com` with your `oidc.issuer` hostname.

---

## Setting up Google Sign In

**Use case:** consumer or Google Workspace apps where users sign in with their Google account.

### Step 1 — Create the Google OAuth client

1. Open [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Click **Create Credentials → OAuth client ID**.
3. Application type: **Web application**.
4. Under **Authorized redirect URIs**, add:
   - `https://auth.example.com/ui/federation/callback` (default realm)
   - or `https://auth.example.com/ui/realms/<realm>/federation/callback` (named realm)
5. Copy the **Client ID** and **Client secret**.

### Step 2 — Add to hearth.yaml

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm   # safe default — see Account-Linking Policy below
      providers:
        google:
          type: google
          client_id:     "${GOOGLE_CLIENT_ID}"
          client_secret: "${GOOGLE_CLIENT_SECRET}"
```

The provider key (`google`) becomes the `?idp=` value in login URLs and the button label on
the login page. Override the label with `display_name: "Sign in with Google"`.

### Step 3 — Restart or SIGHUP

```bash
kill -HUP $(pidof hearth)
# Verify the provider loaded:
curl -s https://auth.example.com/ui/federation/begin?idp=google
# Expect: redirect to accounts.google.com
```

---

## Setting up GitHub OAuth

**Use case:** developer tools, open-source portals, or any app where the user base uses GitHub.

> **Protocol note:** GitHub implements OAuth 2.0 but not OIDC. It has no ID token. Hearth
> handles this automatically — the `type: github` preset calls GitHub's `/user` and
> `/user/emails` endpoints instead of a token introspection endpoint.

### Step 1 — Create the GitHub OAuth app

1. Open **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Set **Authorization callback URL** to:
   - `https://auth.example.com/ui/federation/callback` (default realm)
   - or `https://auth.example.com/ui/realms/<realm>/federation/callback` (named realm)
3. Copy the **Client ID** and generate a **Client secret**.

### Step 2 — Add to hearth.yaml

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        github:
          type: github
          client_id:     "${GITHUB_CLIENT_ID}"
          client_secret: "${GITHUB_CLIENT_SECRET}"
```

### Step 3 — Restart or SIGHUP

```bash
kill -HUP $(pidof hearth)
```

> **Account-linking note:** GitHub does not guarantee that the email address it returns is
> verified. Do not use `link_existing_accounts: auto` with a GitHub-only realm; use `confirm`
> (the default) or `disabled`.

---

## Setting up Microsoft Azure AD (Entra ID)

**Use case:** authenticating Microsoft 365 or Entra ID users from a specific corporate tenant.

### Step 1 — Register the app in Azure

1. Open **Azure Portal → Microsoft Entra ID → App registrations → New registration**.
2. Under **Redirect URIs**, add:
   - `https://auth.example.com/ui/federation/callback` (default realm)
   - or `https://auth.example.com/ui/realms/<realm>/federation/callback` (named realm)
3. Under **Certificates & secrets**, create a new **Client secret**. Copy its value.
4. Copy the **Application (client) ID** and the **Directory (tenant) ID**.

### Step 2 — Add to hearth.yaml

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
          # Always pin to your tenant to prevent cross-tenant token acceptance.
          issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
          client_id:     "${AZURE_CLIENT_ID}"
          client_secret: "${AZURE_CLIENT_SECRET}"
```

> **Security:** omitting `issuer` causes Hearth to accept tokens from *any* Azure AD
> tenant — a critical misconfiguration for single-tenant applications. Always set `issuer`
> in production.

### Azure UPN claim mapping

Some Azure AD tenants do not populate the standard OIDC `email` claim; they use `upn`
instead. If users cannot log in and you see an empty email error in the audit log:

```yaml
          claim_mappings:
            email: "upn"
```

See [Custom claim mappings](#custom-claim-mappings) for more detail.

---

## Setting up Apple Sign In

**Use case:** iOS/macOS apps and web apps that require "Sign in with Apple".

### Step 1 — Create an Apple Services ID

1. Open **Apple Developer Portal → Certificates, Identifiers & Profiles → Identifiers**.
2. Create a new **Services ID** (type: Services).
3. Under the Services ID, enable **Sign in with Apple** and add the redirect URI:
   - `https://auth.example.com/ui/federation/callback`
4. Note your **Services ID** (this is `client_id`).

### Step 2 — Generate the client_secret JWT

Apple requires `client_secret` to be a short-lived ES256 JWT signed with your Apple private
key — not a static string. Generate it with the `ruby` script from Apple's documentation or
the `apple-client-secret-gen` CLI. The JWT expires in at most 6 months and must be regenerated
before expiry.

Store the generated JWT in an environment variable:

```bash
export APPLE_CLIENT_SECRET="eyJhbGci..."
```

### Step 3 — Add to hearth.yaml

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      providers:
        apple:
          type: apple
          client_id:     "${APPLE_CLIENT_ID}"      # your Services ID
          client_secret: "${APPLE_CLIENT_SECRET}"  # short-lived ES256 JWT
```

---

## Setting up a generic OIDC provider (Okta, PingFederate, etc.)

**Use case:** connecting to an enterprise IdP that speaks OIDC Core 1.0 but is not one of the
built-in presets.

### Step 1 — Register a client at the IdP

In your IdP's admin console, create an OAuth client / application with:
- **Grant type:** Authorization Code with PKCE
- **Redirect URI:** `https://auth.example.com/ui/realms/<realm>/federation/callback`

Collect: **Client ID**, **Client secret**, and the four well-known URLs (issuer, authorization
endpoint, token endpoint, JWKS URI). Most OIDC providers publish these at
`<issuer>/.well-known/openid-configuration`.

### Step 2 — Add to hearth.yaml

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
          issuer:                 "https://your-domain.okta.com"
          authorization_endpoint: "https://your-domain.okta.com/oauth2/v1/authorize"
          token_endpoint:         "https://your-domain.okta.com/oauth2/v1/token"
          jwks_uri:               "https://your-domain.okta.com/oauth2/v1/keys"
          client_id:     "${OKTA_CLIENT_ID}"
          client_secret: "${OKTA_CLIENT_SECRET}"
          # Optional: add extra scopes your app needs.
          scopes:
            - openid
            - email
            - profile
            - groups
```

For **PingFederate**, substitute Ping's base URL for `your-domain.okta.com` above.

> `type: oidc` requires all four endpoint fields (`issuer`, `authorization_endpoint`,
> `token_endpoint`, `jwks_uri`). For presets (`google`, `microsoft`, `apple`, `github`)
> these are inferred and do not need to be supplied.

> The optional `userinfo_endpoint` field can be added for IdPs that return richer claims
> there than in the ID token.

---

## Setting up SAML federation (Hearth as SP)

**Use case:** enterprise customers or internal tooling where the IdP only supports SAML 2.0
(Okta SAML, Azure AD SAML, ADFS, Shibboleth, OneLogin, etc.).

In this setup Hearth acts as the **Service Provider (SP)** and the upstream directory is the
**Identity Provider (IdP)**.

> **Keycloak operators:** Keycloak's **Identity Providers → SAML v2.0** configuration maps
> directly to the `type: saml` provider block in Hearth. See the
> [Keycloak mapping table](#keycloak--hearth-federation-mapping) below.

### Step 1 — Retrieve Hearth's SP metadata

Before registering with the IdP, get Hearth's SP metadata. Hearth generates it dynamically:

```bash
curl -s "https://auth.example.com/ui/realms/<realm>/federation/saml/metadata?idp=<provider-name>"
```

The metadata XML contains Hearth's SP **entity ID** and **Assertion Consumer Service (ACS)**
URL. You will need both when registering Hearth at the IdP.

The ACS URL has the form:
```
https://auth.example.com/ui/realms/<realm>/federation/saml/acs
```

### Step 2 — Register Hearth as an SP at the IdP

In your IdP's admin console, create a new SAML application/trust and supply:
- **SP entity ID** — from the metadata (`entityID` attribute of `<EntityDescriptor>`)
- **ACS URL** — `https://auth.example.com/ui/realms/<realm>/federation/saml/acs`
- **Name ID format** — `emailAddress` (recommended) or `persistent`
- **Attribute mapping** — map email to `NameID` or a standard attribute URI

Download the IdP's **metadata XML** or copy its **entity ID**, **SSO URL**, and
**signing certificate**.

### Step 3 — Add to hearth.yaml

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    federation:
      link_existing_accounts: confirm
      providers:
        corp-saml:
          type: saml
          display_name: "Corporate SSO"
          entity_id: "https://idp.corp.example/saml2"      # IdP entity ID
          sso_url:   "https://idp.corp.example/saml2/sso"  # IdP SSO URL (HTTP-Redirect)
          # Paste the IdP signing certificate PEM inline.
          idp_certificate_pem: |
            -----BEGIN CERTIFICATE-----
            MIICmzCCAYMCBgF...
            -----END CERTIFICATE-----
          sign_authn_requests: true    # recommended; requires IdP to trust Hearth's SP cert
          want_assertions_signed: true # reject unsigned assertions
          # Map SAML attributes to Hearth user fields.
          attribute_map:
            email: "urn:oid:0.9.2342.19200300.100.1.3"   # mail OID
            name:  "urn:oid:2.16.840.1.113730.3.1.241"   # displayName OID
```

SAML login is initiated at:
```
https://auth.example.com/ui/realms/<realm>/federation/saml/begin?idp=corp-saml
```

> **`attribute_map` vs `claim_mappings`:** for `type: saml` use `attribute_map` (maps Hearth
> field names to SAML attribute URIs). The `claim_mappings` field is only meaningful for OIDC
> and OAuth2 providers and is silently ignored for SAML.

### SAML field reference

| Field | Required | Description |
|---|---|---|
| `entity_id` | Yes | IdP SAML entity ID (`entityID` in IdP metadata) |
| `sso_url` | Yes | IdP Single Sign-On Service URL (HTTP-Redirect binding) |
| `slo_url` | No | IdP Single Logout Service URL |
| `idp_certificate_pem` | Yes | IdP signing certificate, PEM-encoded (inline) |
| `sign_authn_requests` | No | Sign outbound AuthnRequests (default: false) |
| `want_assertions_signed` | No | Reject unsigned assertions (default: false; set true in production) |
| `attribute_map` | No | Maps Hearth field names to SAML attribute URIs |

---

## Account-linking policy

`link_existing_accounts` controls what happens when a federated identity asserts an email
address that matches an existing local Hearth user.

```yaml
realms:
  default:
    federation:
      link_existing_accounts: confirm   # default
```

| Value | Behavior | When to use |
|---|---|---|
| `disabled` | Never link — always JIT-provision a new account, even if the email matches | Strict isolation; users get separate accounts per IdP |
| `confirm` | Prompt the user to authenticate with their local password or passkey before linking **(default; Keycloak-equivalent safety posture)** | Any public-facing realm |
| `auto` | Silently link on verified email match — no re-auth step | Single high-trust IdP where the IdP verifies email (Google, Microsoft) |

> **`auto` security note:** `auto` removes the phishing-protection gate. A compromised
> upstream account can silently access the linked local Hearth account. Only use `auto` when:
> (1) the upstream IdP verifies email addresses, and (2) your realm federates to exactly one
> IdP. Google and Microsoft verify email; GitHub does **not** by default.

> **Keycloak equivalent:** Keycloak's **First Broker Login** authentication flow with the
> "Detect Existing Account" and "Confirm Link Existing Account" steps maps to Hearth's
> `link_existing_accounts: confirm`.

---

## Custom claim mappings

By default Hearth reads the standard OIDC claims (`email`, `name`, `sub`) from the upstream
token. Some IdPs use non-standard claim names. Use `claim_mappings` to remap them.

```yaml
providers:
  azure:
    type: microsoft
    issuer: "https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0"
    client_id:     "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
    claim_mappings:
      email: "upn"            # Azure AD: map Hearth's "email" to the "upn" claim
      name:  "display_name"   # optional: map Hearth's "name" to "display_name"
```

The key is the **Hearth field name** (`email`, `name`); the value is the **upstream claim
name** as it appears in the ID token or userinfo response.

Common remappings:

| Provider | Hearth field | Upstream claim |
|---|---|---|
| Azure AD | `email` | `upn` |
| Azure AD (some tenants) | `email` | `preferred_username` |
| Okta (custom app) | `email` | `email_address` |
| PingFederate | `name` | `cn` |

> `claim_mappings` applies only to `type: oidc`, `google`, `microsoft`, `apple`, and `github`
> providers. For `type: saml`, use `attribute_map` instead (see the SAML section above).

---

## Keycloak → Hearth federation mapping

| Keycloak concept | Hearth equivalent | Notes |
|---|---|---|
| **Identity Providers** (Admin Console → Identity Providers → Add) | `realms.<name>.federation.providers` in `hearth.yaml` | Hearth's providers are YAML-only; UI is read-only |
| **Identity Provider type: Google** | `type: google` | Same OAuth 2.0 / OIDC flow |
| **Identity Provider type: GitHub** | `type: github` | Same OAuth 2.0 flow (no OIDC) |
| **Identity Provider type: Microsoft** | `type: microsoft` | Add `issuer` to pin to a specific tenant |
| **Identity Provider type: OIDC v1.0** | `type: oidc` | Supply `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` |
| **Identity Provider type: SAML v2.0** | `type: saml` | Supply `entity_id`, `sso_url`, `idp_certificate_pem` |
| **Display Name** | `display_name` | Optional; defaults to the provider key |
| **Client ID / Client Secret** | `client_id` / `client_secret` | Same semantics |
| **Default Scopes** | `scopes` | Defaults to `openid email profile` for OIDC |
| **Issuer / validateSignature** | `issuer` / `jwks_uri` | Hearth always validates signatures |
| **First Broker Login → "Detect Existing Account"** | `link_existing_accounts: confirm` | Keycloak's default; Hearth's default |
| **First Broker Login → no detection** | `link_existing_accounts: disabled` | JIT-provision only |
| **Trust Email** (First Broker Login) | `link_existing_accounts: auto` | Auto-link on verified email match |
| **Identity Provider Mapper: Hardcoded Role** | Hearth RBAC role assignment on first JIT-provision | Configure in `realms.<name>.roles` |
| **Identity Provider Mapper: Attribute Importer** | `claim_mappings` (OIDC) or `attribute_map` (SAML) | |
| **SAML → Mapper: User Attribute** | `attribute_map: { <hearth-field>: "<saml-uri>" }` | |
| **SAML → NameID format** | Configured at the IdP; Hearth reads `NameID` automatically | |
| **SAML → Want AuthnRequests Signed** | `sign_authn_requests: true` | |
| **SAML → Validate Signatures** | `want_assertions_signed: true` | Recommended for production |
| **LDAP User Federation** | Not supported | Hearth does not support LDAP |

---

## Auth0 Connection → Hearth federation mapping

| Auth0 concept | Hearth equivalent | Notes |
|---|---|---|
| **Connections → Social → Google** | `type: google` | |
| **Connections → Social → GitHub** | `type: github` | |
| **Connections → Enterprise → Microsoft Entra ID** | `type: microsoft` with `issuer` tenant pin | |
| **Connections → Enterprise → OIDC** | `type: oidc` with explicit endpoints | |
| **Connections → Enterprise → SAML** | `type: saml` | |
| **Connection Name** | Provider key (the map key under `providers:`) | Becomes the `?idp=` URL parameter |
| **Display Name** | `display_name` | |
| **Client ID / Client Secret** | `client_id` / `client_secret` | |
| **Scope** | `scopes` list | |
| **Attribute Mapping** | `claim_mappings` (OIDC) or `attribute_map` (SAML) | |
| **Default action: link accounts** | `link_existing_accounts: auto` | Only for high-trust IdPs |
| **Default action: always create new user** | `link_existing_accounts: disabled` | |
| **Require identifier re-login before linking** | `link_existing_accounts: confirm` (default) | |
| **SAML → IdP URL** | `sso_url` | |
| **SAML → IdP Signing Certificate** | `idp_certificate_pem` | Paste PEM inline or use `${ENV_VAR}` |
| **SAML → User ID Attribute** | `attribute_map: { email: "<uri>" }` | |
| **AD/LDAP connector** | Not supported | Hearth does not support LDAP or AD connectors |
| **Connections → Passwordless** | Built-in to Hearth (magic link) | Configure under `realms.<name>.onboarding` |

---

## Full provider field reference

The following fields are available on every provider entry. Fields marked *preset-inferred*
are auto-populated for named presets (`google`, `microsoft`, `apple`, `github`) and do not
need to be specified unless you want to override a default.

| Field | Type | Presets | Description |
|---|---|---|---|
| `type` | string | — | **Required.** One of: `google`, `microsoft`, `apple`, `github`, `oidc`, `saml` |
| `display_name` | string | optional | Button label shown on the login page |
| `client_id` | string | required | OAuth client ID registered at the upstream IdP |
| `client_secret` | string | required | OAuth client secret (use env var: `"${MY_SECRET}"`) |
| `issuer` | string | preset-inferred | OIDC issuer URL. Required for `type: oidc`. Use on `microsoft` to pin a tenant. |
| `authorization_endpoint` | string | preset-inferred | Required for `type: oidc` |
| `token_endpoint` | string | preset-inferred | Required for `type: oidc` |
| `jwks_uri` | string | preset-inferred | Required for `type: oidc` |
| `userinfo_endpoint` | string | preset-inferred | Optional even for `type: oidc` |
| `scopes` | list of strings | preset-inferred | Defaults to `[openid, email, profile]` for OIDC types |
| `claim_mappings` | map | — | OIDC/OAuth2 only. Renames upstream claims to Hearth field names |
| `entity_id` | string | — | **SAML only.** IdP entity ID |
| `sso_url` | string | — | **SAML only.** IdP SSO URL (HTTP-Redirect binding) |
| `slo_url` | string | — | **SAML only.** IdP Single Logout URL (optional) |
| `idp_certificate_pem` | string | — | **SAML only.** IdP signing certificate, PEM inline |
| `sign_authn_requests` | bool | — | **SAML only.** Sign outbound AuthnRequests (default: false) |
| `want_assertions_signed` | bool | — | **SAML only.** Reject unsigned assertions (default: false) |
| `attribute_map` | map | — | **SAML only.** Maps Hearth field names to SAML attribute URIs |
