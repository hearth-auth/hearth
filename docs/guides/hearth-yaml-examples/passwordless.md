# Passwordless — Examples 7–9

`hearth.yaml` snippets for magic-link and passkey authentication flows.
Return to the [example index](./index.md) for a full list of all examples.

---

## Example 7 — Magic link only

**Audience:** operators building consumer apps where password friction hurts conversion, or
internal tools where phishing resistance matters more than convenience.

```yaml
email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls          # none | starttls | tls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"  # used in magic-link URLs sent via email

realms:
  default:
    auth:
      allowed_auth_methods:
        - magic_link
      registration:
        mode: open
```

- `email` must be configured with a real transport; magic links cannot be delivered via the
  default `log` transport in production.
- `onboarding.base_url` (or `oidc.issuer`) is used to construct the clickable link in emails.
- Users who previously had passwords can no longer log in with them once `allowed_auth_methods`
  excludes `password`.

---

## Example 8 — Passkey / WebAuthn only

**Audience:** operators building high-assurance applications where phishing-resistant
authentication is required (FIDO2 / WebAuthn Level 2).

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      allowed_auth_methods:
        - passkey
      registration:
        mode: open
```

- Restricting `allowed_auth_methods` to `[passkey]` disables all other login methods for this
  realm; Hearth will reject password and magic-link login attempts with `401`.
- WebAuthn relying-party policy (user verification requirement, resident-key preference) is
  configured at runtime via the Admin API — these are not `hearth.yaml` keys.
- Passkey enrollment requires the user to complete at least one prior authentication; provision
  accounts via the admin API or an invitation flow.

---

## Example 9 — Combined passwordless (magic link + passkey)

**Audience:** operators who want a fully passwordless experience with a fallback for users whose
device does not support passkeys.

```yaml
email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"

realms:
  default:
    auth:
      allowed_auth_methods:
        - magic_link
        - passkey
      registration:
        mode: open
```

- Users are presented with both options on the login page; the UI highlights passkeys when the
  browser supports them.
- `password` is omitted from `allowed_auth_methods`, so password auth is disabled.
- Ensure `email` is configured — magic link delivery fails silently with the `log` transport.

---
