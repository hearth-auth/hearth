# MFA — Examples 10–12

`hearth.yaml` snippets for multi-factor authentication: TOTP, WebAuthn second factors, and
passkey combinations. Valid `mfa_methods` values are `totp`, `webauthn` and `email_otp`.
Return to the [example index](./index.md) for a full list of all examples.

---

## Example 10 — MFA required globally (TOTP)

**Audience:** operators in security-conscious environments (SOC 2, HIPAA) who must enforce a
second factor for all users across all realms.

```yaml
auth:
  mfa_required: true       # global default — applies to every realm unless overridden

oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      mfa_methods:
        - totp             # time-based one-time password (Google Authenticator, Authy, etc.)
```

- MFA is required by default. `auth.mfa_required: true` states the default explicitly.
  Opt out globally or per realm with `mfa_required: false`. A realm value wins over the global value.
- When a realm's MFA is off, startup logs one `WARN` that names every such realm.
- `mfa_methods` controls which second factors are accepted. When absent, all enrolled factors
  are accepted. When MFA is required, a set list must include `totp` or `webauthn`. A list with
  only `email_otp` stops startup.
- Only a passkey, a TOTP code or a recovery code satisfies MFA. Email OTP and magic links do not.
- Users without an enrolled factor are redirected to MFA enrollment on first login.

---

## Example 11 — MFA required (TOTP + WebAuthn)

**Audience:** operators who want users to choose their preferred second factor: TOTP app or a
hardware security key.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - webauthn         # security keys (YubiKey, etc.) used as a second factor
```

- `webauthn` as an MFA method means users authenticate with a password first, then confirm with
  a security key. This is distinct from `passkey` (which is a first-factor, passwordless flow).
- Users may enroll multiple factors; any enrolled and allowed factor satisfies the MFA gate.

---

## Example 12 — Passkey + TOTP backup

**Audience:** regulated environments (FedRAMP, PCI-DSS) that require an additional OTP challenge
even after a phishing-resistant passkey authentication.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  default:
    auth:
      allowed_auth_methods:
        - passkey
        - password          # keep password as fallback; remove if fully passkey-only
      passkey_requires_mfa: true   # enforce TOTP step after passkey authentication
      mfa_methods:
        - totp
```

- Passkeys are inherently multi-factor (possession + biometric). `passkey_requires_mfa: true`
  adds an explicit TOTP step on top — use only when a compliance control explicitly mandates it.
- Setting `passkey_requires_mfa: true` without configuring `mfa_methods` accepts all enrolled
  MFA factors (TOTP and WebAuthn hardware keys).

---

## Example 42 — removed

Adaptive (risk-based) step-up MFA and SMS codes were removed in Hearth 3.0.0. Use
`mfa_required` with TOTP or WebAuthn instead. Email OTP does not satisfy `mfa_required`.
