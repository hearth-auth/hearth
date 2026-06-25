# MFA — Examples 10–12, 42

`hearth.yaml` snippets for multi-factor authentication: TOTP, WebAuthn second factors, passkey
combinations, and adaptive/risk-based step-up MFA.
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

- `auth.mfa_required: true` at the top level enables MFA globally. Override per-realm with
  `realms.<name>.auth.mfa_required: false`.
- `mfa_methods` controls which second factors are accepted. When absent, all enrolled factors
  are accepted.
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

## Example 42 — Risk-based step-up MFA (adaptive)

**Audience:** operators who want MFA challenges only when a user logs in from an unrecognised
device or IP range, rather than on every single login. Useful for consumer applications where
constant MFA friction hurts retention, or for internal tools where you want a security signal
without mandatory TOTP enrollment.

Adaptive MFA is separate from, and complementary to, `mfa_required`. A user who already
passed their regular MFA challenge this session will not be challenged again for a recognised
device.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  customer-portal:
    auth:
      mfa_required: false              # no MFA on every login — only on unknown devices
      mfa_methods:
        - totp
        - webauthn
      adaptive_mfa:
        enabled: true
        recognition_window_days: 30   # device stays "recognised" for 30 days (default)
        # MUST come from an external secret store — never a literal value.
        # Generate: openssl rand -base64 32
        fingerprint_hmac_secret: "${HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET}"
```

How recognition works:

1. On each login, Hearth computes `HMAC-SHA256(secret, "{user_id}:{ip_/24}:{user_agent_normalized}")`.
2. If the resulting hex digest is found in the device-fingerprint store and is within
   `recognition_window_days`, the login proceeds without an additional MFA challenge.
3. If no match is found, the user is redirected to the MFA challenge page. On success, the
   fingerprint is stored for future logins.

Combining adaptive MFA with `mfa_required: true` is valid — the step-up fires on unrecognised
devices; regular enrolled-MFA fires on every login:

```yaml
    auth:
      mfa_required: true             # always require MFA
      mfa_methods:
        - totp
      adaptive_mfa:
        enabled: true
        recognition_window_days: 7  # tighter recognition window for high-security realms
        fingerprint_hmac_secret: "${HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET}"
```

Key operational notes:

- `fingerprint_hmac_secret` must be at least 32 bytes. Hearth fails closed at startup if the
  value is shorter — no silent fail-open. Generate with `openssl rand -base64 32` (44 chars,
  well above the minimum).
- Rotating the secret invalidates every stored fingerprint for the realm — all active users
  will be challenged once on their next login. Schedule rotations outside peak hours.
- See [Device fingerprint HMAC secret](../security-hardening.md#device-fingerprint-hmac-secret)
  for the full key-generation, Kubernetes injection, and 9-step rotation runbook.

---
