# SMS / Phone MFA — Deployment Guide

**Who this is for:** self-hosted Hearth operators who need SMS one-time passwords (OTPs) as a
second MFA factor for users who cannot use TOTP apps or passkeys.

**When to use SMS MFA:** TOTP and Passkeys are more phishing-resistant than SMS OTPs. Use SMS
OTP only when your user base includes device segments (legacy devices, no smartphone) that cannot
support an authenticator app, or when an enterprise procurement checklist explicitly requires it.

---

## Prerequisites

- Hearth v1.0.0 or later (SMS is shipped; `sms:` is a standard top-level config key)
- A Twilio account **or** an AWS account with SNS SMS access
- A verified sender identity (Twilio phone number, or SNS origination identity / Sender ID)
- `HEARTH_SMS_OTP_HMAC_KEY` set in your process environment (see §1)

---

## 1. HEARTH_SMS_OTP_HMAC_KEY

Hearth signs every OTP challenge with HMAC-SHA256 so the 6-digit code can be verified without
storing it in the database. This secret **must** be injected as an environment variable — it
must never appear in `hearth.yaml`.

> **Minimum length:** The key value must be at least 32 characters long. Hearth validates
> this at startup and refuses to start if the string is shorter. The `openssl rand -hex 32`
> command below produces a 64-character hex string and satisfies this requirement.

### Generate the key

```bash
openssl rand -hex 32
```

Inject the output into your process environment or secret store before starting Hearth:

```bash
export HEARTH_SMS_OTP_HMAC_KEY="$(openssl rand -hex 32)"
```

For container deployments, pass the secret at runtime — never bake it into an image:

```bash
# Docker
docker run -e HEARTH_SMS_OTP_HMAC_KEY="<value from secret manager>" hearth:latest serve

# Kubernetes — reference a Secret, never a ConfigMap
env:
  - name: HEARTH_SMS_OTP_HMAC_KEY
    valueFrom:
      secretKeyRef:
        name: hearth-secrets
        key: sms-otp-hmac-key
```

**Do not** use `${HEARTH_SMS_OTP_HMAC_KEY}` in `hearth.yaml`. Hearth loads the SMS HMAC key
directly from the process environment, bypassing the `hearth.yaml` variable-expansion path, so
the key cannot appear in config files, audit logs, or process-inspection output.

**Rotation:** Rotating this key invalidates all in-flight OTP challenges immediately. Rotate
during a scheduled maintenance window with no active authentication sessions.

---

## 2. Transport Configuration

Add an `sms:` block to `hearth.yaml`. The `transport` field selects the provider; the
provider sub-block holds provider-specific credentials.

### Transport values

| Value | Description |
|-------|-------------|
| `log` | **Development only.** OTPs are written to the structured log and never delivered to a phone. Hearth emits a `WARN` at startup when this transport is active. |
| `twilio` | Twilio Programmable SMS REST API. |
| `aws_sns` | AWS Simple Notification Service `Publish` API. |

### Production guard

Using `transport: log` outside of `--dev` mode will drop all OTPs. Hearth guards against
accidental misconfiguration at startup: when `transport: log` is active and the server is
not running with `--dev`, startup emits a `WARN` and continues:

```
WARN hearth::sms: sms.transport = log is active outside dev mode — no real SMS messages will be sent
```

There are no `production_guard` or `fail_fast` config keys — the guard is always active and
cannot be silenced via configuration. To prevent this warning in production, set `transport`
to `twilio` or `awssns`.

---

## 3. Twilio Configuration

```yaml
sms:
  transport: twilio

  twilio:
    account_sid: "${TWILIO_ACCOUNT_SID}"   # e.g. ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    auth_token: "${TWILIO_AUTH_TOKEN}"      # always use env var — never hardcode
    from: "+15005550006"                    # E.164 number or Messaging Service SID
```

Set the credentials in your environment before starting Hearth:

```bash
export TWILIO_ACCOUNT_SID="AC…"
export TWILIO_AUTH_TOKEN="<your auth token>"
```

**Required fields:** `account_sid`, `auth_token`, and `from` are all required. Hearth rejects
startup with a config error if any is empty.

### Sender types

`from` accepts any of the following Twilio sender types:

| Type | Format | Best For | Notes |
|------|--------|----------|-------|
| Long code (E.164) | `+15550001111` | Low-volume dev / test | May be filtered as spam in some markets |
| Short code (5–6 digits) | `12345` | US/Canada high-volume production | Requires carrier registration (8–12 weeks) |
| Toll-free number | `+18005551234` | US/Canada medium-volume | 1–2 week registration, lower filter risk |
| Messaging Service SID | `MGxxxxxxx…` | Multi-number pools, copilot | Recommended for scaling |

---

## 4. AWS SNS Configuration

### Required IAM permissions

Attach the following policy to the IAM role or user Hearth runs as:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish",
        "sns:SetSMSAttributes",
        "sns:GetSMSAttributes"
      ],
      "Resource": "*"
    }
  ]
}
```

For least-privilege deployments, `sns:SetSMSAttributes` and `sns:GetSMSAttributes` can be
omitted if you pre-configure your SNS SMS attributes in the AWS Console and do not need Hearth
to set them at runtime.

### hearth.yaml block

```yaml
sms:
  transport: awssns

  aws_sns:
    region: "us-east-1"
    access_key_id: "${AWS_ACCESS_KEY_ID}"          # required — use env var substitution
    secret_access_key: "${AWS_SECRET_ACCESS_KEY}"  # required — use env var substitution
    sender_id: "Hearth"                            # optional — up to 11 alphanumeric chars
```

**Required fields:** `region`, `access_key_id`, and `secret_access_key` are all required.
Use `${VAR}` env-var substitution so credentials are not stored in the YAML file directly.
Set the variables in your process environment before starting Hearth:

```bash
export AWS_ACCESS_KEY_ID="AKIA…"
export AWS_SECRET_ACCESS_KEY="<your secret key>"
```

> **Note:** Hearth does not use the AWS credential chain (instance roles, `~/.aws/credentials`,
> etc.) for the SNS transport. Credentials must be supplied explicitly via the config file
> using `${VAR}` substitution or by setting `access_key_id`/`secret_access_key` directly.
> For ECS/EKS deployments, inject the key pair from a Secrets Manager secret or a Kubernetes
> Secret rather than relying on instance role credential resolution.

### Enabling Transactional SMS tier

AWS SNS defaults to Promotional SMS, which has higher latency, lower throughput limits, and
higher carrier-filter risk. OTP delivery **requires** Transactional SMS:

**AWS Console:**

1. Open **SNS → Text messaging (SMS) → Edit**.
2. Under **Default message type**, select **Transactional**.
3. Click **Save changes**.

**AWS CLI:**

```bash
aws sns set-sms-attributes \
  --attributes '{"DefaultSMSType":"Transactional"}' \
  --region us-east-1
```

Hearth always sets `MessageAttributes["AWS.SNS.SMS.SMSType"] = "Transactional"` on each
`Publish` call. The account-level default is a safety net, but Hearth does not rely on it.

### Account spending limit

AWS SNS has a default $1.00/month SMS spending cap. Raise it before going to production:

1. **AWS Console → SNS → Text messaging → Edit → Account spend limit**.
2. Set an appropriate monthly cap for your OTP volume.
3. For high-volume deployments (>50k SMS/month), open an AWS Support case to raise the limit
   beyond what the console allows.

### Per-market pre-registration requirements

SMS in several markets requires carrier registration before messages are delivered. Plan for
these lead times before enabling SMS MFA for users in those regions.

#### United States — Short Codes and 10DLC

| Sender type | Registration | Lead time |
|-------------|-------------|-----------|
| Short code (5–6 digits) | Carrier registration via Twilio or AWS Support | 8–12 weeks |
| Toll-free number | Toll-free verification | 1–2 weeks |
| 10DLC long code | A2P brand + campaign registration | 1–3 weeks |

For new deployments without an existing short code, a toll-free number is the fastest path to
compliant US A2P SMS. Register via:

- **Twilio:** Messaging → Regulatory Compliance → Toll-Free Verification
- **AWS SNS:** SNS → Origination identities → Request toll-free number

Until registration is complete, unregistered 10DLC messages to US numbers are filtered by major
carriers (AT&T, T-Mobile, Verizon) at high rates.

#### India — DLT Registration

The Telecom Regulatory Authority of India (TRAI) mandates Distributed Ledger Technology (DLT)
registration for all commercial SMS senders. Messages from unregistered senders are blocked at
the carrier level.

**Registration steps:**

1. Register your entity on one of the TRAI-approved DLT platforms (Vodafone Idea, Airtel, or
   BSNL). Business registration documents (GST/CIN) required.
2. Register your brand name.
3. Register each SMS template individually. The template body must exactly match what Hearth
   sends. Hearth's default OTP template:

   ```
   Your Hearth login code is {#var#}. Valid for {#var#} minutes. Do not share this code.
   ```

   If you customize the OTP message body, register your customized template before enabling SMS
   MFA for Indian numbers.

4. Obtain a DLT-registered 6-character alpha Sender ID (e.g. `HEARTH`).

**Lead times:** 3–5 business days for brand approval; 1–2 additional days per template.

**hearth.yaml for India (AWS SNS):**

```yaml
sms:
  transport: awssns
  aws_sns:
    region: "ap-south-1"                          # Mumbai — lowest latency to India
    access_key_id: "${AWS_ACCESS_KEY_ID}"
    secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
    sender_id: "HEARTH"                           # must match your DLT-registered Sender ID exactly
```

For Twilio India, the originating number must complete DLT registration through the Twilio
India SMS compliance process (Twilio Console → Messaging → Regulatory Compliance).

---

## 5. Complete `hearth.yaml` `sms:` Examples

### Twilio (production-ready)

```yaml
# ──────────────────────────────────────────────────────────────
# SMS / Phone MFA — Twilio transport
# Requires: HEARTH_SMS_OTP_HMAC_KEY environment variable (§1)
# ──────────────────────────────────────────────────────────────
sms:
  transport: twilio          # twilio | awssns | log (dev only)

  twilio:
    account_sid: "${TWILIO_ACCOUNT_SID}"
    auth_token: "${TWILIO_AUTH_TOKEN}"
    from: "+15005550006"     # E.164 number, short code, toll-free, or Messaging Service SID
```

### AWS SNS (production-ready)

```yaml
# ──────────────────────────────────────────────────────────────
# SMS / Phone MFA — AWS SNS transport
# Requires: HEARTH_SMS_OTP_HMAC_KEY environment variable (§1)
# ──────────────────────────────────────────────────────────────
sms:
  transport: awssns

  aws_sns:
    region: "us-east-1"
    access_key_id: "${AWS_ACCESS_KEY_ID}"
    secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
    sender_id: "Hearth"                  # optional — up to 11 alphanumeric chars
```

Enable `sms` in your realm's allowed MFA methods:

```yaml
realms:
  default:
    auth:
      mfa_required: true
      mfa_methods:
        - totp
        - sms              # enable SMS OTP as an allowed second factor
```

---

## 6. Operational Notes

### Carrier delivery SLAs

SMS delivery is best-effort; carriers do not guarantee delivery times. Observed p95 latencies
under normal conditions:

| Region | Twilio p95 | AWS SNS p95 |
|--------|-----------|-------------|
| United States | 2–4 s | 3–6 s |
| Europe (UK, DE, FR) | 3–6 s | 5–10 s |
| India | 5–15 s | 8–20 s |
| Southeast Asia | 8–20 s | 10–25 s |

Latency can spike to 30–90 s during carrier maintenance windows or network congestion. Inform
users to wait up to 2 minutes before requesting a resend.

### OTP expiry window

OTP expiry is set per-realm via the Admin API (`PATCH /admin/realms/{id}/config`, field
`sms_otp_expiry_seconds`). The engine default is 600 seconds (10 minutes). This is not a
`hearth.yaml` config field.

| Expiry | Guidance |
|--------|----------|
| < 180 s | High failure rate in APAC markets and during congestion — users receive expired codes |
| 300–600 s | **Recommended range.** Consistent with NIST SP 800-63B. |
| > 600 s | Exceeds NIST SP 800-63B OTP validity guidance; avoid in regulated environments. |

### Rate limiting

Hearth applies a built-in per-phone-number OTP send rate limit to prevent SMS bombing (an
attacker triggering unlimited OTP requests to incur billing charges or exhaust limits).
The rate limit values are engine-level defaults and are not currently configurable via
`hearth.yaml`. Carrier-level rate limits in your Twilio or AWS SNS account provide an
additional backstop.

### Monitoring

Add an alert on the `hearth_sms_delivery_errors_total` Prometheus counter. Sustained non-zero
values indicate a transport misconfiguration or carrier outage. The counter is labeled by
`{transport, error_type}`:

| `error_type` | Meaning |
|-------------|---------|
| `provider_error` | Twilio / SNS API returned a non-retryable error |
| `rate_limited` | Provider rate limit hit — reduce OTP send frequency or upgrade plan |
| `invalid_number` | Phone number failed E.164 validation or was rejected by carrier |
| `delivery_failed` | Provider accepted the message but carrier reported delivery failure |

### Production readiness checklist

Before enabling SMS MFA for real users:

- [ ] `HEARTH_SMS_OTP_HMAC_KEY` is set in the process environment and not in `hearth.yaml`
- [ ] `sms.transport` is `twilio` or `awssns`, not `log`
- [ ] Twilio `auth_token` or AWS credentials are injected via `${VAR}` substitution — not hardcoded
- [ ] AWS SNS: `access_key_id` and `secret_access_key` loaded via env vars
- [ ] AWS SNS account spending limit raised above the $1.00/month default
- [ ] AWS SNS `DefaultSMSType` set to `Transactional`
- [ ] US senders: toll-free, short code, or 10DLC registration completed
- [ ] India senders: DLT brand, template, and Sender ID registration completed
- [ ] `hearth_sms_delivery_errors_total` alert configured in your monitoring stack
- [ ] Per-realm OTP expiry reviewed via `PATCH /admin/realms/{id}/config` against your regional delivery SLA data
