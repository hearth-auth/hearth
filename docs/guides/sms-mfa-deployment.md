# SMS / Phone MFA — Deployment Guide

> **Planned feature:** This guide documents the SMS/Phone MFA feature tracked in
> [HEA-829](/HEA/issues/HEA-829). None of the configuration keys described here are active in
> current Hearth builds. Do not add an `sms:` block to `hearth.yaml` before HEA-829 ships —
> Hearth will reject the config at startup with an `unknown field: sms` error. After the feature
> lands, verify exact key names and default values against the shipped `hearth.example.yaml`.

**Who this is for:** self-hosted Hearth operators who need SMS one-time passwords (OTPs) as a
second MFA factor for users who cannot use TOTP apps or passkeys.

**When to use SMS MFA:** TOTP and Passkeys are more phishing-resistant than SMS OTPs. Use SMS
OTP only when your user base includes device segments (legacy devices, no smartphone) that cannot
support an authenticator app, or when an enterprise procurement checklist explicitly requires it.

---

## Prerequisites

- Hearth version: requires [HEA-829](/HEA/issues/HEA-829) (not yet released)
- A Twilio account **or** an AWS account with SNS SMS access
- A verified sender identity (Twilio phone number, or SNS origination identity / Sender ID)
- `HEARTH_SMS_OTP_HMAC_KEY` set in your process environment (see §1)

---

## 1. HEARTH_SMS_OTP_HMAC_KEY

Hearth signs every OTP challenge with HMAC-SHA256 so the 6-digit code can be verified without
storing it in the database. This secret **must** be injected as an environment variable — it
must never appear in `hearth.yaml`.

### Generate the key

```bash
openssl rand -base64 32
```

Inject the output into your process environment or secret store before starting Hearth:

```bash
export HEARTH_SMS_OTP_HMAC_KEY="$(openssl rand -base64 32)"
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

Using `transport: log` in production silently drops all OTPs. Hearth guards against this with
two startup checks controlled by `production_guard` and `fail_fast`:

```yaml
sms:
  transport: log
  production_guard: true   # default: true — logs WARN when transport is 'log'
  fail_fast: false         # default: false — set true to abort startup on 'log'
```

With `production_guard: true` (the default), startup emits:

```
WARN hearth::sms: SMS transport is set to 'log' — OTPs will NOT be delivered to real phones.
     Set sms.transport to 'twilio' or 'aws_sns' before serving real users.
```

With `fail_fast: true`, Hearth exits with a non-zero status if `transport: log` is set. Enable
`fail_fast: true` in all production and staging deployments to prevent an accidental `log`
transport reaching real users.

---

## 3. Twilio Configuration

```yaml
sms:
  transport: twilio
  production_guard: true
  fail_fast: true

  twilio:
    account_sid: "${TWILIO_ACCOUNT_SID}"   # e.g. AC000000000000000000000000000000
    auth_token: "${TWILIO_AUTH_TOKEN}"      # always use env var — never hardcode
    from_number: "+15005550006"             # your verified Twilio sender (E.164 format)
    # from_name: "Hearth"                  # alpha sender ID — mutually exclusive with from_number
```

Set the credentials in your environment before starting Hearth:

```bash
export TWILIO_ACCOUNT_SID="AC…"
export TWILIO_AUTH_TOKEN="<your auth token>"
```

Hearth rejects startup if `auth_token` is set to a literal non-`${…}` string (a static-secret
check enforced on boot to prevent credential leakage into `hearth.yaml`).

### Sender types

| Type | Best For | Notes |
|------|----------|-------|
| Long code (E.164) | Low-volume dev / test | May be filtered as spam in some markets |
| Short code (5–6 digits) | US/Canada high-volume production | Requires carrier registration (8–12 weeks) |
| Toll-free number | US/Canada medium-volume | 1–2 week registration, lower filter risk |
| Alpha sender ID | EU / APAC | Sender name instead of number; not supported in US/Canada |

For alpha senders, set `from_name` instead of `from_number`. The two fields are mutually
exclusive.

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
  transport: aws_sns
  production_guard: true
  fail_fast: true

  aws_sns:
    region: "us-east-1"
    # AWS credentials are resolved from the standard credential chain:
    #   1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables
    #   2. EC2 / ECS / EKS instance role (recommended for cloud deployments)
    #   3. ~/.aws/credentials or AWS_PROFILE
    # Never set access_key_id or secret_access_key in hearth.yaml.
    sender_id: "Hearth"               # shown as sender in markets that support it (optional)
    message_type: "Transactional"     # always Transactional for OTP / auth codes
```

Do not put `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` in `hearth.yaml`. Use the AWS
credential chain — an EC2/ECS/EKS instance role is the recommended approach for cloud
deployments.

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
aws_sns:
  region: "ap-south-1"    # Mumbai — lowest latency to India
  sender_id: "HEARTH"     # must match your DLT-registered Sender ID exactly
  message_type: "Transactional"
```

For Twilio India, the originating number must complete DLT registration through the Twilio
India SMS compliance process (Twilio Console → Messaging → Regulatory Compliance).

---

## 5. Complete `hearth.yaml` `sms:` Example

Annotated production-ready block (Twilio):

```yaml
# ──────────────────────────────────────────────────────────────
# SMS / Phone MFA
# Requires: HEARTH_SMS_OTP_HMAC_KEY environment variable (§1)
# ──────────────────────────────────────────────────────────────
sms:
  transport: twilio          # twilio | aws_sns | log (dev only)
  production_guard: true     # WARN at startup if transport is 'log'
  fail_fast: true            # abort startup if transport is 'log' (recommended for prod)

  otp:
    digits: 6                # OTP length. Default: 6. Supported: 6–8.
    expiry: "5m"             # How long an OTP challenge is valid. Default: 5m. Max: 10m.
    max_attempts: 5          # Wrong-code attempts before the challenge is invalidated.
    rate_limit_window: "15m" # Rolling window for per-phone OTP send rate limiting.
    rate_limit_max: 3        # Max OTP sends per phone number per rate_limit_window.

  twilio:
    account_sid: "${TWILIO_ACCOUNT_SID}"
    auth_token: "${TWILIO_AUTH_TOKEN}"
    from_number: "+15005550006"   # E.164 long code, short code, or toll-free
    # from_name: "Hearth"         # alpha sender ID — mutually exclusive with from_number

  # aws_sns:                       # uncomment to use SNS instead
  #   region: "us-east-1"
  #   sender_id: "Hearth"
  #   message_type: "Transactional"
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

### OTP expiry window tuning

The default `otp.expiry: "5m"` is the recommended balance between security and usability:

| Expiry | Risk |
|--------|------|
| < 3 minutes | High failure rate in APAC markets and during congestion — users receive expired codes |
| 5 minutes | **Recommended default.** Consistent with NIST SP 800-63B. |
| > 10 minutes | Exceeds NIST SP 800-63B OTP validity guidance. Avoid in regulated environments. |

If your user base is primarily in APAC markets with documented high SMS latency, `otp.expiry: "8m"` is acceptable. Document the deviation from the 5-minute default in your security policy.

### Rate limiting

`otp.rate_limit_max` and `otp.rate_limit_window` protect against SMS bombing — an attacker
sending unlimited OTP requests to a victim's phone number to incur billing charges or exhaust
rate limits. The defaults (3 sends per 15 minutes) suit most deployments. Lower the window
to `"5m"` on cost-sensitive per-message billing plans.

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
- [ ] `sms.transport` is `twilio` or `aws_sns`, not `log`
- [ ] `sms.fail_fast: true` is set to catch accidental `log` transport in production
- [ ] Twilio `auth_token` or AWS credentials are injected via environment — not hardcoded
- [ ] AWS SNS account spending limit raised above the $1.00/month default
- [ ] AWS SNS `DefaultSMSType` set to `Transactional`
- [ ] US senders: toll-free, short code, or 10DLC registration completed
- [ ] India senders: DLT brand, template, and Sender ID registration completed
- [ ] `hearth_sms_delivery_errors_total` alert configured in your monitoring stack
- [ ] OTP expiry (`otp.expiry`) reviewed against your regional delivery SLA data
