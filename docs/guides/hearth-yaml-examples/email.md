# Email Transports — Examples 19–22

`hearth.yaml` snippets for configuring outbound email delivery: SMTP, SendGrid, Postmark, and
Mailgun.
Return to the [example index](./index.md) for a full list of all examples.

All examples in this section assume `onboarding.base_url` is set (needed for verification links).
The `email.from` field is required for every production transport; it becomes the `From:` header.
Leave the transport unset (or set `transport: log`) in development — Hearth will write the email
content to the log instead of attempting delivery.

---

## Example 19 — SMTP

**Audience:** operators self-hosting email delivery via any SMTP relay (AWS SES SMTP, Postfix, etc.).

```yaml
email:
  transport: smtp
  from: "Hearth Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls      # none | starttls | tls — default is starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- `encryption: starttls` (STARTTLS on port 587) is the default. Use `tls` for implicit TLS on
  port 465. Use `none` only against a local relay on a trusted network (e.g. a local SMTP proxy on `:1025`).
- `username` and `password` must either both be set or both be absent — the config validator
  enforces the pair.
- Store credentials in environment variables; never commit them to `hearth.yaml`.

---

## Example 20 — SendGrid

**Audience:** operators using the SendGrid v3 transactional email API.

```yaml
email:
  transport: sendgrid
  from: "Hearth Auth <auth@example.com>"
  sendgrid:
    api_key: "${SENDGRID_API_KEY}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- Create a restricted API key in the SendGrid dashboard with **Mail Send** permission only.
- The sending domain (`example.com` in the `from` address) must be verified in SendGrid's
  **Sender Authentication** settings, otherwise deliveries are rejected.

---

## Example 21 — Postmark

**Audience:** operators using Postmark for transactional email.

```yaml
email:
  transport: postmark
  from: "Hearth Auth <auth@example.com>"
  postmark:
    server_token: "${POSTMARK_SERVER_TOKEN}"

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- The field is `server_token`, not `api_key` — use the **Server API token** from your Postmark
  server dashboard, not the account-level API key.
- The sender domain must be verified in Postmark's **Sender Signatures** settings.

---

## Example 22 — Mailgun EU region

**Audience:** operators using Mailgun from an EU-based deployment who must keep email traffic
within EU infrastructure for data-residency compliance.

```yaml
email:
  transport: mailgun
  from: "Hearth Auth <auth@example.com>"
  mailgun:
    api_key: "${MAILGUN_API_KEY}"
    domain:  "mg.example.com"       # your Mailgun sending domain
    region:  eu                     # us (default) | eu

oidc:
  issuer: "https://auth.example.com"

onboarding:
  base_url: "https://auth.example.com"
```

- `domain` is required — it is the Mailgun sending domain (e.g. `mg.example.com`), not your
  application domain.
- `region: eu` routes API calls to `api.eu.mailgun.net`. Omit (or set `region: us`) for US
  infrastructure.
- Add `mg.example.com` as a verified domain in the Mailgun dashboard and configure the
  required DNS records (MX, SPF, DKIM) on `mg.example.com`.

---
