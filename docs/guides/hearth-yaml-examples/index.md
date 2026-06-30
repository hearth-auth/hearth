# `hearth.yaml` Examples

This guide collects copy-paste-ready `hearth.yaml` snippets for common deployment patterns. Every
key is verified against `src/config/types.rs`. Use `${ENV_VAR_NAME}` syntax for secrets —
Hearth substitutes environment variables at startup and treats an unset variable as a fatal error.
All example URLs use `auth.example.com`.

> **Quick-start:** An empty file (`{}`) or no file at all is a valid configuration.
> Run `hearth serve --dev` in development — it enables in-memory storage and disables fsync so you
> never need a config file to get started.

---

## Quick Reference

| # | Title | Page |
|---|-------|------|
| 1 | Zero-config / dev quickstart | [Basics](./basics.md#example-1--zero-config--dev-quickstart) |
| 2 | Minimal production | [Basics](./basics.md#example-2--minimal-production) |
| 3 | Password login — basic | [Basics](./basics.md#example-3--traditional-password-login-basic) |
| 4 | Password login — strict policy | [Basics](./basics.md#example-4--traditional-password-login-strict-policy) |
| 5 | Rate limiting + lockout | [Basics](./basics.md#example-5--rate-limiting--lockout) |
| 6 | Invite-only registration | [Basics](./basics.md#example-6--closed--invite-only-registration) |
| 7 | Magic link only | [Passwordless](./passwordless.md#example-7--magic-link-only) |
| 8 | Passkey / WebAuthn only | [Passwordless](./passwordless.md#example-8--passkey--webauthn-only) |
| 9 | Combined passwordless | [Passwordless](./passwordless.md#example-9--combined-passwordless-magic-link--passkey) |
| 10 | MFA required — TOTP | [MFA](./mfa.md#example-10--mfa-required-globally-totp) |
| 11 | MFA — TOTP + WebAuthn | [MFA](./mfa.md#example-11--mfa-required-totp--webauthn) |
| 12 | Passkey + TOTP backup | [MFA](./mfa.md#example-12--passkey--totp-backup) |
| 42 | Risk-based step-up MFA (adaptive) | [MFA](./mfa.md#example-42--risk-based-step-up-mfa-adaptive) |
| 13 | Google Sign In | [Federation](./federation.md#example-13--google-sign-in) |
| 14 | Google + GitHub | [Federation](./federation.md#example-14--google--github-two-providers) |
| 15 | Microsoft Azure AD (tenant) | [Federation](./federation.md#example-15--microsoft-azure-ad-tenant-specific) |
| 16 | Apple Sign In | [Federation](./federation.md#example-16--apple-sign-in) |
| 17 | Generic OIDC (Okta / PingFederate) | [Federation](./federation.md#example-17--generic-oidc-connector-okta--pingfederate) |
| 18 | Auto account-linking | [Federation](./federation.md#example-18--auto-account-linking) |
| 19 | SMTP transport | [Email](./email.md#example-19--smtp) |
| 20 | SendGrid | [Email](./email.md#example-20--sendgrid) |
| 21 | Postmark | [Email](./email.md#example-21--postmark) |
| 22 | Mailgun EU region | [Email](./email.md#example-22--mailgun-eu-region) |
| 23 | HTTPS / TLS termination | [TLS](./tls.md#example-23--https--tls-termination) |
| 24 | Mutual TLS (mTLS) | [TLS](./tls.md#example-24--mutual-tls-mtls) |
| 25 | Two realms — consumer + internal | [Multi-Tenancy](./multi-tenancy.md#example-25--two-realms-consumer--internal) |
| 26 | Single realm with organizations (B2B) | [Multi-Tenancy](./multi-tenancy.md#example-26--single-realm-with-organizations-b2b) |
| 27 | Full B2B SaaS — multi-realm | [Multi-Tenancy](./multi-tenancy.md#example-27--full-b2b-saas-multi-realm-per-realm-scim--branding--auth-policy) |
| 28 | Custom permissions + roles | [RBAC & OAuth](./rbac-and-oauth.md#example-28--custom-permissions--roles) |
| 29 | OAuth scope bundles | [RBAC & OAuth](./rbac-and-oauth.md#example-29--oauth-scope-bundles) |
| 30 | Public OAuth client — SPA | [RBAC & OAuth](./rbac-and-oauth.md#example-30--public-oauth-client--spa) |
| 31 | Confidential OAuth client — M2M | [RBAC & OAuth](./rbac-and-oauth.md#example-31--confidential-oauth-client--m2m) |
| 32 | First-party SSO — no consent | [RBAC & OAuth](./rbac-and-oauth.md#example-32--first-party-sso--no-consent) |
| 33 | Decision-mode client with `POST /oauth/authorize` | [RBAC & OAuth](./rbac-and-oauth.md#example-33--decision-mode-client-with-post-oauthauthorize) |
| 34 | SCIM provisioning | [Enterprise](./enterprise.md#example-34--scim-provisioning) |
| 35 | SAML SP registration | [Enterprise](./enterprise.md#example-35--saml-sp-registration) |
| 36 | Custom claim mappings | [Enterprise](./enterprise.md#example-36--custom-claim-mappings) |
| 37 | Production observability | [Enterprise](./enterprise.md#example-37--production-observability) |
| 38 | Storage tuning | [Enterprise](./enterprise.md#example-38--storage-tuning) |
| 39 | Custom branding | [Branding & Complex](./branding-and-complex.md#example-39--custom-branding) |
| 40 | High-security / financial services (+ FAPI 2.0 client setup) | [Branding & Complex](./branding-and-complex.md#example-40--high-security--financial-services) |
| 41 | Full enterprise kitchen sink | [Branding & Complex](./branding-and-complex.md#example-41--full-enterprise-kitchen-sink) |

---

## Sections

| Page | Examples | When to use |
|------|----------|-------------|
| [Basics](./basics.md) | 1–6 | Dev quickstart, production baseline, password policy, rate limiting, invite-only |
| [Passwordless](./passwordless.md) | 7–9 | Magic link, passkey-only, combined passwordless |
| [MFA](./mfa.md) | 10–12, 42 | TOTP, WebAuthn, passkey + MFA, adaptive/risk-based step-up |
| [Social Login & Federation](./federation.md) | 13–18 | Google, GitHub, Azure AD, Apple, generic OIDC, account linking |
| [Email Transports](./email.md) | 19–22 | SMTP, SendGrid, Postmark, Mailgun (EU) |
| [TLS](./tls.md) | 23–24 | HTTPS termination, mutual TLS |
| [Multi-Tenancy](./multi-tenancy.md) | 25–27 | Multiple realms, B2B organizations, per-realm SCIM and branding |
| [RBAC & OAuth](./rbac-and-oauth.md) | 28–33 | Custom permissions, scope bundles, SPA, M2M, SSO, decision mode |
| [Enterprise Integrations](./enterprise.md) | 34–38 | SCIM provisioning, SAML, custom claims, observability, storage tuning |
| [Branding & Complex Scenarios](./branding-and-complex.md) | 39–41 | Custom branding, financial services hardening, kitchen sink |
