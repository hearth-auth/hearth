# Security Policy

## Supported Versions

Hearth 1.0.0 shipped on 2026-06-21. Support follows the 1.x window in
[VERSIONING.md](VERSIONING.md#support-window-for-the-1x-line):

| Version | Supported | Until |
|---|---|---|
| 1.x (latest release, currently 1.6.x) | ✅ Active support — bug and security fixes | 2027-12-21 |
| 1.x (security-only phase) | ✅ Security fixes only | 2028-06-21 |
| < 1.0 (pre-release) | ❌ | — |

Fixes land on `main` first and ship in the next 1.x release; there are no back-port branches for
older 1.x minors. **Note:** the newest installable server release, v1.6.10, predates the security
fixes merged in PR #358 — until the next release is cut, those fixes exist only on `main`.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use one of the following channels:

- **GitHub Security Advisories (preferred):** Use the "Report a vulnerability" button on the [Security tab](https://github.com/hearth-auth/hearth/security/advisories/new) of this repository. This opens a private channel between you and the maintainers. You need to be signed in to a GitHub account to use it; if you do not have one, use email.
- **Email:** therecluse26@protonmail.com — PGP key available on request.

### What to include

Please provide:

1. A description of the vulnerability and the affected component.
2. Steps to reproduce or a proof-of-concept (even a partial one).
3. The potential impact as you understand it.
4. Any mitigations or workarounds you are aware of.

### Response SLA

| Severity | Acknowledgement | Patch target |
|---|---|---|
| Critical (CVSS ≥ 9.0) | 24 hours | 7 days |
| High (CVSS 7.0–8.9) | 48 hours | 14 days |
| Medium (CVSS 4.0–6.9) | 72 hours | 30 days |
| Low (CVSS < 4.0) | 5 business days | Next release |

We will keep you informed throughout the process and credit you in the release notes and CVE advisory unless you prefer to remain anonymous.

## Scope

The following are **in scope** for security reports:

| Component | Description |
|---|---|
| Storage encryption | AES-256-GCM three-tier envelope encryption (`src/storage/encryption.rs`) |
| JWT signing & verification | Ed25519 token issuance and validation (`src/identity/tokens.rs`) |
| Credential hashing | Argon2id password hashing and legacy migration (`src/identity/credentials.rs`) |
| Session management | Session lifecycle, TTL, revocation (`src/identity/sessions.rs`, `src/identity/engine/`) |
| SAML 2.0 | SP/IdP flows, XML signature validation (`src/identity/federation/saml/`) |
| OIDC / OAuth 2.0 | Relying party, authorization server, PKCE (`src/identity/federation/oidc.rs`, `src/protocol/web/`) |
| RBAC engine | Role composition, cycle detection, org scoping (`src/rbac/`) |
| Input validation | Centralised validator (`src/identity/validation.rs`) |
| WebAuthn / FIDO2 | Registration and authentication ceremonies (`src/identity/webauthn.rs`) |
| SCIM 2.0 | Provider auth, filter parsing, CRUD (`src/protocol/scim/`) |
| Webhook signing | HMAC-SHA256 delivery (`src/webhook/dispatcher.rs`) |
| Admin API | Auth and rate limiting (`src/protocol/admin_auth.rs`) |
| TLS | rustls configuration and hot-reload (`src/protocol/tls.rs`) |
| Audit log integrity | Hash-chain tamper detection (`src/audit/`) |

**Out of scope:**

- Vulnerabilities in third-party dependencies — please report those upstream. We actively track them via `cargo deny` and will address them promptly if they affect Hearth.
- Theoretical attacks with no practical exploitation path.
- Issues requiring physical access to the server or root/kernel-level compromise.
- Social engineering or phishing attacks.

## Safe Harbour

We consider security research conducted in good faith under this policy to be:

- Authorised in accordance with the Computer Fraud and Abuse Act (CFAA) and equivalent laws.
- Exempt from restrictions in our terms of service that would otherwise prohibit such research.

We will not pursue civil or criminal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption.
- Report findings through the channels above before public disclosure.
- Give us reasonable time to respond before public disclosure (90 days from initial report).

## Audit Status

| Audit type | Status | Notes |
|------------|--------|-------|
| Internal assessments | 🔄 Findings open | Internal audits are not clean. The 2026-08-12 production-readiness audit reported critical findings, and the 2026-09-28 GA-readiness audit of `main` at `060d4541` reported high-severity blockers (consent bypass on refresh and device grants, second-factor bypasses, an unauthenticated connection-exhaustion DoS, a revocation race). Remediation is in progress; the verdict at the time of writing is **not GA-ready**. |
| Third-party penetration test | 🔄 In procurement | Scope document at `docs/security-audit/pentest-scope.md`; board budget approval pending (HEA-1244) |
| Independent threat model review | ⏳ Pending pentest | Blocked on HEA-1244 completion (HEA-1243) |

This page will be updated with the pentest report summary and firm name once the engagement concludes. The redacted full report will be stored at `docs/security-audit/pentest-YYYY-MM-DD-summary.md`.

## Known Exceptions

The server's advisory ignore lists (`deny.toml`, `.cargo/audit.toml`) carry no exception for a
crate that is compiled into the Hearth binary. The former RUSTSEC-2023-0071 (`rsa`) exception was
removed: `rsa` is not in the server's `Cargo.lock` (RSA key generation uses `rcgen` + `aws-lc-rs`;
signing uses `ring`).

Advisory exceptions for SDK and tooling lockfiles live in [`osv-scanner.toml`](osv-scanner.toml),
each with its rationale.

| CVE / Advisory | Affected crate / package | Justification |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa`, **Rust SDK only** (`sdks/rust/Cargo.lock`, via `jsonwebtoken`'s `rust_crypto` backend and a test-only dependency) | Marvin Attack timing side-channel in PKCS#1 v1.5 decryption. The Rust SDK performs no RSA decryption. No patched `rsa` release exists. |

## Encryption at Rest

Encryption at rest is **active** in Hearth 1.0. All data written to disk — WAL records and SST file sections — is encrypted using a three-tier key hierarchy:

1. **Host Key (32 B)** — loaded from the `HEARTH_MASTER_KEY` env var (64 hex chars, e.g. `openssl rand -hex 32`). In production that variable is the **only** key source: if it is unset, Hearth **refuses to start**, and it never reads a `hearth.host_key` file from the data directory even when one exists (`src/storage/key_registry.rs`). Only `--dev` mode auto-generates a key, persists it to `hearth.host_key`, and reads that file back on a later `--dev` start. Protects the KEKs in `hearth.keys`.
2. **KEK (32 B)** — stored encrypted in `hearth.keys`; wraps per-file DEKs. The key registry is realm-keyed, but only the system realm's KEK is provisioned, so **one KEK covers every realm**. Size your key-compromise blast radius accordingly: recovering that one KEK exposes every realm's data, not one tenant's.
3. **File DEK (32 B per SST/WAL segment)** — randomly generated per file; stored in the 76-byte encryption header at the start of each file.

Key rotation re-wraps only the DEK header in each file (O(file count), not O(data size)) — the ciphertext on disk is unchanged.

If you self-host Hearth and need to rotate the host key, back up `HEARTH_MASTER_KEY` and `hearth.keys` before any rotation operation. Loss of the host key makes all on-disk data permanently unrecoverable.

## Release Signing

Every Hearth release binary and SBOM is signed via **cosign keyless signing** using a GitHub Actions OIDC identity. No long-lived private key exists; each release obtains a short-lived certificate from [Sigstore Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) and logs the event to [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/).

**Cosign verification identity:**

| Field | Value |
|-------|-------|
| `--certificate-oidc-issuer` | `https://token.actions.githubusercontent.com` |
| `--certificate-identity-regexp` | `^https://github\.com/hearth-auth/hearth/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$` |

Every release also ships a **SLSA provenance document** (`multiple.intoto.jsonl`, one document covering every binary and the SBOM — the asset name on v1.6.10) and a **CycloneDX SBOM** (`hearth-sbom.cdx.json`).

See [docs/guides/verify-release.md](docs/guides/verify-release.md) for full verification instructions including `cosign verify-blob`, `slsa-verifier`, and SBOM inspection.


## Cryptographic Choices

For transparency, Hearth's core cryptographic primitive selections:

| Purpose | Algorithm | Library |
|---|---|---|
| At-rest encryption | AES-256-GCM (3-tier envelope, active in 1.0) | `ring` 0.17 |
| JWT signing | Ed25519 (EdDSA) | `ring` 0.17 |
| ID-token signing, opt-in per client (`id_token_signed_response_alg: RS256`) | RSA-3072, RSASSA-PKCS1-v1_5 SHA-256 (RS256); never accepted as an access token | `ring` 0.17 (sign/verify), `rcgen` 0.13 + `aws-lc-rs` (key generation) |
| Password hashing | Argon2id (OWASP params: 19 MiB, 2 iterations, p=1) | `argon2` 0.5 |
| TLS | TLS 1.2 / 1.3 | `rustls` 0.23 |
| Webhook signing | HMAC-SHA256 | `ring` 0.17 |
| SCIM token comparison | SHA-256 + constant-time eq | `ring` + `subtle` |

