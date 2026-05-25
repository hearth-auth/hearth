# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `main` (pre-release) | ✅ |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues to: **security@hearth-auth.dev** (or open a [GitHub private security advisory](https://github.com/therecluse26/hearth/security/advisories/new)).

We aim to acknowledge reports within 48 hours and provide an initial assessment within 5 business days.

## Release Signing

All Hearth release binaries (≥ v0.1.0) are signed with [cosign](https://github.com/sigstore/cosign) keyless signing via the GitHub Actions OIDC identity. Signatures and a CycloneDX SBOM are published alongside every GitHub Release.

### Signing identity

| Field | Value |
|---|---|
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate identity regexp | `https://github\.com/therecluse26/hearth/\.github/workflows/release\.yml@refs/tags/v.*` |

### Quick verification

```sh
cosign verify-blob \
  --certificate         hearth-linux-amd64.pem \
  --signature           hearth-linux-amd64.sig \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "https://github\\.com/therecluse26/hearth/\\.github/workflows/release\\.yml@refs/tags/v.*" \
  hearth-linux-amd64
```

See [`docs/guides/verify-release.md`](docs/guides/verify-release.md) for the full verification guide including SLSA provenance and SBOM import instructions.

### Supply-chain artefacts per release

- **`*.sig` / `*.pem`** — cosign detached signatures (keyless, Sigstore Rekor-logged)
- **`hearth-sbom.cdx.json`** — CycloneDX 1.4 SBOM
- **`hearth-multiple.intoto.jsonl`** — SLSA L1 provenance attestation (slsa-github-generator)
