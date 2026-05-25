# Verifying a Hearth Release

Every Hearth release ships four artefacts per platform plus a CycloneDX SBOM:

| File | Description |
|------|-------------|
| `hearth-<os>-<arch>` | Release binary |
| `hearth-<os>-<arch>.sig` | cosign detached signature |
| `hearth-<os>-<arch>.pem` | Sigstore Fulcio short-lived certificate |
| `hearth-sbom.cdx.json` | CycloneDX SBOM (JSON) |
| `hearth-sbom.cdx.json.sig` | cosign signature for the SBOM |
| `hearth-sbom.cdx.json.pem` | Certificate for the SBOM signature |
| `hearth.intoto.jsonl` | SLSA L1 provenance document |

All signing is **keyless** — there is no long-lived private key. Each binary receives a short-lived X.509 certificate issued by [Sigstore Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) bound to the GitHub Actions workflow that produced it. The certificate is logged to [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) (public, append-only transparency log).

## Prerequisites

Install `cosign` (v2+):

```bash
# Linux / macOS via Homebrew
brew install cosign

# Or download from https://github.com/sigstore/cosign/releases
# and verify the cosign binary itself using its own certificate.
```

Install `slsa-verifier` (for SLSA provenance):

```bash
brew install slsa-verifier
# Or: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## Verify a binary with cosign

Download the binary, its `.sig`, and its `.pem` from the [GitHub Releases page](https://github.com/therecluse26/hearth/releases), then run:

```bash
VERSION=v0.1.0   # replace with the release tag
ARTIFACT=hearth-linux-amd64   # replace with your target

cosign verify-blob \
  --certificate         "${ARTIFACT}.pem" \
  --signature           "${ARTIFACT}.sig" \
  --certificate-identity-regexp \
    'https://github\.com/therecluse26/hearth/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer \
    'https://token.actions.githubusercontent.com' \
  "${ARTIFACT}"
```

Expected output:

```
Verified OK
```

If verification fails, do not run the binary.

## Verify the SBOM

```bash
cosign verify-blob \
  --certificate         hearth-sbom.cdx.json.pem \
  --signature           hearth-sbom.cdx.json.sig \
  --certificate-identity-regexp \
    'https://github\.com/therecluse26/hearth/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer \
    'https://token.actions.githubusercontent.com' \
  hearth-sbom.cdx.json
```

## Verify SLSA L1 provenance

Download `hearth.intoto.jsonl` from the release assets, then:

```bash
slsa-verifier verify-artifact \
  --provenance-path hearth.intoto.jsonl \
  --source-uri     github.com/therecluse26/hearth \
  --source-tag     "$VERSION" \
  "${ARTIFACT}"
```

SLSA L1 provenance asserts that the binary was built by the declared workflow and that the build inputs (git ref, SHA) are recorded. It does not guarantee builder isolation (that requires SLSA L2/L3).

## Inspect the certificate

You can decode the PEM certificate to see the embedded workflow identity:

```bash
openssl x509 -in "${ARTIFACT}.pem" -noout -text \
  | grep -A2 "Subject Alternative Name"
```

You should see a URI extension containing the full workflow path, for example:

```
URI:https://github.com/therecluse26/hearth/.github/workflows/release.yml@refs/tags/v0.1.0
```

## Inspect the transparency log entry

cosign logs every signing event to Rekor. To retrieve the log entry:

```bash
cosign triangulate --type=blob "${ARTIFACT}"
# Returns a Rekor entry URL — open it in a browser for the full audit record.
```

## Inspect the SBOM

The SBOM is a CycloneDX 1.x JSON document listing every Rust dependency with its name, version, and licence. To view a dependency summary:

```bash
# With jq installed:
jq '.components[] | {name: .name, version: .version, licenses: .licenses}' \
  hearth-sbom.cdx.json
```

Integrate with your own SCA tooling (Dependency-Track, Grype, Trivy) by importing `hearth-sbom.cdx.json`.

## What these checks prove

| Check | What it proves |
|-------|---------------|
| `cosign verify-blob` | The binary was signed by the `release.yml` workflow in this exact repository at a `v*` tag. The private key never left Sigstore's ephemeral HSM. |
| `slsa-verifier` | The git commit SHA, ref, and workflow that produced the binary are recorded and signed. |
| Rekor transparency log | The signing event is publicly auditable and cannot be silently removed. |

## What these checks do NOT prove

- That the binary is free of bugs or vulnerabilities — use your SCA tooling on the SBOM for that.
- Builder isolation — Hearth currently targets SLSA L1. L2 and L3 require a separate hardened builder and are planned for a future release.
