# Verifying a Hearth Release

Every Hearth release (≥ v0.1.0) ships with:

| Artifact | Purpose |
|---|---|
| `hearth-<os>-<arch>` | Compiled binary |
| `hearth-<os>-<arch>.sig` | cosign detached signature (base64) |
| `hearth-<os>-<arch>.pem` | Signing certificate (Sigstore) |
| `hearth-sbom.cdx.json` | CycloneDX 1.4 SBOM |
| `hearth-sbom.cdx.json.sig` / `.pem` | SBOM signature |
| `hearth-multiple.intoto.jsonl` | SLSA L1 provenance attestation |

## Prerequisites

```sh
# cosign ≥ 2.0
brew install cosign          # macOS
go install github.com/sigstore/cosign/v2/cmd/cosign@latest  # Go

# slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## 1 — Verify a binary signature with cosign

```sh
VERSION=v0.1.0
BINARY=hearth-linux-amd64   # adjust for your platform

# Download from the GitHub release
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/${BINARY}"
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/${BINARY}.sig"
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/${BINARY}.pem"

cosign verify-blob \
  --certificate         "${BINARY}.pem" \
  --signature           "${BINARY}.sig" \
  --certificate-oidc-issuer   "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "https://github\\.com/therecluse26/hearth/\\.github/workflows/release\\.yml@refs/tags/v.*" \
  "${BINARY}"
# Expected output: Verified OK
```

The signing identity confirms the binary was produced by the `release.yml` workflow running against a `v*` tag, not an arbitrary branch or fork.

## 2 — Verify the SBOM signature

```sh
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/hearth-sbom.cdx.json"
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/hearth-sbom.cdx.json.sig"
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/hearth-sbom.cdx.json.pem"

cosign verify-blob \
  --certificate         hearth-sbom.cdx.json.pem \
  --signature           hearth-sbom.cdx.json.sig \
  --certificate-oidc-issuer   "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "https://github\\.com/therecluse26/hearth/\\.github/workflows/release\\.yml@refs/tags/v.*" \
  hearth-sbom.cdx.json
```

## 3 — Verify SLSA provenance

```sh
curl -LO "https://github.com/therecluse26/hearth/releases/download/${VERSION}/hearth-multiple.intoto.jsonl"

slsa-verifier verify-artifact "${BINARY}" \
  --provenance-path hearth-multiple.intoto.jsonl \
  --source-uri      github.com/therecluse26/hearth \
  --source-tag      "${VERSION}"
# Expected: PASSED: Verified SLSA provenance
```

## 4 — Inspect the Rekor transparency log entry

Every cosign signing operation is recorded in the public Rekor transparency log. You can look up the entry using the certificate's log index:

```sh
# Extract the log index from the certificate
openssl x509 -in "${BINARY}.pem" -noout -text | grep -A2 "Rekor"

# Or search by artifact hash
DIGEST=$(sha256sum "${BINARY}" | awk '{print $1}')
rekor-cli search --sha "sha256:${DIGEST}"
```

## 5 — Import the SBOM into your SCA toolchain

The CycloneDX 1.4 JSON SBOM is accepted by most Software Composition Analysis tools:

```sh
# Dependency-Track
curl -X POST https://dtrack.example.com/api/v1/bom \
  -H "X-API-Key: ${DTRACK_API_KEY}" \
  -F "project=${PROJECT_UUID}" \
  -F "bom=@hearth-sbom.cdx.json"

# Grype (vulnerability scanning)
grype sbom:hearth-sbom.cdx.json
```

## Signing identity reference

| Field | Value |
|---|---|
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate identity regexp | `https://github\.com/therecluse26/hearth/\.github/workflows/release\.yml@refs/tags/v.*` |
| Transparency log | Sigstore Rekor (public instance) |
| SLSA level | L1 (source + provenance attested; builder not yet hardened) |
