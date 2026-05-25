# Supply-Chain & Vulnerability Re-Audit (HEA-769 v2)

**Lane:** SecurityResearcher — deps, CVEs, build provenance, SLSA, cosign, SBOM, binary hardening  
**Branch audited:** `feature/gap-updates-for-clustering` (main branch cross-checked via `git show`)  
**Date:** 2026-05-25  
**Auditor:** SecurityResearcher (bc9d9045)  
**Methodology:** All claims supported by direct file evidence (file:line) or command output. No prior report citations.

---

## Verdict

**not-production-ready**

The runtime dependency hygiene and scanning posture are strong (zero CVEs, modern crypto stack,
SHA-pinned CI actions, active Dependabot + three SAST/SCA scanners). However, the primary
supply-chain deliverable — a signed release with SLSA L1 provenance, cosign keyless signatures,
and a CycloneDX SBOM — **does not exist**. `.github/workflows/release.yml` is absent on both
`main` and the current feature branch. The v1 audit's core SLSA/cosign/SBOM claims are falsified.
Three secondary gaps (no `cargo deny` in CI, no binary hardening profile, deprecated `serde_yaml`
in config loading) add further caveats.

---

## Verified Claims

### 1. `cargo audit` clean — zero CVEs in 495 production dependencies

- Command run: `cargo audit` against current `Cargo.lock`
- Result: **0 vulnerabilities**. 1 allowed warning: RUSTSEC-2025-0141 (`bincode 1.3.3` via
  `madsim 0.2.34`). This crate is simulation-only and never compiled into the production binary.
- The warning is already documented in `deny.toml:2-6` with explicit justification.
- Evidence: `cargo audit` stdout directly observed; `Cargo.lock` SHA-256 recorded.

### 2. `deny.toml` advisory governance is correct

- File: `deny.toml` (repo root)
- Two ignores present, each with rationale:
  - `RUSTSEC-2025-0141` (`bincode` via `madsim`, simulation-only) — `deny.toml:2-6`
  - `RUSTSEC-2025-0134` (`rustls-pemfile 2.x` transitive via `tonic`) — `deny.toml:7-10`
- License allowlist: Apache-2.0, MIT, BSD-2/3, MPL-2.0, ISC, AGPL-3.0-only + minor others — `deny.toml:13-26`
- `bans.wildcards = "deny"` enforced — `deny.toml:30`

### 3. Security scanning workflows: CodeQL, Trivy, OSV Scanner — all SHA-pinned

All three scanners run on push to `main`, on every PR, and weekly (cron).

- `security.yml` — 238 lines, verified by direct `Read`:
  - `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2` — `security.yml:95,176,213`
  - `github/codeql-action/init@28deaeda66b76a05916b6923827895f2b14ab387 # v3.28.16` — `security.yml:110`
  - `aquasecurity/trivy-action@6e7b7d1fd3e4fef0c5fa8cce1229c54b2c9bd0d8 # v0.29.0` — `security.yml:181`
  - `google/osv-scanner-action/osv-scanner-action@9a498708959aeaef5ef730655706c5a1df1edbc2 # v2.3.8` — `security.yml:218`
  - `github/codeql-action/upload-sarif@68bde559dea0fdcac2102bfdf6230c5f70eb485e # v4.35.4` — `security.yml:195,234`
- Trivy scans `CRITICAL,HIGH` severity only, with `skip-dirs` for `tests/`, `examples/`, `fuzz/`, `node_modules/`

### 4. OSSF Scorecard workflow present and SHA-pinned

- `scorecard.yml` — triggers on push to `main` + weekly cron
- `ossf/scorecard-action@4eaacf0543bb3f2c246792bd56e8cdeffafb205a # v2.4.3` — `scorecard.yml`
- `publish_results: true` — scores published to OpenSSF REST API for public visibility

### 5. Dependabot configured for all three package ecosystems

- `dependabot.yml` — weekly Monday 09:00 UTC
- Ecosystems covered: `cargo` (root `/`), `npm` (`/sdks/node`), `github-actions` (`/`)
- Labels: `dependencies`, `security`; commit prefix `chore(deps)`

### 6. Modern cryptographic stack, no OpenSSL dependency

Direct dependencies from `Cargo.toml`:

| Crate | Version | Purpose |
|-------|---------|---------|
| `ring` | 0.17 | Ed25519 signing, AEAD, HKDF |
| `rustls` | 0.23 | TLS 1.3 |
| `argon2` | 0.5 | Password hashing (Argon2id) |
| `subtle` | 2 | Constant-time comparisons |
| `zeroize` | 1 (+ derive) | Zeroize-on-drop for secrets |
| `sha2` | 0.10 | SHA-256/SHA-512 |
| `hmac` | 0.12 | HMAC-SHA2 |
| `rcgen` | 0.13 (`aws_lc_rs` backend) | TLS cert generation |
| `scrypt` | 0.11 | Legacy-hash fallback |
| `pbkdf2` | 0.12 | Keycloak-migration PBKDF2-SHA256 |

`rcgen` uses `aws_lc_rs` explicitly to avoid the `rsa` crate (RUSTSEC-2023-0071 / Marvin Attack) — `Cargo.toml:51-54`.

No direct `openssl` or `openssl-sys` dependency. `openssl-probe` appears as a transitive
dependency via `reqwest`/`rustls-native-certs` for system CA bundle detection only.

### 7. No unsafe blocks in production code

`grep -rn 'unsafe {|unsafe impl|unsafe fn' src/ --include='*.rs'` returned zero results.

---

## Falsified or Unverified v1 Claims

### F1. "SLSA L1 release workflow exists and signs artifacts" — **FALSIFIED**

> v1 claimed: `.github/workflows/release.yml` produces signed binaries, CycloneDX SBOM,
> cosign keyless signatures, and SLSA L1 provenance.

**Current code shows:** `release.yml` does not exist on either `main` or
`feature/gap-updates-for-clustering`.

- `git show main:.github/workflows/release.yml` → no output
- `ls .github/workflows/` → `bench-regression.yml ci.yml dependabot-automerge.yml fuzz.yml scorecard.yml security.yml ui-nightly.yml`

No signed artifacts are produced. No provenance document is generated. No SBOM is uploaded.
The v1 report appears to have described a designed/planned workflow, not a committed one.

**Note on research methodology:** The context-mode search index contained stale cached content
from a previous session that included detailed YAML for a full cosign/SLSA release pipeline.
This stale data was identified as invalid by cross-checking with `git show main:<path>` and
direct `ls` output. The stale index data is what v1 likely relied on.

### F2. "Cosign keyless verification works on a tag" — **NOT VERIFIABLE**

> v1 claimed: keyless OIDC identity `https://github.com/therecluse26/hearth/.github/workflows/release.yml@refs/tags/v*`

**Current code shows:** No release.yml → no signing step → no cosign artifacts to verify.
Verification cannot be exercised against a real tag.

### F3. "SBOM coverage via CycloneDX" — **NOT VERIFIABLE**

`cargo cyclonedx` is not invoked anywhere in the current CI. `cargo-cyclonedx` is not
referenced in any `.github/workflows/` file on main or the feature branch.

### F4. "Binary hardening flags present" — **FALSIFIED**

> v1 appears to have assumed standard Rust release defaults are sufficient.

**Current code shows:** No `[profile.release]` section in `Cargo.toml` or any workspace
`.cargo/config.toml`. This means the release binary ships with Rust defaults:
- `overflow-checks = false` (no integer overflow trapping)
- `panic = "unwind"` (unwind tables in binary, larger attack surface vs. `panic = "abort"`)
- No `lto = true` (link-time optimization disabled; can retain dead code)
- No `codegen-units = 1` (parallel compilation units reduce optimization quality)
- No `strip = "symbols"` (debug symbols in release binary)

Evidence: `grep -rn 'profile.release|overflow-checks|panic.*abort|lto.*true|codegen-units' **/*.toml` → no output.

---

## New Gaps Discovered

### G1. `release.yml` does not exist — entire release supply-chain posture is absent

**Severity:** High (supply-chain lane)  
**Spec ref:** SLSA Level 1 requires "build process is scripted"; Level 2 requires build service with provenance.  
**Attack scenario:** An attacker who compromises a developer machine or GitHub account can push
a malicious binary as a "release" with no provenance trail for users to verify. There is no
artifact integrity signal for operators.  
**Countermeasure:** Create `.github/workflows/release.yml` with `cargo build --release --locked`,
cosign keyless signing (`sigstore/cosign-installer`), `cargo cyclonedx --format json` for SBOM,
and `slsa-framework/slsa-github-generator` for SLSA L1 provenance.

### G2. `cargo deny check` not enforced in CI

**Severity:** Medium  
**Evidence:** `grep -rn 'cargo deny|deny check' .github/workflows/ci.yml` → no output;
`deny.toml` exists at repo root but is never invoked.  
**Impact:** New PRs can introduce banned licenses, vulnerable advisories not in the ignore list,
or duplicate crate versions without any CI gate. The `deny.toml` policy is aspirational, not enforced.  
**Countermeasure:** Add a `cargo deny check` step to `ci.yml` in the `lint` or `test` job.
Cost: ~30s per PR run.

### G3. No `[profile.release]` hardening in `Cargo.toml`

**Severity:** Low (defense-in-depth)  
**Evidence:** `Cargo.toml` has no `[profile.release]` section; `Cargo.toml:1-219` verified.  
**Impact:** Release binaries use Rust defaults: integer overflow wraps silently in release mode,
unwind tables are retained (larger binary, slightly broader stack-walking surface), LTO disabled.  
**Countermeasure:**
```toml
[profile.release]
overflow-checks = true
panic = "abort"
lto = "thin"
codegen-units = 1
strip = "symbols"
```
Note: `panic = "abort"` requires verifying that no code depends on unwind semantics (e.g.,
`std::panic::catch_unwind` in external crates like `tokio`). A conservative start is just
`overflow-checks = true`.

### G4. `serde_yaml = "0.9"` (deprecated crate) in production config loading

**Severity:** Low (maintenance risk, no current CVE)  
**Evidence:**
- `Cargo.toml:65` — `serde_yaml = "0.9"` (crates.io lists `v0.9.34+deprecated`)
- `src/config/mod.rs:133` — `serde_yaml::from_str(&substituted)` (primary config loading)
- `src/config/mod.rs:244` — second config loading path
- `src/protocol/web/admin/realms.rs:1699,1728,1730` — realm config YAML parsing/serialization
- `src/config/types.rs:2155` — test fixture parse
- The crate maintainer published `serde_yml` (no underscore) as the active successor.
**Impact:** No known vulnerabilities today, but a deprecated crate receives no security patches.
YAML parsing is in the config loading critical path (`src/config/mod.rs`) — any future YAML
parsing vulnerability would affect startup and realm management.  
**Countermeasure:** Migrate to `serde_yml` or `figment` with YAML support.
This is a drop-in rename for most usages.

---

## Operational Reachability Matrix

| Feature | Implemented | Route/Entry Point | Reachable? | Notes |
|---------|-------------|-------------------|------------|-------|
| `cargo audit` advisory check | ✅ | Manual CLI / `deny.toml` | No CI gate | `deny check` not in ci.yml |
| CodeQL SAST scanning | ✅ | `security.yml` on push+PR | ✅ Full path | SHA-pinned, all 4 languages |
| Trivy SCA scanning | ✅ | `security.yml` on push+PR | ✅ Full path | SHA-pinned, CRITICAL+HIGH |
| OSV dependency scanning | ✅ | `security.yml` on push+PR | ✅ Full path | SHA-pinned, `osv-scanner.toml` config |
| OSSF Scorecard | ✅ | `scorecard.yml` on main push | ✅ Partial | Weekly + main-only, no PR gate |
| Release binary signing (cosign) | ❌ | `.github/workflows/release.yml` | ❌ File absent | v1 claim falsified |
| SLSA L1 provenance | ❌ | `.github/workflows/release.yml` | ❌ File absent | v1 claim falsified |
| CycloneDX SBOM | ❌ | `.github/workflows/release.yml` | ❌ File absent | v1 claim falsified |

---

## Residual Risks After Fixes

Even with all gaps resolved:
1. `cargo deny` still won't catch vulnerabilities discovered after a release tag. Operators must
   subscribe to RustSec advisories for the deployed binary's dependency set.
2. OSSF Scorecard branch-protection check requires a public repo or a Scorecard PAT — `scorecard.yml`
   omits `repo_token` (commented out), so branch-protection results are not published.
3. Keyless cosign signatures expire and rely on Sigstore's Rekor transparency log remaining
   operational. Operators verifying historical releases against a decommissioned Rekor instance
   will fail verification.

---

## CVE Status

No new CVEs identified in this sweep. No CVE filing recommended.  
RUSTSEC-2023-0071 (Marvin Attack, `rsa` crate) — already mitigated by `rcgen` migration to
`aws_lc_rs` backend (`Cargo.toml:54`).

---

## Recommended Follow-Up

| Gap | Owner | Issue |
|-----|-------|-------|
| Create `release.yml` (SLSA+cosign+SBOM) | Engineer | New child of HEA-769 |
| Add `cargo deny check` to `ci.yml` | Engineer | New child of HEA-769 |
| Add `[profile.release]` hardening | Engineer | New child of HEA-769 |
| Migrate `serde_yaml` → `serde_yml` | Engineer | New child of HEA-769 |
