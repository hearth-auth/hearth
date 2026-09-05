## ADDED Requirements

### Requirement: `make check` completes
`make check` SHALL run clippy, `cargo fmt --check` and the test suite to completion on every
commit. No gate may abort a later gate.

#### Scenario: Clippy finds a denied lint
- **WHEN** `cargo clippy --all-targets -- -D warnings` reports a violation
- **THEN** the violation is reported as a lint failure, not a hard compile error
- **AND** `cargo fmt --check` and `cargo nextest run --workspace` still execute

#### Scenario: A clean checkout at HEAD
- **WHEN** an operator runs `make check` on a clean checkout
- **THEN** every gate reports its own result
- **AND** the exit code reflects the worst result, not the first

### Requirement: A red commit publishes nothing
No release channel SHALL publish an artefact built from a commit whose test suite, lint, format
or supply-chain gates are failing. The container image, the Helm chart, every SDK release and
every registry package are gated on the same signal the binary channel uses.

#### Scenario: The suite fails on the release commit
- **WHEN** the release workflow runs against a commit with one or more failing tests
- **THEN** no container image, Helm chart, SDK release or registry package is published
- **AND** the workflow fails loudly rather than reporting success

#### Scenario: Release validation has not yet reported
- **WHEN** a publish job is ready to run and release validation has not written its verdict
- **THEN** the publish job waits for that verdict
- **AND** it does not publish ahead of it

### Requirement: Advisory gates can fail the build
Dependency-advisory gates SHALL be able to fail a run. `continue-on-error` MUST NOT be used
without a re-raise. `cargo deny check` and `cargo audit` are required contexts.

#### Scenario: A scan reports vulnerabilities
- **WHEN** `cargo audit` or `cargo deny check` reports one or more findings
- **THEN** the job status is failure
- **AND** the required check summary is failure

#### Scenario: A PR does not touch the lockfile
- **WHEN** a pull request changes no dependency file
- **THEN** the advisory gate still runs
- **AND** a pre-existing advisory failure still blocks the merge

### Requirement: Merges are blocked by a check that ran
Every merge to the default branch SHALL be blocked until a required check has reported success
on that exact commit. A bypass MUST NOT be always-on.

#### Scenario: A required context has not reported
- **WHEN** a merge is attempted before the required check reports
- **THEN** the merge is refused

### Requirement: The reported version is the running version
`hearth --version`, the container image labels, the Helm chart, and both published SBOMs SHALL
report the same version, derived from the server release tag.

#### Scenario: `.git` is absent at build time
- **WHEN** the binary is built in a context with no `.git` directory, such as the container build
- **THEN** the version is supplied explicitly by the build
- **AND** it does not silently fall back to a stale `Cargo.toml` value

#### Scenario: `git describe` resolves to an SDK tag
- **WHEN** the newest reachable tag is an SDK release tag
- **THEN** the server version is not derived from it

### Requirement: Release validation reports what happened
The release-validation summary SHALL state the true outcome of the suite it parsed.

#### Scenario: The suite completes with failures
- **WHEN** the suite runs to completion and four tests fail
- **THEN** the summary reports a completed suite with four named failures
- **AND** it does not report "suite did not complete"

### Requirement: Documented verification commands are executable and meaningful
Every command in the release-verification guide and the README install path SHALL execute as
written, and SHALL verify a property an attacker cannot forge.

#### Scenario: An operator follows the documented install path
- **WHEN** an operator runs the documented Docker or Helm install commands anonymously
- **THEN** each command succeeds
