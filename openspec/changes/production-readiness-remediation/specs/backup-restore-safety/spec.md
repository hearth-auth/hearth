## ADDED Requirements

### Requirement: A restore completes or refuses
A restore SHALL NOT destroy the target realm before it can restore it. An operation it cannot
complete SHALL be refused before any destructive step.

#### Scenario: `mode=overwrite` restore
- **WHEN** an operator runs a restore with `mode=overwrite`
- **THEN** the target realm is either fully restored or left untouched
- **AND** the command never leaves the realm destroyed, truncated, or unexportable

#### Scenario: A restore fails part way
- **WHEN** a restore fails after it has begun writing
- **THEN** the exit code is non-zero
- **AND** the failure is reported on the operator's terminal

### Requirement: The backup CLI reports what it did
Every `hearth backup` subcommand SHALL install a `tracing` subscriber and report its outcome on
stdout or stderr.

#### Scenario: `create` cannot acquire the data-directory lock
- **WHEN** `hearth backup create` fails because the server still holds the data-directory lock
- **THEN** the command prints the reason
- **AND** it exits non-zero

#### Scenario: Any backup subcommand runs
- **WHEN** `create`, `restore`, `verify` or `inspect` runs
- **THEN** it emits a non-empty report of what it did

### Requirement: A backup round-trips every factor it claims to carry
A backup SHALL carry every credential factor its record type declares, or the record type SHALL
declare what it omits.

#### Scenario: A realm with TOTP, passkey and OTP factors is backed up and restored
- **WHEN** a realm holding TOTP secrets, passkeys and OTP factors is backed up and restored
- **THEN** every factor is present after the restore
- **OR** the backup refuses and names the factors it cannot carry

### Requirement: The backup signature check is wired
`security.backup.verify_key` SHALL be consulted by the restore handler and SHALL fail closed.

#### Scenario: A configured verify key and an unsigned archive
- **WHEN** `security.backup.verify_key` is set and an archive fails its signature check
- **THEN** the restore is refused

### Requirement: A restored audit event keeps its integrity hash
Restore SHALL verify an imported audit event's integrity hash rather than discarding and
re-signing it.

#### Scenario: An archive carries a tampered audit event
- **WHEN** an archive contains an audit event whose hash does not verify
- **THEN** the restore reports it rather than re-signing it

### Requirement: The audit chain detects erasure
`verify_integrity` SHALL report a truncated or fully erased audit log as invalid.

#### Scenario: The chain-head record is deleted with the rest
- **WHEN** every audit record including the chain head is deleted
- **THEN** `verify_integrity` reports the log as invalid

### Requirement: A backup export is consistent
The backup consistency barrier SHALL be effective on every storage handle the server installs.

#### Scenario: Export runs against a live server
- **WHEN** a backup export runs while writes are in flight
- **THEN** the barrier holds on the handle `serve` installed
- **AND** `write_batch` is atomic on the cluster storage adapter
