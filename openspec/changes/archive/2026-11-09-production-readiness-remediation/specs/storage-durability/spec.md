## ADDED Requirements

### Requirement: An acknowledged write is durable
The WAL SHALL be `fsync`'d before any write is acknowledged. An acknowledged write SHALL survive
`SIGTERM`, `kill -9` and power loss.

#### Scenario: Concurrent writers during WAL rotation
- **WHEN** two or more writers are concurrent and the WAL rotates
- **THEN** every acknowledged record is still present after recovery

#### Scenario: Clean shutdown
- **WHEN** the process receives `SIGTERM` and exits cleanly
- **THEN** the memtable is flushed or its contents are recoverable from the WAL
- **AND** no acknowledged write is lost

### Requirement: The durability property is testable
The repository SHALL contain a test that distinguishes `fsync`-before-ack from no `fsync` at all,
and that fails against code which omits the `fsync`.

#### Scenario: The `fsync` call is removed
- **WHEN** the pre-acknowledgement `fsync` is removed from the WAL write path
- **THEN** at least one test in the repository fails

### Requirement: A corrupt WAL never destroys good records
Recovery from a corrupt WAL SHALL NOT physically destroy acknowledged records, and SHALL NOT
report success when records were discarded.

#### Scenario: Mid-segment CRC mismatch
- **WHEN** `open()` finds a CRC mismatch in the middle of a segment
- **THEN** it does not physically destroy the records that follow it before the operator has
  been told
- **AND** it does not return `Ok` as if the segment were intact

#### Scenario: Corrupt WAL magic
- **WHEN** the WAL magic bytes are corrupt and `open()` fails
- **THEN** the failed open does not rewrite the segment in place

### Requirement: A torn write leaves a recoverable data directory
A fault during an SST body write or a WAL rotation SHALL leave a data directory the next startup
can open, or SHALL emit a documented repair path.

#### Scenario: Torn SST body
- **WHEN** an SST body write is interrupted, leaving a short file at the live `NNNNNN.sst` name
- **THEN** the next startup opens the data directory

#### Scenario: Partial WAL header
- **WHEN** a write fault leaves a 1–81-byte WAL header
- **THEN** the engine either opens the directory or names the documented repair command

### Requirement: The write fence is observable
A permanent WAL write fence SHALL be logged, counted in metrics, and reflected in `/readyz`.

#### Scenario: The fence engages
- **WHEN** the WAL write fence engages
- **THEN** `/readyz` reports not-ready
- **AND** a log line and a metric record it

### Requirement: A CLI subcommand uses the production storage config
Every CLI subcommand that opens a production data directory SHALL open it with the production
storage configuration.

#### Scenario: `hearth backup restore` opens a data directory
- **WHEN** `hearth backup restore` or a migration importer opens a production data directory
- **THEN** the storage engine uses the production `SyncMode`, not `SyncMode::None`
- **AND** `dev_mode` is not enabled

### Requirement: In-flight requests drain on shutdown
Both the plaintext and the TLS-terminating server SHALL drain in-flight requests on `SIGTERM`,
and SHALL exit non-zero if a drain does not complete.

#### Scenario: TLS server receives `SIGTERM` with a request in flight
- **WHEN** the TLS server receives `SIGTERM` while serving a request
- **THEN** the request completes before the process exits
