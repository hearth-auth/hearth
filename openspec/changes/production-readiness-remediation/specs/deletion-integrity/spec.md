## ADDED Requirements

### Requirement: Deleted data does not return
A key deleted through the public API SHALL NOT become readable again through compaction, SST
reload, crash recovery, or re-import.

#### Scenario: Crash during partial compaction
- **WHEN** the process dies between the partial-compaction rename and the unlink, on the shipped
  default configuration
- **THEN** no key deleted before the crash is readable after recovery

#### Scenario: An SST cannot be opened
- **WHEN** `reload_sst_readers()` encounters an SST it cannot open
- **THEN** it fails loudly rather than silently dropping the file
- **AND** the next partial compaction does not discard tombstones it must keep

### Requirement: Realm deletion sweeps the realm's key space
`delete_realm` SHALL remove every key under the realm's prefix. It MUST NOT rely on a
hand-written allowlist of key families, and MUST NOT choose its cascade by realm size.

#### Scenario: A realm with credential history and audit records is deleted
- **WHEN** a realm holding `cred:history:`, `audit:*`, `rba:*` and RBAC rows is deleted
- **THEN** no key under that realm's prefix remains readable

#### Scenario: The same realm ID is reused
- **WHEN** a new realm is created with a previously deleted realm's ID, or a user is re-imported
  with a previously deleted `UserId`
- **THEN** no permission grant, role, group membership or credential from the deleted entity is
  reactivated

### Requirement: A cascade that fails is retryable
A fault during a delete cascade SHALL leave the entity deletable, not wedged.

#### Scenario: Process death mid-cascade
- **WHEN** the process dies after the `204` and before the cascade completes
- **THEN** the admin API can delete the realm again
- **AND** startup reconciliation completes rather than aborting

#### Scenario: `delete_user` faults mid-cascade
- **WHEN** `delete_user` faults after removing the primary record
- **THEN** the operation is retryable and does not permanently orphan the user's remaining rows

### Requirement: Archival is a freeze
An archived realm SHALL reject every mutating engine operation.

#### Scenario: A mutation targets an archived realm
- **WHEN** `delete_user`, `set_password`, `register_client` or any other mutating operation
  targets an archived realm
- **THEN** the operation is refused

### Requirement: Retiring a client retires its consent
Retiring an OAuth client SHALL remove the consent records bound to it.

#### Scenario: A client is deleted and its key reclaimed
- **WHEN** a client is deleted and a new application later claims the same deterministic
  `ClientId`
- **THEN** the new application does not inherit the previous client's consent records

### Requirement: Delete preconditions are enforced in the domain layer
Deletion preconditions SHALL be enforced where the deletion happens, not in each protocol
adapter.

#### Scenario: Deletion is requested over gRPC
- **WHEN** `DeleteRealm` is called over gRPC, or an application delete is called over REST or
  gRPC
- **THEN** the archival gate and the YAML-managed gate are enforced identically to every other
  adapter

### Requirement: `unsafe` invariants hold
Every `SAFETY:` comment SHALL state an invariant that every caller upholds.

#### Scenario: `compact_partial` runs against a memory-mapped SST
- **WHEN** `compact_partial` operates on an SST that another reader has mapped
- **THEN** the invariant named in the SST mmap `SAFETY:` comment is not violated
