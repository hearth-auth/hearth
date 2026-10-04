# credential-hashing Specification

## Purpose
The Argon2id parameters used to hash user passwords.
## Requirements
### Requirement: New passwords are hashed with Argon2id at OWASP parameters
Hearth SHALL hash every new password credential with Argon2id (RFC 9106). Unless a realm overrides them, the parameters SHALL be:

| Parameter | Value | Unit | OWASP 2023 minimum |
|-----------|-------|------|--------------------|
| `memory_cost` (`m`) | 19 456 | KiB (19 MiB) | 19 456 KiB |
| `time_cost` (`t`) | 2 | iterations | 2 |
| `parallelism` (`p`) | 1 | threads | 1 |
| Algorithm | Argon2id | — | Argon2id |
| Version | 0x13 (v=19) | — | — |

These values meet or exceed the OWASP Password Storage Cheat Sheet 2023 minimum for Argon2id.

#### Scenario: A password is stored and verified
- **WHEN** a user sets a password in a realm with no cost override
- **THEN** the stored hash is Argon2id v=19 with `m=19456`, `t=2`, `p=1`
- **AND** the correct password verifies and a wrong one does not

### Requirement: A realm can raise the password hashing cost
Operators MAY raise the Argon2id memory or time cost per realm with `password_memory_cost` and `password_time_cost` in the realm's configuration. An override SHALL apply to new credentials, and to existing credentials when they are re-hashed on the next successful login.

#### Scenario: A realm raises the memory cost
- **WHEN** a realm sets `password_memory_cost: 65536` and `password_time_cost: 3`
- **THEN** passwords set in that realm afterwards are hashed with `m=65536` and `t=3`

### Requirement: A stale hash is upgraded on the next successful login
When a stored credential's Argon2id parameters differ from the realm's current configuration, Hearth SHALL re-hash the password with the current parameters on the next successful login. The upgrade SHALL be atomic: the old hash is replaced in a single storage write before the login response is returned.

#### Scenario: An operator raises the memory cost
- **WHEN** a user whose hash uses `m=19456` logs in successfully after the realm raised `password_memory_cost`
- **THEN** the stored hash carries the new memory cost before the login response is sent

#### Scenario: A failed login
- **WHEN** a login with a stale-parameter hash fails
- **THEN** the stored hash is unchanged

### Requirement: Legacy hashes are upgraded to Argon2id on login
Hearth SHALL verify legacy hashes imported from Keycloak or Auth0 migrations (bcrypt, scrypt, PBKDF2-SHA256), and SHALL replace each one with an Argon2id hash on its first successful login.

#### Scenario: A migrated bcrypt credential
- **WHEN** a user whose stored hash is bcrypt logs in with the right password
- **THEN** the login succeeds
- **AND** the stored hash is now Argon2id

#### Scenario: A migrated scrypt credential with a wrong password
- **WHEN** a user whose stored hash is scrypt logs in with a wrong password
- **THEN** the login fails and the hash is unchanged

### Requirement: The default hashing parameters are pinned
A unit test SHALL pin the default Argon2id parameter values and SHALL fail CI when they are lowered. Any intentional reduction below the OWASP minimum MUST come with a security review and a `### Security` entry in `CHANGELOG.md`.

#### Scenario: A change lowers the default memory cost
- **WHEN** a change sets the default `memory_cost` below 19 456 KiB
- **THEN** the pinning test fails

