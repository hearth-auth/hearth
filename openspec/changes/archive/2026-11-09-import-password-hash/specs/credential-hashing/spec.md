## MODIFIED Requirements

### Requirement: Legacy hashes are upgraded to Argon2id on login
Hearth SHALL verify legacy hashes imported from Keycloak or Auth0 migrations or through the admin user import (bcrypt, scrypt, PBKDF2-SHA256), and SHALL replace each one with an Argon2id hash on its first successful login.

#### Scenario: A migrated bcrypt credential
- **WHEN** a user whose stored hash is bcrypt logs in with the right password
- **THEN** the login succeeds
- **AND** the stored hash is now Argon2id

#### Scenario: A migrated scrypt credential with a wrong password
- **WHEN** a user whose stored hash is scrypt logs in with a wrong password
- **THEN** the login fails and the hash is unchanged

## ADDED Requirements

### Requirement: The admin user import stores a password hash
`POST /admin/users/import` SHALL accept an optional `password_hash` for each entry, and SHALL store a well-formed bcrypt (`$2a$`, `$2b$`, `$2y$`), `$argon2id$`, `$scrypt$` or `$pbkdf2-sha256$` PHC string as the user's credential. The response SHALL NOT contain a hash.

#### Scenario: An imported bcrypt hash
- **WHEN** an import entry carries the bcrypt hash of a password
- **THEN** the user is created
- **AND** the user signs in with that password and with no other

#### Scenario: No hash
- **WHEN** an import entry carries no `password_hash`
- **THEN** the user is created with no password

### Requirement: The admin user import refuses a hash that sign-in cannot verify
The import SHALL fail an entry whose hash is in another format, is malformed, has a work factor above the ceilings that sign-in applies, or has a PBKDF2 digest shorter than 16 bytes. The entry's error SHALL name `password_hash`, and no user SHALL be created for it. The check SHALL run no key derivation.

#### Scenario: A hash in another format
- **WHEN** an import entry carries an unsalted MD5 digest
- **THEN** the entry fails with an error that names `password_hash`
- **AND** no user is created, and the other entries are imported

#### Scenario: A work factor above the ceiling
- **WHEN** an import entry carries a bcrypt hash with cost 18
- **THEN** the entry fails with an error that names the ceiling
- **AND** no user is created
