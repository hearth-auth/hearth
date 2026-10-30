## 1. Tests first

- [x] 1.1 Black-box `tests/admin_users.rs`: an imported bcrypt or Argon2id hash verifies its password and no other; an entry without `password_hash` gets no password; a hash in another format, a malformed hash, an empty PBKDF2 digest and a work factor above the ceilings each fail their entry and create no user; the response does not contain a hash.
- [x] 1.2 Run them red.

## 2. Implementation

- [x] 2.1 `check_importable_hash` in `src/identity/credentials.rs`, with unit tests for each format.
- [x] 2.2 The `password_hash` field of an import entry, as a `FormSecret`.
- [x] 2.3 The OpenAPI schemas, the regenerated SDK admin clients, `admin-api.md` and the CHANGELOG.
