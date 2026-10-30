## Why

`POST /admin/users/import` has no field for a password. An operator who moves users from another system through the API cannot keep their passwords, and only the offline `hearth migrate` commands import password hashes (#701). The restore drill imports its users through this API too, so its published restore times include no credential rows.

## What Changes

- Each import entry accepts an optional `password_hash`: a PHC string in a format that sign-in verifies. Hearth stores it as it is, and the first successful sign-in replaces it with an Argon2id hash.
- The import refuses an entry whose hash sign-in cannot verify or would refuse to compute: another format, a malformed hash, a work factor above the ceilings, or a PBKDF2 digest shorter than 16 bytes. The entry gets an error in `results` and no user. The check runs no key derivation.
- The response never contains the hash.
- The OpenAPI document types the import request, so the SDK admin clients type it too.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `credential-hashing`: legacy hashes can also come from the admin user import, and the import checks each hash before it stores it.

## Impact

- `src/identity/credentials.rs`: `check_importable_hash`.
- `src/protocol/http/admin.rs`: the `password_hash` field of an import entry.
- `docs/api/openapi.supplement.yaml`, `docs/api/openapi.json` and the generated SDK admin clients.
- `docs/guides/admin-api.md`.
