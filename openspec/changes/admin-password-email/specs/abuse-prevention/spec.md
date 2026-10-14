## MODIFIED Requirements

### Requirement: A-14 Per-realm TTL hard caps
Configuration load SHALL refuse a realm whose `auth.token.password_reset_token_ttl` exceeds 1 hour, whose `auth.token.set_password_token_ttl` exceeds 7 days, or whose `auth.token.magic_link_ttl` exceeds 30 minutes, unless `auth.token.allow_unsafe_ttl: true` is also set. The keys SHALL apply per realm under `realms.<name>` and globally under `auth.token`.

#### Scenario: Unsafe reset TTL
- **WHEN** a realm sets `password_reset_token_ttl: 2h` without `allow_unsafe_ttl`
- **THEN** startup fails with a validation error naming the field

#### Scenario: Unsafe TTL accepted on opt-in
- **WHEN** the same realm also sets `allow_unsafe_ttl: true`
- **THEN** the configuration loads

#### Scenario: Unsafe set-password TTL
- **WHEN** a realm sets `set_password_token_ttl: 30d` without `allow_unsafe_ttl`
- **THEN** startup fails with a validation error naming the field
