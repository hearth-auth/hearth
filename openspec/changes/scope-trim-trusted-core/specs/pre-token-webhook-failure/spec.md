## ADDED Requirements

### Requirement: The pre-token webhook fails closed by default
When a realm configures a pre-token webhook and does not set `on_error`, a webhook failure SHALL stop token issuance.

#### Scenario: Webhook times out with the default setting
- **WHEN** a realm has a pre-token webhook with no `on_error`, and the webhook does not answer within its timeout
- **THEN** the token request fails, and no token is issued

#### Scenario: Explicit fail-open
- **WHEN** the realm sets `on_error: fail_open`, and the webhook fails
- **THEN** the token is issued without the extra claims, and a warning is logged

### Requirement: Reserved claims cannot be overridden
The server SHALL drop any webhook claim whose name is a reserved JWT or Hearth claim.

#### Scenario: Webhook returns `sub`
- **WHEN** the webhook response contains `extra_claims` with `sub`, `iss`, `aud`, `exp` or `roles`
- **THEN** the issued token carries the server's values for those claims, not the webhook's
