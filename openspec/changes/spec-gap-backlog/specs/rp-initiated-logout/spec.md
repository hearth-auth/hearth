## ADDED Requirements

### Requirement: Logout infers the session from the request
When a logout request carries no `id_token_hint` but the session can be inferred from the request, the endpoint SHALL end that session instead of refusing the request. Only a request with neither an `id_token_hint` nor an inferable session SHALL be refused with `400 invalid_request`.

#### Scenario: A browser logs out without a hint
- **WHEN** a browser with a live Hearth session calls `/realms/{realm}/end_session` without `id_token_hint`
- **THEN** that session is revoked

#### Scenario: No hint and no session
- **WHEN** a caller with no session calls `/end_session` without `id_token_hint`
- **THEN** the response is `400 invalid_request`
