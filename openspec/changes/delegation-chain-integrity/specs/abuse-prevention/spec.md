## MODIFIED Requirements

### Requirement: A-38 Delegation-chain depth cap
Token validation SHALL reject a token whose RFC 8693 `act` delegation chain is deeper than the configured ceiling `security.max_act_chain_depth` with an invalid-token error (fail-closed). The ceiling SHALL default to `3`. Config load SHALL refuse a value outside `1`–`32`. The upper bound of `32` is a token-size bound, not a security policy: it keeps a delegated token below common 8 KB request-header limits. Depth SHALL count the outer actor as 1 and each nested `act` as one more, and the traversal SHALL be iterative and stop once the ceiling is passed.

With the default ceiling:

| `act` claim | Depth | Result |
|-------------|-------|--------|
| `{ "sub": "x" }` | 1 | accepted |
| `{ "sub": "x", "act": { "sub": "y" } }` | 2 | accepted |
| Three-level chain | 3 | accepted |
| Four-level chain | 4 | rejected |

#### Scenario: An over-deep chain
- **WHEN** the ceiling is the default and a token carries a four-level `act` chain
- **THEN** validation fails with an invalid-token error

#### Scenario: The default delegation chain depth ceiling is 3
- **WHEN** `security.max_act_chain_depth` is not set and an inbound token carries a four-level `act` chain
- **THEN** validation fails with an invalid-token error

#### Scenario: An operator raises the ceiling
- **WHEN** `security.max_act_chain_depth` is `6` and a token carries a five-level `act` chain
- **THEN** the chain depth does not fail validation

#### Scenario: A ceiling out of range
- **WHEN** `security.max_act_chain_depth` is `0` or `33`
- **THEN** config load fails and names the key

#### Scenario: A very deep chain stops early
- **WHEN** a token carries an `act` chain far deeper than the ceiling
- **THEN** validation stops reading the chain once the ceiling is passed and fails with an invalid-token error
