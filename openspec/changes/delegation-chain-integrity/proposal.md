## Why

`security-hardening` found three delegation rules that need more than a local fix: the act-chain depth ceiling, revocation of onward-exchanged tokens, and validation of every link of an AAT chain. Each one needs a design (a config key, a stored link between delegations, a stored AAT record), so they move here.

The owner also settled a conflict between two specs. `abuse-prevention` fixed the global ceiling at 3, and `agent-identity` allowed an agent depth up to 10. RFC 8693 sets no number, so the ceiling becomes configurable: `security.max_act_chain_depth`, default `3`, range `1`–`32`. The bound of `32` is a token-size limit, not a policy. An agent's `max_delegation_depth` must not exceed the ceiling.

The detail of each gap is kept in the draft repository security advisory `GHSA-hxcr-696v-vqw3` (maintainers only).

## What Changes

- New config key `security.max_act_chain_depth`, replacing the fixed constant. The chain-depth count is iterative and stops once the ceiling is passed.
- `max_delegation_depth` is validated against the ceiling. A lowered ceiling caps a stored depth.
- Revoking a delegation also revokes every token exchanged onward from it.
- AAT validation checks the chain's structure and that each link only narrows its parent.
- Each fix ships with a `### Security` entry in `CHANGELOG.md`, plus an `### Added` entry for the config key.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `abuse-prevention`: "A-38 Delegation-chain depth cap" becomes configurable.
- `agent-identity`: "The agent record" ties `max_delegation_depth` to the ceiling.
- `delegated-authorization`: scenarios added to "Users can view and revoke agent delegations" and "An AAT is validated along its whole chain".

## Impact

- **Code:** `src/abuse/mod.rs`, `src/config/`, `src/identity/tokens.rs`, `src/identity/engine/` (token exchange, delegation revocation, AAT), `src/identity/types/token.rs`, `docs/guides/configuration-reference.md`.
- **Hot path:** none. Revocation reuses the existing revoked-`jti` cache, and AAT validation is not on the hot path.
- **Order:** after `security-hardening`.
