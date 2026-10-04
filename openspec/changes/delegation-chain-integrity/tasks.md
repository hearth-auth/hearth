## 0. Before you start

- [ ] 0.1 Read the draft advisory `GHSA-hxcr-696v-vqw3` (maintainers only)
- [ ] 0.2 Write `design.md`: the delegation parent link and its index, the revoke walk and the store-then-recheck race, the AAT record shape and what happens to an AAT minted before the record existed
- [ ] 0.3 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`

## 1. Act-chain depth ceiling

- [ ] 1.1 Add `security.max_act_chain_depth` (default `3`, range `1`–`32`). Test: scenarios "The default delegation chain depth ceiling is 3", "An operator raises the ceiling", "A ceiling out of range" (`tests/abuse_dpop_act.rs`)
- [ ] 1.2 Make the chain-depth count iterative and bounded. Test: scenario "A very deep chain stops early"
- [ ] 1.3 Validate `max_delegation_depth` against the ceiling, and cap a stored depth. Test: scenarios "A delegation depth out of range", "A lowered ceiling caps a stored depth"
- [ ] 1.4 Document the key in `docs/guides/configuration-reference.md`, including why the bound is `32`

## 2. Delegation revocation

- [ ] 2.1 Enforce: Revoking a delegation revokes onward exchanges. Test: scenario "Revoking a delegation revokes onward exchanges" (`tests/consent_delegations.rs`)

## 3. AAT chain validation

- [ ] 3.1 Enforce: Validation checks every chain link. Test: scenario "Validation checks every chain link" (`src/identity/engine/tests/aat.rs`)
