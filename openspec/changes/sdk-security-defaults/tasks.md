## 0. Before you start

- [ ] 0.1 Read the draft advisory `GHSA-hxcr-696v-vqw3` (maintainers only)
- [ ] 0.2 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `CHANGELOG.md` entry

## 1. Token validation

- [ ] 1.1 Add the `audience` option (default `hearth`) to all four SDKs. Test: scenarios "Every SDK checks the audience by default", "A protected resource sets its audience"
- [ ] 1.2 TypeScript: refuse a future `iat`. Test: scenario "TypeScript rejects a future `iat`" (`sdks/typescript/tests/verify-token-jose.test.ts`). Also fix the installed `jose` version drift
- [ ] 1.3 Add both scenarios to `sdks/conformance/scenarios.yaml`

## 2. Claim checks

- [ ] 2.1 TypeScript facade verifies the signature. Test: scenario "The TypeScript facade verifies the signature"
- [ ] 2.2 Python permission checks verify the signature. Test: scenario "Python permission checks verify the signature"

## 3. Browser token storage

- [ ] 3.1 TypeScript `createHearthAuth`: default `sessionStorage`, `storage` option, key prefix, token getters on the returned object, one-time removal of the old `localStorage` keys. Test: scenario "The refresh token is not kept in `localStorage`" (first browser-auth tests)

## 4. Docs

- [ ] 4.1 Update the four SDK guides under `docs/guides/` for the audience option and the API changes
