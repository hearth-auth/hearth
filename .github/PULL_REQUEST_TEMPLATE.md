## Description

<!-- What does this PR do? Why is it needed? Link the relevant issue. -->

## SDK Conformance Checklist

If this PR touches any SDK (`sdks/typescript`, `sdks/go`, `sdks/python`, `sdks/php`),
verify each item against the [Hearth SDK Common Specification](../openspec/specs/sdk-support-contract/spec.md).
Leave items unchecked only if they genuinely do not apply — CI will also enforce most of these automatically.

- [ ] **Error types:** All 9 required error type names are present in the SDK source:
  `ConfigurationError`, `DiscoveryError`, `JWKSFetchError`, `TokenExpiredError`,
  `TokenNotYetValidError`, `TokenInvalidError`, `TokenIssuerError`, `TokenAudienceError`,
  `IntrospectionError`
- [ ] **Claims API:** All required public methods are present:
  `subject`, `issuer`, `audiences`, `expiry`, `issuedAt`, `jwtID`,
  `scope`, `scopes`, `hasScope`, `hasRole`, `hasPermission`
- [ ] **Secret hygiene:** No tokens or secrets can appear in error messages or log output
- [ ] **JWKS caching:** Cache follows all 5 rules (kid-keyed, Cache-Control respected,
  cache-miss re-fetch, 401 re-fetch, 24 h max age)
- [ ] **Tests:** New or updated tests cover JWKS key rotation and clock skew edge cases
- [ ] **Documentation:** README includes installation, quickstart, and troubleshooting sections
- [ ] **Changelog:** `CHANGELOG.md` is updated for any user-visible change

## Non-SDK PRs

For PRs that do not touch any SDK directory, mark all checklist items `N/A` by striking them through.

---

## Test plan

<!-- How did you verify this change? Link CI run or describe manual steps. -->

- [ ] CI passes (conformance check + unit tests)
- [ ] Integration tests run against a live Hearth instance (if applicable)
