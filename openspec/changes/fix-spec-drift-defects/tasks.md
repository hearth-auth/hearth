## 0. Before you start

- [ ] 0.1 Archive `adopt-openspec-specs` first (it lands the baseline these MODIFIED deltas apply to)
- [ ] 0.2 For every task: write the named regression scenario as a failing test first (red), then fix (green). Security defects are tracked separately, in `security-hardening`
- [ ] 0.3 SDK tasks: check each one against `sdk-standard-libraries` first; if that change replaces the code path, close the task there instead

## 1. `abuse-prevention`

- [ ] 1.1 An A-4 hard-capped or soft-capped send writes no `AbuseDetected` audit event and no security webhook (`src/protocol/web/handlers.rs:4231`). Test: Regression — abandoned send is audited
- [ ] 1.2 Security webhooks created in the admin UI are stored under `wh:id:` with `security.*` names that the dispatcher never reads (`src/protocol/web/admin/webhooks.rs:351`). Test: Regression — UI-created security subscription delivers
- [ ] 1.3 `realms.<name>.quotas` has no YAML field, so the documented block refuses to boot (`src/config/types.rs:3646`). Test: Regression — documented quota block loads
- [ ] 1.4 `quotas.max_audit_rows` is declared but never enforced by the pruner (`src/identity/types/realm.rs:688`). Test: Regression — audit row quota is enforced
- [ ] 1.5 The code comments label the SAML event cap `MAX_SAML_XML_EVENTS` as A-44 instead of A-35 (`src/abuse/mod.rs:66`). Test: Regression — SAML cap carries its own id
- [ ] 1.6 An A-50 hard-capped send writes no `AbuseDetected` audit event and no webhook (`src/abuse/runtime.rs:217`). Test: Regression — abandoned cross-realm send is audited

## 2. `agent-identity`

- [ ] 2.1 the Agent Card's `url` is always the empty string; an agent has no endpoint field to fill it from (`src/protocol/http/agents.rs:211`). Test: Regression — the card has no endpoint URL
- [ ] 2.2 the `AgentDelegation` audit metadata has no `delegation_chain` (`src/identity/engine/mod.rs:17887`). Test: Regression — the delegation event lacks the chain
- [ ] 2.3 an allowed `POST /v1/tools/invoke` records `AgentToolInvocation` with `metadata: None`, so no actor, tool or `token_jti` (`src/protocol/http/tool_invocation.rs:131`). Test: Regression — an allowed tool invocation has no context

## 3. `delegated-authorization`

- [ ] 3.1 the `AgentDelegation` event records `actor` and `on_behalf_of` but not the nested chain (same code as the agent-identity line above) (`src/identity/engine/mod.rs:17887`). Test: Regression — the event lacks the chain
- [ ] 3.2 the `AgentDelegation` audit write result is discarded (`let _ =`), so the token is issued even when the delegation is not recorded (`src/identity/engine/mod.rs:17898`). Test: Regression — a failed audit write still issues a token

## 4. `agent-approvals`

- [ ] 4.1 nothing writes `ApprovalRequestStatus::Expired`, so an expired request stays `Pending` in get and list and `?status=expired` finds nothing (`src/identity/engine/approval.rs:176`). Test: Regression — an expired request still reads Pending
- [ ] 4.2 rate-triggered suspension calls `suspend_agent(realm_id, agent_id, None)`, so `AgentSuspended` has no actor or signal context, and the result is ignored (`let _ =`) (`src/identity/engine/mod.rs:16399`). Test: Regression — rate suspension is audited without its signal

## 5. `rbac-admin-api`

- [ ] 5.1 the effective-permissions preview narrows with `narrow_by_scope` (an OIDC scope cancels narrowing, an unmapped scope empties the set) instead of the granted-scope rule issuance uses, so it does not show what a token would carry (`src/protocol/http/admin.rs:3094`). Test: Regression — the preview matches the issued token

## 6. `custom-permissions`

- [ ] 6.1 HTTPS-namespaced claim names are accepted without the character-class check (`src/rbac/registry.rs:524-535`). Test: Regression — an HTTPS claim name with a space
- [ ] 6.2 Adding or removing an additional organization role writes no audit event (`src/protocol/http/admin/orgs.rs:370-425`, `src/rbac/engine.rs:875-922`). Test: Regression — adding an additional role is not audited
- [ ] 6.3 `hearth rbac orphans list`/`purge` never detect orphans: they scan the system realm's `rba:user_perm:` keys only, ignore `--realm`, and purge deletes every grant found, with no audit event (`src/main.rs:5814-5880`). Test: Regression — purge does not find orphans
- [ ] 6.4 an undeclared scope raises `IdentityError::InvalidInput`, which answers `400 "invalid input"` instead of `invalid_scope` (`src/identity/engine/mod.rs:1349`, `src/protocol/http/auth.rs:719`). Test: Regression — an undeclared scope answers with the `invalid_scope` wire code

## 7. `dpop`

- [ ] 7.1 The token endpoint records a DPoP proof's `jti` before the refresh-family and token-exchange binding checks, so a proof that fails the binding still burns its `jti` (`src/protocol/http/oauth.rs:3813`). Test: Regression — a wrong-key refresh proof burns its jti

## 8. `saml-sp-profile`

- [ ] 8.1 The SAML endpoints emit no wire codes: the ACS answers a plain-text `400`, an unknown IdP gets `404 "IdP not configured"`, and `MetadataFetch`/`UnknownIdp` are never constructed (`src/protocol/web/saml.rs:343`). Test: Regression — the ACS answers without a SAML error code

## 9. `ui-routing`

- [ ] 9.1 Five route keywords (`config`, `identity-providers`, `abuse`, `webhooks`, `approvals`) are missing from the reserved realm names (`src/identity/validation.rs:566`). Test: Regression — route keywords missing from the reserved set
- [ ] 9.2 The sessions list template emits realm-less `/ui/admin/sessions?status=…` links in its dead `is_global` branch (`templates/ui/admin/sessions/list.html:36`). Test: Regression — realm-less sessions filter links

## 10. `performance-budgets`

- [ ] 10.1 the `rbac_check` `resolve_permissions` gate times a bench-local base64 + `serde_json` decode of a forged JWT, not the RBAC engine's `resolve_permissions` for a 5-role, 10-group, 30-permission user (`benches/rbac_check.rs:157`). Test: Regression — the gate times Hearth's resolve_permissions
- [ ] 10.2 a warm `lookup_user()` allocates: `get_user` decodes an owned `User` from the owned `Vec<u8>` that `StorageEngine::get` returns, and `get_user_by_email` normalizes into a `String` (`src/identity/engine/mod.rs:8522`). Test: Regression — warm user lookup allocates nothing
- [ ] 10.3 the `lookup_hot` and `lookup_cold` load-test journeys (`GET /dev/probe-user`, a user lookup) are graded against the token-issuance budget (6,000 μs) instead of the user-lookup budgets (1,200 μs hot, 6,000 μs cold) (`loadtest/src/budget.rs:112`). Test: Regression — tier-miss lookups carry the user-lookup budget

## 11. `sdk-support-contract`

- [ ] 11.1 Go `NewClient` builds an `http.Client` with no timeout, and offers no timeout option (`sdks/go/hearth/client.go:111`). Test: Regression — Go client without a timeout
- [ ] 11.2 Go and Python hard-code `/token`, `/device_authorization`, `/introspect`, `/userinfo`, `/realms/{realm}/token` and `/.well-known/jwks.json` instead of the discovered endpoints (`sdks/go/hearth/flows.go:36`, `sdks/python/src/hearth/client.py:650`). Test: Regression — Go and Python ignore the discovered token endpoint
- [ ] 11.3 Go falls back to `{baseURL}/.well-known/jwks.json` when discovery fails, instead of returning `DiscoveryError` (`sdks/go/hearth/verify.go:30`). Test: Regression — Go guesses the JWKS path
- [ ] 11.4 an unreachable JWKS endpoint surfaces as a raw `fetch` error in TypeScript and as `NetworkException` in PHP, not `JWKSFetchError` (`sdks/typescript/src/jwks-client.ts:213`, `sdks/php/src/JwksClient.php:111`). Test: Regression — unreachable JWKS in TypeScript and PHP
- [ ] 11.5 PHP `checkDecision` posts to the discovered OIDC `authorization_endpoint` instead of `POST /oauth/authorize`, and throws instead of failing closed (`sdks/php/src/HearthClient.php:604`). Test: Regression — PHP decision check misses the decision endpoint
- [ ] 11.6 Go sends JSON bodies to the token and device-authorization endpoints instead of `application/x-www-form-urlencoded` (`sdks/go/hearth/flows.go:200`). Test: Regression — Go sends JSON to the token endpoint; Regression — Go device flow sends JSON
- [ ] 11.7 Go sends `X-Realm-ID` to the realm token endpoint whenever the realm is a UUID (`sdks/go/hearth/flows.go:219`). Test: Regression — Go sends X-Realm-ID to the token endpoint
- [ ] 11.8 Python `start_device_flow` posts to `/realms/{realm}/device/authorize`, which the server does not serve (404) (`sdks/python/src/hearth/client.py:680`). Test: Regression — Python device authorization path
- [ ] 11.9 Go `RequirePermission` answers `403` to a missing token, sends `401` without `WWW-Authenticate`, and puts no claims in the request context (`sdks/go/hearth/middleware.go:103`). Test: Regression — Go middleware without a token; Regression — Go middleware hides the claims
- [ ] 11.10 Python ASGI and WSGI middleware answer `403` to a missing or invalid token instead of `401` with `WWW-Authenticate` (`sdks/python/src/hearth/middleware.py:222`). Test: Regression — Python middleware without a token
