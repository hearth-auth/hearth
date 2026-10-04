## 1. Triage (one task per capability: cut each requirement, or promote it into its own change with a design and tasks)

- [ ] 1.1 `abuse-prevention` (11): "A-1 One abuse policy consulted by every public handler"; "A-51 Signed audit-head attestations shipped off-host"; "P-6 WAF egress through the security webhook channel"; "A-8 Block and unblock an IP from the abuse dashboard"; "A-14 Lifting a TTL cap is logged"; "A-19 Self-service email change is reachable and notifies the old address"; "A-27 Per-deployment PII logging override"; "A-40 Cookie name prefixes and partitioned session cookies"; "P-7 Session lookups go through a pluggable store"; "P-8 Secrets are read through a pluggable backend"; "Abuse data retention and IP truncation"
- [ ] 1.2 `agent-approvals` (6): "Intent claims bind a token to an operation"; "Resource servers enforce `tool_binding`"; "Agents redeem capability tokens"; "Hearth emits and consumes risk signals"; "Risk signals revoke the tokens they affect"; "Risk-signal evaluation stays off the hot path"
- [ ] 1.3 `agent-identity` (8): "Agents authenticate with their own credentials"; "Capability declarations use the Hearth URI form"; "Workload identity is enabled per realm"; "SPIFFE SVIDs identify agents"; "The TLS layer maps an SVID to an agent"; "Agents in an act chain must be active"; "The audit API filters by agent, chain and tool"; "Rate monitoring covers all agent activity"
- [ ] 1.4 `custom-permissions` (7): "Config load rejects raw permission scopes on third-party clients"; "Tier 2 claim overrides are format-checked at load"; "Role assignment enforces the role's scope kind"; "Additional organization roles respect scope kind, uniqueness and a cap"; "`hearth config diff` previews a configuration change"; "Connected applications are grouped by organization and resource"; "The realm claims page shows the merged profile with an example token"
- [ ] 1.5 `delegated-authorization` (9): "Agents request delegation with `requested_actor`"; "Delegated tokens name the acting agent"; "An agent's delegation depth bounds the chain"; "Agent delegation needs the user's prior consent"; "Users manage agent delegations through the API and the admin UI"; "Agents are discoverable by tag and directory"; "Agent-to-agent tokens are bound to the target agent"; "Cross-realm trust policies expire and are visible to both realms"; "Cross-realm agent tokens name both realms"
- [ ] 1.6 `dpop` (2): "Agents get DPoP-bound tokens by default"; "Each delegation hop re-binds the token to the next agent's key"
- [ ] 1.7 `mcp-authorization` (1): "Agent clients register dynamically"
- [ ] 1.8 `oidc-provider` (1): "Rich authorization requests"
- [ ] 1.9 `rbac-admin-api` (1): "Scope mappings accept prefix globs"
- [ ] 1.10 `rp-initiated-logout` (1): "Logout infers the session from the request"
- [ ] 1.11 `saml-sp-profile` (1): "IdP-initiated SSO is a per-IdP registration policy"
- [ ] 1.12 `sdk-support-contract` (11): "JWKS re-fetch after a resource-server 401"; "Tenant and session claim accessors"; "Claim hooks re-render on token change"; "Admin client from the claim-check facade"; "Required-action error from REST answers"; "SDK releases declare the minimum server version"; "SDK line-coverage gate"; "Live role round-trip test"; "SDK dependencies are audited automatically"; "Go SDK refreshes expired access tokens"; "Conformance gate checks every error name and accessor"
- [ ] 1.13 `tool-permissions` (1): "Agents hold tool permissions as principals"

## 2. Close

- [ ] 2.1 When every requirement is cut or promoted, delete this change (do not archive it: nothing here was built)
