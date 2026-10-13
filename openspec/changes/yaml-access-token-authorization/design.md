## Context

`OAuthClient.access_token_authorization` exists, and the engine's `ImportClientRequest` and `UpdateClientRequest` carry it. Only the admin API (`POST`/`PATCH /admin/applications`) and the console set it, and the console refuses every edit of a YAML-declared application. `reconcile_applications` creates and updates YAML-declared clients, but `ApplicationYamlConfig` has no field for the mode, so a YAML client is always created `embedded`.

The admin API cannot reach a YAML-declared realm at first start. `extract_admin_auth` validates the bearer token against the realm in `X-Realm-ID`, and `/admin/bootstrap` returns tokens for `dev-realm` and the system realm only. `scoped_realm` (cross-realm access for a system token) covers realm routes, not applications.

## Goals / Non-Goals

**Goals:**
- An operator declares a resource server's client, with its mode, in `hearth.yaml` alone.
- The mode of a YAML-declared client never drifts from `hearth.yaml`.

**Non-Goals:**
- Cross-realm application administration for a system-realm token.
- The REST `PATCH` mapping of an unknown `access_token_authorization` or `trust_level` value to a default. That is a separate defect.
- Read-only display of YAML-owned fields in the console.

## Decisions

1. **YAML owns the mode; an omitted key means `embedded`.** The alternative is the `trust_level` rule (an omitted key leaves the stored value). The mode decides who can introspect every user-session token of the realm without `azp`, so it is a security setting, like `dpop_bound_access_tokens` and `jwks`. With YAML ownership, removing the key removes the right. With the `trust_level` rule, a mode set once stays after the operator removes it from the file.
2. **The engine gate refuses a change, not a mention.** `update_client` refuses `access_token_authorization` on a YAML-managed client only when the value differs from the stored mode. A REST client can send the whole application record with every `PATCH`; a gate on `is_some()` would refuse its change to an unrelated field. The existing gate for `jwks`, `assertion_public_key` and `dpop_bound_access_tokens` stays as it is.
3. **The YAML spelling is snake_case** (`introspection`), the serde form of `AccessTokenAuthorization`, the same as `trust_level`. `deny_unknown_fields` and the enum refuse any other value at config load.
4. **Reconcile writes the mode in the same write as the other fields.** Creation passes it in `ImportClientRequest`; an update passes `Some(mode)` only when it changed, the same as `dpop_bound_access_tokens`.

## Risks / Trade-offs

- [An admin set the mode of a YAML client through the API before the upgrade] → The first reconcile sets it to `embedded`, and the resource server's introspection answers `active: false`. Mitigation: a CHANGELOG `Changed` entry tells operators to declare the mode in `hearth.yaml`. Hearth has no production users yet.
