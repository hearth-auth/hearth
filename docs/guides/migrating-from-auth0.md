# Migrating from Auth0

This guide covers the key differences between Auth0 and Hearth to help operators migrate existing deployments.

## Federation / Connections

Auth0 uses **Connections** to configure social and enterprise identity providers. In Hearth, all federation configuration lives in `hearth.yaml` under `realms.<name>.federation` — there is no dynamic runtime UI for managing providers.

For a full mapping of Auth0 Connection concepts to Hearth equivalents, see **§11 (Auth0 Connection → Hearth federation mapping)** in the [Federation and social login guide](./federation.md).

For step-by-step setup instructions for each provider type (Google, GitHub, Microsoft, Apple, OIDC, SAML), see the [Federation and social login guide](./federation.md).

## Configuration model

| Auth0 | Hearth |
|------|-------|
| Dashboard + API | `hearth.yaml` (config-as-code) |
| Tenant | Realm in `hearth.yaml` |
| Application | Client registered in `hearth.yaml` |
| Hot-reload via Dashboard | `SIGHUP` to reload `hearth.yaml` |

## Tenants and Realms

Auth0 tenants map to Hearth realms under the `realms:` key in `hearth.yaml`. Hearth boots with a built-in `default` realm when no `realms:` block is present.

## Applications

Auth0 Applications map to clients in Hearth. See [CONFIGURATION.md](../specs/CONFIGURATION.md) for the full client field reference.

## Rules and Actions

Auth0 Rules/Actions that manipulate tokens map to Hearth's `claim_mappings` (OIDC) and `attribute_map` (SAML) settings for inbound claim transformation. See [Federation and social login §9](./federation.md#9-custom-claim-mappings).

## Account linking

Auth0's account linking Actions map to Hearth's `link_existing_accounts` setting (`disabled`, `confirm`, or `auto`). See [Federation and social login §8](./federation.md#8-account-linking-policy).

## Universal Login

Auth0 Universal Login corresponds to Hearth's built-in login UI served at `/ui/login`. Hearth's login page is customizable via theme configuration in `hearth.yaml`.
