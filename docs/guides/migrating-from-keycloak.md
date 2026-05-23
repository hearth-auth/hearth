# Migrating from Keycloak

This guide covers the key differences between Keycloak and Hearth to help operators migrate existing deployments.

## Federation / Identity Providers

Keycloak federation is configured via the Admin Console under **Identity Providers**. In Hearth, all federation configuration lives in `hearth.yaml` under `realms.<name>.federation` — the Admin UI is read-only.

For a full mapping of Keycloak concepts to Hearth equivalents, see **§10 (Keycloak → Hearth federation mapping)** in the [Federation and social login guide](./federation.md).

For step-by-step instructions on configuring each provider type, see the [Federation and social login guide](./federation.md).

## Configuration model

| Keycloak | Hearth |
|---------|-------|
| Admin Console + database | `hearth.yaml` (config-as-code) |
| Realm export/import JSON | `hearth.yaml` realms block |
| Hot-reload via UI | `SIGHUP` to reload `hearth.yaml` |

## Realms

Keycloak realms map directly to Hearth realms under the `realms:` key in `hearth.yaml`. Hearth boots with a built-in `default` realm when no `realms:` block is present.

## Clients

Keycloak client concepts map to Hearth clients registered in `hearth.yaml` under `realms.<name>.clients`. See [CONFIGURATION.md](../specs/CONFIGURATION.md) for the full client field reference.

## Account linking

Keycloak's **First Login Flow** account-linking behavior maps to Hearth's `link_existing_accounts` setting. See [Federation and social login §8](./federation.md#8-account-linking-policy).

## Claim / attribute mappings

Keycloak Mappers translate to `claim_mappings` (OIDC) and `attribute_map` (SAML) in Hearth. See [Federation and social login §9](./federation.md#9-custom-claim-mappings).
