# Enterprise Integrations — Examples 34–38

`hearth.yaml` snippets for SCIM provisioning, SAML SP registration, custom claim mappings,
production observability, and storage tuning.
Return to the [example index](./index.md) for a full list of all examples.

---

## Example 34 — SCIM provisioning

**Audience:** operators whose enterprise customers provision and de-provision user accounts
from an identity provider (Okta, Azure AD, Workday) using the SCIM 2.0 protocol.

```yaml
oidc:
  issuer: "https://auth.example.com"

email:
  transport: smtp
  from: "Auth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"

realms:
  enterprise:
    scim:
      bearer_token: "${SCIM_TOKEN}"    # static token; Argon2id-hashed before storage
    auth:
      registration:
        mode: invite_only              # SCIM is the only provisioning path
```

- The SCIM endpoint is available at `/scim/v2/realms/enterprise/` once `bearer_token` is set.
  Configure this URL and the hashed token in your IdP's SCIM provisioning settings.
- `bearer_token` is stored as an Argon2id hash; the plaintext value is never persisted.
  Rotate it by updating the env var and restarting (or via the Admin API).
- Set `registration.mode: invite_only` (or `disabled`) so users cannot self-register and
  bypass the SCIM-controlled user lifecycle.

---

## Example 35 — SAML SP registration

**Audience:** operators who need Hearth to act as a SAML Identity Provider, issuing SAML
assertions to external service providers (Salesforce, Workday, internal wikis, etc.).

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  enterprise:
    saml_service_providers:
      salesforce:
        entity_id: "https://saml.salesforce.com"
        acs_url: "https://salesforce.com/services/oauth2/callback"
        slo_url: "https://salesforce.com/services/auth/logout"
        nameid_format: emailAddress   # emailAddress | persistent | transient | unspecified
        sign_assertions: true
        sign_responses: false
        attribute_map:
          email: "User.Email"
          display_name: "User.Name"
          department: "User.Department"

      internal-wiki:
        entity_id: "https://wiki.internal.example.com/saml"
        acs_url: "https://wiki.internal.example.com/saml/acs"
        nameid_format: persistent
        sign_assertions: true
```

- `saml_service_providers` keys (e.g. `salesforce`) are the SP identifier in Hearth's routing.
- `entity_id` and `acs_url` are required; all other fields are optional.
- Hearth signs assertions with the realm's Ed25519 signing key. Download the realm's public
  key from `GET /v1/realms/<slug>/keys` in JWK format to configure trust in the SP.
- `attribute_map` maps Hearth's internal field names to the SAML attribute names the SP
  expects (`email` → `User.Email` in this example).
- Set `slo_url` to participate in SAML Single Logout; omit it to skip SLO support.

---

## Example 36 — Custom claim mappings

**Audience:** operators who need to add, rename, or gate custom claims in access tokens,
ID tokens, or the UserInfo endpoint beyond Hearth's default claim set.

```yaml
oidc:
  issuer: "https://auth.example.com"

realms:
  acme:
    claims:
      mappings:
        # Embed assigned roles as a JSON array
        - claim: roles
          source: roles_from_assignments

        # Embed all effective permissions
        - claim: permissions
          source: effective_permissions

        # Map a canonical user field to a custom claim name
        - claim: preferred_username
          source: canonical_user_field
          field: preferred_username

        # Expose a profile attribute stored on the user record
        - claim: department
          source: user_attribute
          attribute: department
          include_in_access_token: true
          include_in_id_token: true
          include_in_userinfo: true

        # Inject a static constant for all tokens issued by this realm
        - claim: iss_env
          source: constant
          value: "production"
          include_in_access_token: true
          include_in_id_token: false
          include_in_userinfo: false

        # Gate a sensitive claim to requests that include a specific scope
        - claim: billing_account_id
          source: user_attribute
          attribute: billing_account_id
          required_scopes:
            - billing
          include_in_userinfo: true
```

- `source` is a YAML inline tag: simple sources (`roles_from_assignments`,
  `effective_permissions`, `org_context`) need no additional fields. Structured sources
  (`canonical_user_field`, `user_attribute`, `constant`) require their companion key (`field`,
  `attribute`, `value`) at the same YAML indentation level.
- `include_in_access_token` and `include_in_id_token` default to `true`. `include_in_userinfo`
  defaults to `false`. Set them explicitly when the defaults are wrong for your use case.
- `required_scopes` is an OR gate: the claim is included if the token has _any_ of the listed
  scopes. Use `allowed_clients` to restrict to specific client slugs.
- Tier-1 reserved claim names (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`) cannot be mapped.
  Hearth rejects the configuration with an error on startup.

---

## Example 37 — Production observability

**Audience:** operators deploying Hearth in a production environment with a centralized log
aggregator, distributed tracing collector, and ops alerting.

```yaml
observability:
  log_level: info          # trace | debug | info | warn | error
  log_format: json         # text | json — use json for log aggregators (Datadog, Loki)
  otlp:
    endpoint: "http://otel-collector.internal:4317"
    protocol: grpc          # grpc (default, port 4317) | http (port 4318)
    service_name: "hearth-prod"
    headers:
      x-honeycomb-team: "${HONEYCOMB_API_KEY}"   # omit if collector is unauthenticated

metrics:
  enabled: true             # expose Prometheus /metrics endpoint (default: true)

onboarding:
  notification_email: "ops@example.com"   # emailed the setup URL on first boot
```

- `observability.otlp` ships OpenTelemetry spans to any OTLP-compatible collector
  (Jaeger, Honeycomb, Grafana Tempo, AWS X-Ray via ADOT, etc.).
- `observability.log_format: json` is recommended in production; it makes structured fields
  (trace IDs, realm, user IDs) searchable in aggregators.
- `metrics.enabled: true` is the default. The Prometheus scrape endpoint is at `/metrics`.
  To disable it (e.g. when a sidecar scrapes instead), set `enabled: false`.
- `onboarding.notification_email` is only used at first boot, before the admin account
  exists. Hearth emails the setup URL to this address so you can complete onboarding without
  tailing container logs.

---

## Example 38 — Storage tuning

**Audience:** operators sizing the hot tier and compaction schedule for production workloads,
or moving data to a non-default path.

```yaml
storage:
  data_dir: "/var/lib/hearth/data"   # default: "hearth-data" in the working directory
  fsync: true                         # must be true in production — WAL durability
  hot_tier_capacity: 100000           # max entries held in the in-process hot tier
  # hot_tier_max_memory: 268435456   # alternative: size cap in bytes (256 MiB here)
  compaction:
    enabled: true
    interval_secs: 3600               # background SST compaction sweep every hour
```

- Set either `hot_tier_capacity` (entry count) or `hot_tier_max_memory` (byte cap), not both.
  `hot_tier_capacity` is simpler to reason about for a known dataset size.
- `fsync: true` is mandatory in production. Setting it to `false` loses WAL durability;
  `hearth serve --dev` does this for local development only.
- Compaction merges fragmented SST files and reclaims deleted-entry space. Lower
  `interval_secs` reduces space amplification at the cost of more background I/O.
- The WAL is always fsynced before acknowledging a write regardless of the `compaction`
  setting — compaction only affects SST merging, not write durability.

---
