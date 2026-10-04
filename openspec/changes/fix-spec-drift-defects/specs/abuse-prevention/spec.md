## MODIFIED Requirements

### Requirement: A-4 Outbound email volume shield
The server SHALL track the distinct outbound email recipients of each realm in a rolling window, and SHALL abandon a send that exceeds the realm's hard cap. Recipient addresses SHALL be held only as `SipHash-1-3` hashes; plaintext recipient addresses SHALL NOT be retained in memory. The check SHALL run before the send, and before the A-50 cross-realm check. The check SHALL run in the off-request-path send job, so a refused send costs the caller exactly what an allowed one does and the caller's response does not reveal it.

| Key (`security.outbound_volume_shield.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the shield runs |
| `window` | `3600s` | Rolling window length |
| `email_soft_cap` | `1000` | Distinct recipients before `SoftCap` |
| `email_hard_cap` | `5000` | Distinct recipients before `HardCap` |

| Outcome | Required caller action |
|---------|------------------------|
| `Allow` | Proceed with the send |
| `SoftCap` | Emit an `AbuseDetected` audit event and an A-7 security webhook; the send MAY proceed |
| `HardCap` | MUST abandon the send silently, with the caller's response unchanged; emit an `AbuseDetected` audit event |

When its lock is poisoned, the shield SHALL recover the lock and keep counting.

#### Scenario: A realm pumps email to many recipients
- **WHEN** a realm sends to more than `email_hard_cap` distinct recipients inside the window
- **THEN** the next message to a new recipient is not sent, and the response to the request that triggered it is the same as for a sent message
- **AND** an `AbuseDetected` audit event is written

#### Scenario: A realm crosses the soft cap
- **WHEN** a realm exceeds `email_soft_cap` but not `email_hard_cap`
- **THEN** the send proceeds, and an audit event and a security webhook are emitted

#### Scenario: Regression — abandoned send is audited
- **WHEN** the shield abandons a send at `email_hard_cap`, or passes one at `email_soft_cap`
- **THEN** an `AbuseDetected` audit event is written
- **AND** at the soft cap, an A-7 security webhook is also emitted

### Requirement: A-7 Security webhook channel
Operators SHALL be able to subscribe a webhook to the `security.*` event family, so security events fan out to a SIEM, a chat channel or a WAF without polling the audit log. Each matching audit event SHALL be signed with HMAC-SHA256 and POSTed to the endpoint with exponential-backoff retry. The `X-Hearth-Event` header SHALL carry the audit action's wire key (for example `login_failed`), not the dot-notation name; consumers SHOULD match on the wire key. The five event types SHALL appear in the admin UI webhook create and edit form under a **Security events** group.

| Event type | Audit action | Meaning |
|------------|--------------|---------|
| `security.login_failed` | `LoginFailed` | Credential verification failed |
| `security.account_locked` | `LoginLocked` | Account temporarily locked |
| `security.abuse_detected` | `AbuseDetected` | Abuse pattern detected by the A-3 detector |
| `security.password_compromised` | `PasswordCompromisedRejected` | Password rejected as known-compromised (HIBP) |
| `security.rate_limit_exceeded` | `IpLoginLimitExceeded` | Per-IP login rate limit hit |

#### Scenario: A failed login reaches a subscribed endpoint
- **WHEN** a webhook is subscribed to `security.login_failed` and a login fails
- **THEN** the endpoint receives a signed POST with `X-Hearth-Event: login_failed`

#### Scenario: The endpoint is down
- **WHEN** the endpoint fails a delivery
- **THEN** the delivery is retried with exponential backoff

#### Scenario: Regression — UI-created security subscription delivers
- **WHEN** an operator subscribes a webhook to `security.login_failed` in the admin UI form and a login then fails
- **THEN** the endpoint receives a signed POST with `X-Hearth-Event: login_failed`

### Requirement: A-24 Per-realm resource quotas
Each realm SHALL be able to cap its resources under `realms.<name>.quotas`; every limit SHALL default to unlimited. A create that would exceed a count-based limit SHALL be rejected with `HEARTH_QUOTA_EXCEEDED` (HTTP `429`) once `current >= limit`.

| Key | Resource | Enforcement |
|-----|----------|-------------|
| `max_users` | User records in the realm | On create, fail-closed |
| `max_orgs` | Organizations in the realm | On create, fail-closed |
| `max_clients` | Registered OAuth/OIDC clients | On create, fail-closed |
| `max_sessions` | Active sessions across all users | On create, fail-closed |
| `max_audit_rows` | Audit rows | Daily background pruner |
| `max_disk_bytes` | Disk usage | Sampled daily; warning only |

Count-based quotas SHALL be checked on every create by scanning the relevant storage prefix, and a scan error SHALL count as `current = limit`, so the create is rejected rather than bypassing the quota. `max_disk_bytes` SHALL be checked once per day by the background pruner and SHALL emit a warning but SHALL NOT block writes (fail-open); operators SHOULD pair it with OS-level disk quotas or alerting. `max_audit_rows` SHALL be enforced by the daily pruner after the `retention_days` sweep.

#### Scenario: The user quota is full
- **WHEN** a realm with `max_users: 10000` holds 10 000 users and another user is created
- **THEN** the create fails with `429` and `HEARTH_QUOTA_EXCEEDED`

#### Scenario: The storage scan fails
- **WHEN** the quota count cannot be read
- **THEN** the create is rejected

#### Scenario: Regression — documented quota block loads
- **WHEN** `hearth.yaml` sets `realms.<name>.quotas.max_users: 10` and an eleventh user is created
- **THEN** the server starts
- **AND** the eleventh create fails with `429` and `HEARTH_QUOTA_EXCEEDED`

#### Scenario: Regression — audit row quota is enforced
- **WHEN** a realm sets `max_audit_rows: 1000` and holds 1 500 audit events at the daily prune
- **THEN** the oldest 500 events are deleted

### Requirement: A-35 SCIM and SAML payload caps
A SCIM PATCH for a user or a group SHALL be rejected with HTTP `413 Payload Too Large` when `Operations` holds more than `MAX_SCIM_OPERATIONS` (1 000) entries, before any patch logic runs. SAML response parsing SHALL stop with a parse error after `MAX_SAML_XML_EVENTS` (10 000) XML events, and SHALL NOT expand entities. Both caps SHALL fail closed.

#### Scenario: A PATCH with too many operations
- **WHEN** a SCIM client sends a PATCH with 1 001 operations
- **THEN** the response is `413` and nothing is changed

#### Scenario: An element flood
- **WHEN** an Assertion Consumer Service receives a response with 50 000 elements and no DTD
- **THEN** parsing stops and the response is rejected

#### Scenario: Regression — SAML cap carries its own id
- **WHEN** the code documents which guard `MAX_SAML_XML_EVENTS` implements
- **THEN** it names A-35, not the id of another guard

### Requirement: A-50 Cross-realm email aggregation cap
The server SHALL count, across the whole cluster and in a rolling window, the distinct realms that send to each recipient, so an attacker who splits sends across many realms to stay under the A-4 per-realm budget is caught. The check SHALL run in addition to the A-4 check and after it; both SHALL pass before a send proceeds. Recipient addresses and realm IDs SHALL be held only as `SipHash-1-3` hashes. Callers MUST NOT surface `realm_count` to the sending realm or to any external client.

| Key (`security.cross_realm_aggregation_cap.*`) | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Whether the cap runs |
| `window` | `3600s` | Rolling window length |
| `alert_threshold` | `3` | Distinct realms before an operator alert |
| `email_realm_soft_cap` | `5` | Distinct realms before `SoftCap` |
| `email_realm_hard_cap` | `10` | Distinct realms before `HardCap` |

| Outcome | Fires at | Required caller action |
|---------|----------|------------------------|
| `MultiRealmAlert` | more than `alert_threshold` realms | Emit an `AbuseDetected` audit event and an A-7 webhook; the send MAY proceed |
| `SoftCap` | more than `email_realm_soft_cap` realms | The send proceeds; SHOULD emit the audit event and webhook |
| `HardCap` | more than `email_realm_hard_cap` realms | MUST abandon the send silently, with the caller's response unchanged; MUST emit the audit event and webhook |

The check SHALL run in the off-request-path send job, like the A-4 check. Setting every threshold to `usize::MAX` SHALL disable the cap. When its lock is poisoned, the cap SHALL recover the lock and keep counting.

#### Scenario: One victim, many realms
- **WHEN** eleven distinct realms send to `victim@example.com` inside the window, each under its own A-4 budget
- **THEN** the eleventh message is not sent, the response to the request that triggered it is unchanged, and an audit event and webhook are emitted

#### Scenario: The count stays private
- **WHEN** a send is refused by the cap
- **THEN** the response does not reveal how many realms targeted the recipient

#### Scenario: Regression — abandoned cross-realm send is audited
- **WHEN** the cap abandons a send at `email_realm_hard_cap`
- **THEN** an `AbuseDetected` audit event and an A-7 webhook are emitted
