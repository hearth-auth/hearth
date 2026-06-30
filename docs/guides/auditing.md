# Audit Log Guide

**Audience:** operators and security engineers responsible for compliance, incident investigation, or audit-trail management.
**Goal:** Query, export, verify integrity of, and configure retention for the Hearth audit log on a realm.
**Time to complete:** 15–20 min.

Hearth records a tamper-evident audit log for every realm. Each event is appended to a SHA-256 hash chain so that truncation or modification is detectable. This guide covers how to query, export, and retain audit events.

---

## What is logged

Every significant identity operation emits an audit event:

| Category | Examples |
|---|---|
| Authentication | login success, login failure, MFA enroll/verify, magic link sent |
| Users | user created, updated, deleted, password changed |
| Sessions | session created, revoked |
| Tokens | access token issued, refresh token rotated, token revoked |
| Clients | OAuth client registered, updated, deleted |
| Roles / Groups | role created, assigned, unassigned; group created, membership changed |
| Organizations | org created, updated, deleted, member added/removed, invitation sent |
| Realms | realm created, updated, deleted |
| Admin | admin API calls, integrity verification |

Each event carries: `id`, `timestamp` (microseconds UTC), `action`, `actor` (user ID or "system"), `resource_type`, `resource_id`, and an optional `metadata` object.

---

## Viewing events

### Admin UI

`GET /admin/realms/{realm}/audit` — the audit log page. Filter by actor, action, or date range. Each row expands to show full metadata.

### REST API

`GET /admin/api/realms/{realm}/audit/events`

Returns a JSON object:

```json
{
  "realm_id": "<uuid>",
  "count": 3,
  "events": [
    {
      "id": "<uuid>",
      "timestamp": 1716163200000000,
      "action": "user.created",
      "actor": "<user-uuid>",
      "resource_type": "user",
      "resource_id": "<user-uuid>",
      "metadata": { "email": "alice@example.com" }
    }
  ]
}
```

**Query parameters:**

| Parameter | Description |
|---|---|
| `actor` | Filter by actor (user UUID or "system") |
| `action` | Filter by action name (e.g., `user.created`) |
| `start_date` | Start of date range, `YYYY-MM-DD` (inclusive) |
| `end_date` | End of date range, `YYYY-MM-DD` (inclusive) |
| `limit` | Max events to return (default 200, max 1 000) |

**Example:**

```bash
curl https://auth.example.com/admin/api/realms/production/audit/events \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -G \
  --data-urlencode "action=user.created" \
  --data-urlencode "start_date=2026-05-01" \
  --data-urlencode "limit=100"
```

---

## Exporting events

`GET /admin/realms/{realm}/audit/export`

Downloads up to 10 000 events as a file attachment. The response format is determined by the `format` parameter:

| `format` | Content-Type | Filename |
|---|---|---|
| *(omitted or any non-csv value)* | `application/x-ndjson` | `audit-{realm}-{date}.ndjson` |
| `csv` | `text/csv; charset=utf-8` | `audit-{realm}-{date}.csv` |

NDJSON (newline-delimited JSON) is the default and is suitable for streaming into log aggregators, SIEM tools, and `jq` pipelines. CSV is useful for spreadsheet analysis.

**Example — download NDJSON and pipe to jq:**

```bash
curl -s "https://auth.example.com/admin/realms/production/audit/export" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r 'select(.action == "user.login_failed") | [.timestamp, .actor, .metadata.ip] | @tsv'
```

**Example — download CSV:**

```bash
curl -s "https://auth.example.com/admin/realms/production/audit/export?format=csv" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o audit-production-$(date +%F).csv
```

Accepts the same `actor`, `action`, `start_date`, `end_date`, and `limit` query parameters as the events API above.

---

## Retention

### Read the current retention policy

`GET /admin/api/realms/{realm}/audit/config`

```bash
curl https://auth.example.com/admin/api/realms/production/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:

```json
{ "retention_days": 90 }
```

A value of `0` means unlimited retention — events are never automatically pruned.

### Update the retention policy

`PUT /admin/api/realms/{realm}/audit/config`

```bash
curl -X PUT https://auth.example.com/admin/api/realms/production/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 365}'
```

The server responds with the updated config object:

```json
{ "retention_days": 365 }
```

**Special values:**

| Value | Effect |
|---|---|
| `90` | Default — keep events for 90 days |
| `0` | Unlimited — never automatically prune |
| `N` | Keep events for N days; prune older on next scheduled run |

### Scheduled vs. manual pruning

Automatic background pruning runs according to Hearth's internal maintenance schedule. To immediately delete all events older than the configured window, call the manual prune endpoint.

---

## Manual prune

`POST /admin/api/realms/{realm}/audit/prune`

Immediately deletes all audit events older than `retention_days`. Returns the count of deleted records.

```bash
curl -X POST https://auth.example.com/admin/api/realms/production/audit/prune \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:

```json
{ "deleted": 1432 }
```

If `retention_days` is `0` (unlimited), the endpoint returns `{"deleted": 0}` without touching any events.

**When to use manual prune:**

- GDPR / CPRA right-to-erasure requests (set a short window, then prune immediately).
- COPPA compliance — reduce stored personal data before an audit.
- Recovering disk space before a scheduled backup.
- Testing retention behavior in staging without waiting for the background job.

:::note[Hash chain integrity after pruning]
Pruning deletes events from the bottom of the hash chain. The remaining events are still internally consistent — each still links to its predecessor — but the chain no longer starts at genesis for the pruned realm. `POST /admin/realms/{realm}/audit/verify` reports the first surviving event as the new chain head; it does **not** flag pruned history as a tampering violation. If you require a continuous unbroken chain for compliance, export the events first, then prune.
:::

---

## Integrity verification

`POST /admin/realms/{realm}/audit/verify`

Recomputes the SHA-256 hash chain for the realm's audit log and reports any breaks. Use this to detect storage corruption or unauthorized deletion.

```bash
curl -X POST https://auth.example.com/admin/realms/production/audit/verify \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

A clean result returns `200 OK` with a summary of the verified event count. A broken chain returns a non-2xx status with the position of the first inconsistency.

---

## Recommended practices

### Compliance exports

For SOC 2 / ISO 27001 / PCI-DSS audit trails, schedule a nightly NDJSON export and ship it to immutable object storage (e.g., S3 Object Lock):

```bash
# /etc/cron.d/hearth-audit-export
0 1 * * * hearth-admin /usr/local/bin/hearth-audit-export.sh >> /var/log/hearth/audit-export.log 2>&1
```

```bash
#!/bin/bash
# hearth-audit-export.sh
DATE=$(date +%F)
REALM=production
curl -sf "https://auth.example.com/admin/realms/$REALM/audit/export" \
  -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  -o "/tmp/audit-$REALM-$DATE.ndjson" \
&& aws s3 cp "/tmp/audit-$REALM-$DATE.ndjson" "s3://my-audit-bucket/hearth/$REALM/$DATE.ndjson" \
&& rm "/tmp/audit-$REALM-$DATE.ndjson"
```

### Retention recommendations

| Use case | `retention_days` |
|---|---|
| General production (recommended minimum) | `90` |
| PCI-DSS / SOC 2 (requires 1 year) | `365` |
| GDPR-sensitive (minimize stored PII) | `30`–`90` + external archive |
| Developer / staging environment | `7`–`30` |
| Unlimited (self-managed deletion) | `0` |

### Per-realm retention

Each realm has its own retention policy. A multi-tenant deployment might set a short window for dev realms and a longer one for production:

```bash
# Short retention for dev
curl -X PUT https://auth.example.com/admin/api/realms/dev/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 14}'

# 1-year retention for production
curl -X PUT https://auth.example.com/admin/api/realms/production/audit/config \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 365}'
```
