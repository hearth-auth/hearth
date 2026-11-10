# Monitoring Hearth

This folder holds Prometheus alert rules and a Grafana dashboard for Hearth (#648).

| File | What it is |
|---|---|
| `prometheus/hearth-alerts.yml` | Alert rules. Load it with `rule_files:` in `prometheus.yml`. For the Prometheus Operator, put its `groups:` list in a `PrometheusRule` resource. |
| `prometheus/hearth-alerts.test.yml` | `promtool` unit tests for the alert rules. |
| `grafana/hearth-dashboard.json` | A Grafana dashboard. Import it, then select your Prometheus data source. |

`make monitoring-check` checks the rules, runs their unit tests, and parses every dashboard query. CI runs it on every pull request. `tests/metric_names_in_docs.rs` fails if a file here names a metric that Hearth does not export.

## Scrape Hearth

Hearth serves Prometheus metrics at `/metrics`. Set `metrics.bearer_token` to require a token (see the `metrics` section of the [configuration reference](../../docs/guides/configuration-reference.md)). The metrics table in that section lists every metric.

The rules and the dashboard select the scrape job `job="hearth"`. If your job has another name, replace `job="hearth"` in the rules and in the dashboard's `instance` variable.

```yaml
scrape_configs:
  - job_name: hearth
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/hearth-metrics-token
    static_configs:
      - targets: ["hearth-1.example.com:8420", "hearth-2.example.com:8420"]
```

## Alerts

The thresholds are starting points. Tune them to your traffic and hardware.

| Alert | Severity | Fires when | What to do |
|---|---|---|---|
| `HearthDown` | critical | Prometheus cannot scrape an instance for 2 min. | Check the process (`systemctl status hearth`, `kubectl get pods`) and `/healthz`. |
| `HearthHighErrorRate` | warning | More than 5% of requests get a 5xx status for 10 min. | Read the server log for the errors. Look at the dashboard's latency and storage panels. |
| `HearthWalWriteFenced` | critical | A WAL write failed, and the server refuses every write. | The fence lasts until the process restarts. Check the disk (space, `dmesg` I/O errors), then restart. See the WAL write fence section of the [disaster recovery guide](../../docs/guides/disaster-recovery.md). |
| `HearthDiskSpaceLow` | warning | Less than 15% of the data disk is free for 10 min. | Add disk space. A compaction needs free space for its output. |
| `HearthDiskSpaceCritical` | critical | Less than 5% of the data disk is free for 5 min. | Add disk space now. A full disk stops all writes. |
| `HearthDiskWillFillIn24h` | warning | At the rate of the last 6 h, the data disk is full within 24 h, and less than 40% is free. | Find the cause of the growth (for example the audit log: see the per-realm audit retention in the [data retention guide](../../docs/guides/data-retention.md)), or add disk space. |
| `HearthWalFsyncSlow` | warning | The WAL fsync p99 is above 50 ms for 10 min. | Every write waits for this sync. Check the disk's latency and for other load on the disk. |
| `HearthCompactionFailing` | warning | A compaction failed in the last hour. | Read the server log for the compaction error. If compaction stops, the SST file count and the read latency grow. |
| `HearthSstFilesHigh` | warning | More than 36 SST files for 30 min (3 times the default `storage.compaction.max_sst_count`). | Compaction does not keep up. Check `HearthCompactionFailing` and the compaction settings. |
| `HearthStorageWritesShed` | warning | The server refused storage writes (503) because `storage.max_writes_in_flight` writes were in progress. | A slow disk is the usual cause: see `HearthWalFsyncSlow`. |
| `HearthBackupTooOld` | warning | For 30 min, the newest successful backup (online or offline, on any instance) is more than 26 h old, or no backup ever completed. | Check the backup job's log and exit status. Run a backup. See the [backup guide](../../docs/guides/backup.md#monitoring-backups). |
| `HearthAuditIntegrityFailure` | critical | An audit chain verification failed. | The audit log was changed outside Hearth, or the store is damaged. Keep a copy of the data directory before you change anything, and investigate. |
| `HearthControlEpochBumpsOwed` | critical | For 10 min, a control (such as a token or session revocation) is not announced to the other cluster nodes. | The other nodes do not enforce that revocation yet. Check the cluster's health and the server log. |
| `HearthRateLimitersDisabled` | warning | The server runs with rate limiters off. | This is for load tests only. Remove the setting that disables the limiters. |
| `HearthKdfShedding` | warning | The server refused password checks (503) for 10 min because the Argon2id queue was full. | Add CPU, or raise `security.password.kdf.max_in_flight` if CPU is free. |
| `HearthUserCreateShedding` | warning | The server refused user creates (503) for 10 min. | Raise `operational.user_create.max_in_flight` if CPU is free. |

`HearthBackupTooOld` sees that the server built an archive. It does not see that your job stored it. Also monitor the exit status of the backup job.
