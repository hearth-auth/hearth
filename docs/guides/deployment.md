# Deploying Hearth

This guide covers production deployment requirements for Hearth, including single-node and cluster modes.

## Single-node mode

By default, Hearth runs as a single node. No `hearth.yaml` file is required; the server starts immediately.

## Cluster mode

### Prerequisites

#### NTP time synchronization (hard requirement)

**NTP is a hard prerequisite for cluster mode.** All nodes must be time-synchronized before starting a Hearth cluster.

| Clock skew | Effect |
|---|---|
| < 1 s | Normal operation |
| 1 s – 10 s | Startup warning logged; leader election may be slower |
| > 10 s | High risk of split-brain; startup is blocked |

Use a system time daemon (e.g. `chrony`, `ntpd`, or `systemd-timesyncd`) on every node and verify synchronization before bringing the cluster online:

```bash
# chrony
chronyc tracking | grep "System time"

# systemd
timedatectl show --property=NTPSynchronized
```

Hearth does **not** compensate for clock skew — correct time synchronization is the operator's responsibility.

### hearth.yaml configuration

Create `hearth.yaml` in Hearth's working directory (or pass `--config /path/to/hearth.yaml`). The `cluster:` section activates cluster mode.

```yaml
cluster:
  # Unique identifier for this node within the cluster.
  node_id: "node-1"

  # Addresses of all other cluster members (excluding this node).
  peers:
    - id: "node-2"
      addr: "10.0.1.2:9090"
    - id: "node-3"
      addr: "10.0.1.3:9090"

  # Raft election timeout range (milliseconds).
  # Randomised between min and max to avoid split votes.
  # Recommended: min=150, max=300 for LAN deployments.
  election_timeout_min_ms: 150
  election_timeout_max_ms: 300

  # How often the leader sends heartbeats (milliseconds).
  # Must be well below election_timeout_min_ms.
  heartbeat_interval_ms: 50

  # Maximum log entries per AppendEntries RPC batch.
  max_log_entries_per_batch: 500

  # Number of log entries between automatic Raft snapshots.
  snapshot_threshold: 10000

  # Reads that lag the leader by more than this value (ms) return an error.
  read_lag_threshold_ms: 500
```

Omitting the `cluster:` key entirely is equivalent to single-node mode — no error, no overhead.

### Validation

Hearth validates the cluster section on startup and emits a descriptive error (not a panic) for each misconfiguration:

- `cluster.node_id` must be non-empty.
- `cluster.peers` must be non-empty.
- Every peer `addr` must be a valid `host:port` socket address.
- `election_timeout_min_ms` must be strictly less than `election_timeout_max_ms`.

### Minimum viable cluster

A Raft cluster requires **at least three nodes** to tolerate one failure. Two-node clusters have no fault tolerance — if one node is unavailable, quorum is lost.

### Port requirements

| Port | Purpose |
|---|---|
| `8080` | OAuth / OIDC API (configurable) |
| `9090` | Raft peer communication (as configured in `peers[].addr`) |

Open the Raft port only between cluster nodes; it must not be externally accessible.
