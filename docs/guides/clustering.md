# Clustering Guide

> **⚠ EXPERIMENTAL — multi-node is NOT supported for production.** Single-node is the only
> supported deployment for Hearth 1.x. **Do not** use a multi-node cluster:
>
> - for **load-balanced traffic** — writes and logins on a follower now succeed (they are forwarded to the leader, [H-3](#h-3--writes-to-a-follower-forwarded-to-the-leader-fixed)), but reads served by a follower may be stale ([C-5](#c-5--follower-cache-invalidation-is-partial-was-followers-never-invalidate)) and per-node state (below) differs between nodes;
> - as **HA failover** — membership is fixed at bootstrap ([C-6](#c-6--cluster-membership-is-immutable-after-bootstrap)), and per-node state (below) does not survive a node switch.
>
> A cold cluster *does* start as of task 26.46 ([G-1](#g-1--a-cold-cluster-could-not-be-bootstrapped-fixed), fixed). Starting is not the same as being fit for production: the defects below still apply to a running cluster. (An earlier revision of this banner said a cluster could not start at all; that described the pre-fix state.)

Hearth includes a partial Raft consensus implementation (`src/cluster/` via `openraft`). The clustering code path exists, but several components are unimplemented or incomplete. This guide documents the current state so operators can make informed decisions.

**Single-node mode is the default and only production-supported configuration.** Omit the `cluster:` YAML section entirely. There is zero overhead — no extra port, no Raft log, no election timers.

**State that is per node, not replicated** (GA audit 2026-09-28): the session-cookie secret and
the DPoP nonce secret are generated per process when not configured, rate limiters and the KDF
admission gate count per node, and MFA / IP attempt counters are node-local. Peer mTLS accepts any
certificate issued by the cluster CA, with no pinning of which node ID a certificate may claim.

---

## Known Defects in Experimental Cluster Mode

### G-1 — A cold cluster could not be bootstrapped (FIXED)

`serve` builds the identity engine over the cluster storage adapter, and that
constructor **writes** on a cold `data_dir` — the KEK-enrolment marker, the
global signing key and the system-realm row. In cluster mode each is a Raft
proposal, and a cluster that has not been bootstrapped has no leader, so the
first one returned `NotLeader` and start-up was fatal on every node:

```text
ERROR hearth: error: storage error: storage I/O error:
              raft: not the leader; redirect to unknown
```

The consequence was that the Bootstrap Sequence could not be performed at all:
step 1 (start all nodes) never completed, so step 3 (POST
`/admin/cluster/bootstrap`) was unreachable — including on the designated
bootstrap node. Verified on three nodes on 2026-09-21; the transcript is in
`reports/cluster-ga-readiness-2026-09-21.md`.

**Fixed in two halves** (task 26.46), both covered by
`tests/cluster_three_node_control_coherence.rs::a_cold_three_node_cluster_starts_every_node_without_a_manual_bootstrap`:

* **Self-initialisation.** The node with the **lowest node ID** in the
  membership its own `cluster.peers` names initialises Raft at start-up, so a
  leader is elected without an HTTP call. The other nodes stay pristine and
  adopt the membership from the first `AppendEntries` they receive. Nothing new
  is trusted — the membership, peer addresses and mTLS material all come from
  that node's own `hearth.yaml`.
* **A start-up write window.** Before building the identity engine, a node
  waits until either it is the leader (its writes will land) or the
  system-realm row has replicated to it (the leader finished the write set, so
  there is nothing left to write). If neither happens within 120 s, start-up
  fails with a message naming the likely causes.

**Operational consequences.**

* A cold cluster forms on its own. `POST /admin/cluster/bootstrap` still works
  and now answers `409` on an already-initialised cluster; it remains the
  escape hatch when the lowest-ID node is the one that is down.
* Provision the lowest-ID node first, or at least start it alongside the
  others. If it never starts, the remaining nodes wait out the 120 s window and
  exit — bootstrap one of them explicitly instead.
* A `cluster:` section with an empty `peers` list does **not** self-initialise;
  there is nothing to replicate to. Use the endpoint.

### C-5 — Follower cache invalidation is partial (was: "followers never invalidate")

Earlier revisions of this section said followers contain no cache-invalidation logic at all. That
is no longer what the code does. Every node's identity engine is registered as the Raft state
machine's replicated-write observer (`impl ReplicatedWriteObserver for EmbeddedIdentityEngine`,
`src/identity/engine/mod.rs`), and on every replicated put **and** delete it forwards:

- the row to the **RBAC engine**, which bumps the realm's decision-cache generation for role,
  permission and assignment rows (task 23.16) — so a role unassignment or permission revocation on
  the leader stops resolving on followers;
- the row to the **audit engine**, which drops its cached signed chain head (task 26.47);
- **revoked-token (JTI) rows** into the node's revocation cache;
- the replicated **control epoch**, which makes the node reload its control caches.

`tests/cluster_three_node_control_coherence.rs` covers a control asserted on the leader binding on
both followers and a token revocation on the leader binding promptly on both followers.

**What is still not established:** this is an allow-list of forwarded row types, not a general
cache-coherence protocol, and no test proves coherence for every cached type (for example
session-lookup caches). Treat any read served by a follower as potentially stale, and do not rely
on a follower for an access decision that must reflect the latest revocation.

### C-6 — Cluster membership is immutable after bootstrap

`add_learner` and `change_membership` are not implemented. The only path to set cluster membership is `raft.initialize()` from static YAML at first bootstrap.

**Consequence:** Nodes cannot be added or removed from a running cluster. Replacing a failed node requires a full-cluster restart with updated YAML. Online membership changes are not possible in Hearth 1.x.

### H-3 — Writes to a follower: forwarded to the leader (fixed)

Earlier releases refused every write that reached a follower (`raft: not the leader`, an HTTP
500), so user creation, token issuance and **every login** (a login writes a session) failed on
`(n-1)/n` of the nodes behind a load balancer.

A follower now **forwards the write to the leader** inside the cluster — standard Raft
client-request forwarding, as in etcd and Consul (`src/cluster/engine.rs`,
`propose_with_response`):

1. The follower sends the replicated command to the current leader over the existing peer mTLS
   channel (the `ForwardWrite` RPC on `cluster.peer_address`). It is authenticated exactly like
   the Raft RPCs: both ends present certificates signed by the cluster CA. No client-facing port
   or redirect is involved, so clients and load balancers need no leader awareness.
2. The leader proposes it and answers once it has committed and applied it, with the log index
   and the result (a conditional write's outcome, such as a single-use claim, travels back
   with it).
3. The follower waits until **its own** state machine has applied that log index before it
   answers, so a caller reads its own write on the node it wrote to — a login served by a
   follower can use its session on that follower straight away.

**Exactly once.** A forwarded write is retried — once, on a newly elected leader — only when it
provably never entered the Raft log: the leader could not be reached at all, or it answered that
it is no longer the leader without proposing the write. Once the request may have reached a
leader that proposed it (the connection dropped mid-call, the leader's commit wait timed out, the
leader died), the outcome is unknown and the write fails with
`the write was forwarded to the leader at <addr> and its outcome is unknown` instead of being
retried: a retried single-use claim would answer "already used" for the caller's own write, and a
retried counter increment would count twice. The caller (and the HTTP client) should re-read
before retrying, exactly as for a `cluster.write_timeout_ms` timeout on the leader itself.

**Bounds.** Finding a leader plus the forwarded call are bounded by `cluster.write_timeout_ms`
(default 10 s) plus 2 s; the follower's wait for its own apply is bounded by
`cluster.write_timeout_ms` again (on expiry the write is durable but the call fails with
`...did not apply it within ... ms`, and the write appears on that node once it catches up). A
leader serves at most **256** forwarded writes at once and refuses the next one immediately; a
forwarded command is limited to **3 MiB** serialized (a larger write fails on a follower with a
message to send it to the leader). While no leader is elected, a follower's write waits for the
election within that bound and then fails with `raft: not the leader`.

**What did not change.** Only writes are forwarded. Reads are still served locally by every node
and may be stale (C-5); the cold-start write set still runs only on the leader
([G-1](#g-1--a-cold-cluster-could-not-be-bootstrapped-fixed)). Covered by
`tests/cluster_follower_write_forwarding.rs` (writes, a login and a single-use claim issued to a
follower; a lost reply applied once and never retried; the leader killed mid-forwarding).

### Exclusive `data_dir` lock

Hearth holds an OS-level advisory flock on the `data_dir/LOCK` file for the lifetime of the process. A second process attempting to open the same `data_dir` will fail immediately with `StorageError::AlreadyLocked`.

This lock is process-scoped and cannot be shared across nodes. Each node in a cluster must use a completely separate `data_dir` on separate storage. You cannot point two nodes at the same directory or network share.

**In Kubernetes:** Use `accessMode: ReadWriteOnce` and a separate PVC per pod. A `ReadWriteMany` mount shared between pods will trigger the lock and prevent startup.

---

## When Clustering Will Be Production-Ready

The Wave 5 roadmap items covering clustering are:
- **HEA-2177 (W5-1)** — RBAC/claims cache invalidation on followers (C-5; partially addressed — RBAC, audit, revoked-token and control-epoch rows are now forwarded, see C-5)
- **HEA-2178 (W5-2)** — Online membership changes via `add_learner` / `change_membership` (C-6)
- ~~**HEA-2173 (W3-3)** — Follower-write 307 redirect to leader instead of HTTP 500 (H-3)~~ — superseded: followers forward writes to the leader inside the cluster (H-3, fixed)

The remaining two are post-GA. Because Hearth 1.x ships **no supported multi-node path**, none of
them gate the 1.0 release.

Until these ship, the production deployment model is single-node with external backups and a planned failover procedure. If your reliability requirements exceed what a single node provides, contact us to understand the timeline.

---

## Experimental Usage (Development and Evaluation Only)

If you are evaluating cluster behaviour for integration work or contributing to the clustering implementation, the following documents the current API. Do not run this in production.

> **Cluster init failure is fatal.** If a `cluster:` section is present in `hearth.yaml` and Raft initialization fails (for example, because peer nodes are unreachable), Hearth exits non-zero. It does **not** fall back to running as a standalone single-node writer. To run single-node, omit the `cluster:` section entirely.

> **Startup emits an EXPERIMENTAL warning.** When the `cluster:` section is present, Hearth logs a `WARN`-level message at startup indicating that cluster mode is experimental and not production-supported (HEA-2154).

### Prerequisites

Before enabling cluster mode in a test environment:

1. **NTP on every node.** Hearth embeds a `leader_timestamp` (wall-clock microseconds) in every Raft log entry so all nodes apply the same timestamp to concurrent writes. Clocks must be NTP-synchronized.

2. **Mutual TLS certificates.** All inter-node gRPC connections are mTLS — plaintext is unconditionally rejected. You need:
   - A CA certificate shared by all nodes
   - A leaf certificate and private key for each node, signed by that CA

3. **Port reachability.** Each node's `peer_address` port (default `8421`) must be reachable from all other nodes.

4. **Separate `data_dir` per node.** The exclusive directory lock means no two nodes may share a `data_dir`.

5. **The same `HEARTH_MASTER_KEY` and key-encryption key on every node.** Both wrap data that *replicates*: a row encrypted by one node must be decryptable by the others. Generate each value **once** for the whole cluster and distribute it — do not run `openssl rand -hex 32` per node. Every node also needs the full set of settings that are [mandatory in production](../specs/CONFIGURATION.md#mandatory-in-production):

   | Setting | Where | Must match across nodes? |
   |---|---|---|
   | `HEARTH_MASTER_KEY` (env) | environment | **Yes** |
   | `security.key_encryption_key` (or `HEARTH_KEK`) | YAML or environment | **Yes** |
   | `server.tls_cert_path` + `server.tls_key_path`, **or** `server.trust_forwarded_proto: true` with a non-empty `server.trusted_proxies` | YAML | No — per node |

   `hearth config validate` reports this on the success path for any
   configuration with a non-empty `cluster.peers` — both when
   `HEARTH_MASTER_KEY` is unset and, because nothing local can compare one
   node's value against its peers', when it is set (task 26.51). It is a
   warning, not an error: the key is a property of the machine, not of the file
   being validated, so validating a cluster config on a laptop stays legal.
   The single-node host-key check only says the variable is missing on the
   host running the check; the cluster note adds that every node must carry
   the same value. A `{data_dir}/hearth.host_key` file never stands in for the
   variable outside `--dev`.

---

### Generating Certificates

Any PKI tooling works. A minimal setup with `openssl`:

```bash
# 1 — CA
openssl req -new -x509 -days 3650 -nodes \
  -subj "/CN=hearth-cluster-ca" \
  -keyout ca.key -out ca.crt

# 2 — Leaf key + CSR for node 1 (repeat with a node-specific CN for each node)
openssl req -new -nodes \
  -subj "/CN=hearth-node-1" \
  -keyout node1.key -out node1.csr

# 3 — Sign it. The SAN is REQUIRED: rustls verifies the peer against
#     subjectAltName and ignores the Common Name, so a leaf signed without
#     -extfile fails the handshake with no usable diagnostic.
#     Use the address the peers will actually dial.
openssl x509 -req -days 3650 \
  -extfile <(printf "subjectAltName=IP:10.0.0.1") \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in node1.csr -out node1.crt
```

Use `subjectAltName=DNS:node1.example.com` instead when `peers[].address` names
a hostname rather than an IP. Verify before deploying:

```bash
openssl x509 -in node1.crt -noout -text | grep -A1 "Subject Alternative Name"
```

An empty result means the certificate will not work.

---

### Configuration

Each node gets its own `hearth.yaml`. The `cluster.node_id` and `cluster.peer_address` are unique per node; the CA cert and `peers` list are the same across all nodes.

**Node 1 (`hearth-1.yaml`):**

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  # Distinct per node only when several nodes share a host (evaluation).
  # On separate hosts every node can keep the default 8420.
  port: 8420
  tls_cert_path: "/etc/hearth/certs/https-node1.crt"
  tls_key_path:  "/etc/hearth/certs/https-node1.key"

security:
  # REQUIRED in production, and IDENTICAL on every node — see Prerequisites §5.
  # Prefer the HEARTH_KEK environment variable to putting it in YAML.
  key_encryption_key: "<64 lowercase hex chars, generated once for the cluster>"

storage:
  data_dir: "/var/lib/hearth/data"

cluster:
  node_id: 1
  peer_address: "10.0.0.1:8421"
  peers:
    - id: 2
      address: "10.0.0.2:8421"
    - id: 3
      address: "10.0.0.3:8421"
  tls_cert_path: "/etc/hearth/certs/node1.crt"
  tls_key_path:  "/etc/hearth/certs/node1.key"
  tls_ca_cert_path: "/etc/hearth/certs/ca.crt"
```

**Node 2 (`hearth-2.yaml`):** Same, but `node_id: 2`, `peer_address: "10.0.0.2:8421"`, `tls_cert_path/key_path` point to node 2's leaf cert.

**Node 3:** Analogous.

> Note the two certificate pairs. `server.tls_cert_path` is the node's **HTTPS**
> identity for client traffic; `cluster.tls_cert_path` is its **peer mTLS**
> identity for Raft. They are unrelated and are not interchangeable.

> Every node must also have `HEARTH_MASTER_KEY` exported in its environment,
> with the same value on all three. It is not a YAML key and `hearth config
> validate` does not check for it.

> All config fields are documented in the [Configuration reference](../specs/CONFIGURATION.md#cluster).

---

### System-realm tokens

`/admin/cluster/*` needs a token for the **system realm** (the nil UUID,
`00000000-0000-0000-0000-000000000000`) that carries `hearth.admin`, sent with that UUID as
`X-Realm-ID`.

**On a running cluster, mint it in the admin console** of any node: sign in at
`/ui/admin/login` with an operator-console account holding `realm.admin`, open **API Tokens**
(`/ui/admin/api-tokens`), pick a lifetime (1 to 60 minutes, default 15) and confirm with your
password and your second factor (see the [realm admin API](./admin-api.md#realms)). The token's
session and its audit record are ordinary writes, proposed through Raft: once they commit, the
token validates on **every** node, and revoking its session on the leader revokes it everywhere
(`tests/cluster_three_node_control_coherence.rs::an_operator_token_minted_on_the_leader_validates_and_revokes_on_both_followers`).
On a follower both the console login and the mint are writes that the follower forwards to the
leader ([H-3](#h-3--writes-to-a-follower-forwarded-to-the-leader-fixed)), so they work there too.
Keep the whole console session on one node, though: the session-cookie secret is per node unless
you configure it (see the per-node state note at the top).

**For a stopped node, use `hearth admin token`.** It mints on the host from a **stopped** node's
data directory, and on a cluster node it is limited:

- **A cluster node's data directory is refused.** The command writes a session and an audit
  record straight into the store, not through Raft, so they would exist on that node only, and
  the audit record would fork the system realm's replicated audit chain there.
- **`--sole-cluster-node` accepts it** for a node that next starts as the cluster's **only**
  member while every other node rejoins empty and copies its store through a snapshot — the
  [divergence recovery](./disaster-recovery.md#raft-divergence-and-split-brain) rebuild.
- **A store restored for a rebuild** holds no `raft.db` yet, so the command accepts it: mint
  into it **before** copying it to every node and the token validates on all of them (the
  [purged-log upgrade](./upgrading.md#upgrading-a-cluster-whose-raft-logs-were-purged), step 4).

Neither source helps a **cold cluster with empty data directories**: it has no operator account
yet, so there is nobody to mint for (see the bootstrap note below).

### Bootstrap Sequence

> **Usually unnecessary.** As of task 26.46 the lowest-ID node in the
> configured membership initialises the cluster itself at start-up — see
> [G-1](#g-1--a-cold-cluster-could-not-be-bootstrapped-fixed). Follow this
> sequence when that node is unavailable, or when you want to form the cluster
> from a different node's membership. On an already-initialised cluster the
> endpoint answers `409`.

Bootstrapping initializes the cluster's initial membership. Do this **once** — running bootstrap on an already-initialized cluster is a no-op (Raft rejects double-initialization).

> **Membership is fixed at bootstrap.** The peers list set here cannot be changed without a full-cluster restart. There is no online membership change API in Hearth 1.x (see C-6 above).

1. Start all nodes: `hearth serve -c hearth-N.yaml`
2. Wait until all nodes are listening (check logs for `"Raft peer gRPC server starting (mTLS)"`).
3. Call the bootstrap endpoint on **one** designated bootstrap node:

> **System-realm token required.** Cluster admin endpoints are gated to the system realm
> (the nil UUID). Your admin token must carry `X-Realm-ID: 00000000-0000-0000-0000-000000000000`.
> See [System-realm tokens](#system-realm-tokens): on a cold cluster with empty data directories
> no operator account exists yet, so there is no token to call this endpoint with — the
> lowest-ID node initialises the cluster itself ([G-1](#g-1--a-cold-cluster-could-not-be-bootstrapped-fixed)).

```bash
curl -s -X POST http://10.0.0.1:8420/admin/cluster/bootstrap \
  -H "Authorization: Bearer <system-admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

**Expected response (`200 OK`):**

```json
{
  "node_id": 1,
  "term": 1,
  "leader_id": 1
}
```

**Error responses:**
- `409 Conflict` — cluster already initialized (safe to ignore on retry)
- `503 Service Unavailable` — server is running in single-node mode (no `cluster:` config)

---

### Write Routing

**Any node accepts writes.** A follower forwards each write to the leader over the peer mTLS
channel and answers once the write is committed and applied on the follower itself
([H-3](#h-3--writes-to-a-follower-forwarded-to-the-leader-fixed)), so a load balancer needs no
leader awareness and a client reads its own write on the node it wrote to. A forwarded write
costs one extra peer round trip; routing writes to the leader avoids it.

Reads from followers may be stale: follower cache invalidation covers only the row types listed
under C-5. For consistent reads, route all traffic to the leader. A write whose forwarded outcome
is unknown (the leader died mid-call) fails rather than being retried — re-read before retrying it.

---

### Quorum and Failure Tolerance

| Cluster size | Fault tolerance |
|:---:|:---:|
| 1 | 0 (single-node mode, no Raft) |
| 3 | 1 node failure |
| 5 | 2 node failures |

A majority (quorum) of nodes must be reachable for writes to succeed.

**If a node fails permanently:** Replace it by restarting all remaining nodes with updated YAML (removing the failed node from the `peers` list). Online membership changes are not supported in Hearth 1.x.

---

### Cluster Status

Needs a system-realm token — see [System-realm tokens](#system-realm-tokens).

```bash
curl -s http://10.0.0.1:8420/admin/cluster/status \
  -H "Authorization: Bearer <system-admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

`role` is one of `"leader"`, `"follower"`, `"candidate"`, `"learner"`, or `"unknown"`. `is_healthy` reflects whether the peer appears in the leader's replication map.

**Alert on `hearth_control_epoch_bumps_owed` staying above 0.** A control — a token or session
revocation, a DPoP key block, a realm status change, a user deletion — is applied on the node that
served it and announced to the others by bumping the replicated control epoch. When a bump cannot
be persisted (for example a leader change between the control's write and its bump, or while Raft
has no leader) the control still binds on the serving node and the admin call still succeeds; the
failed bump is logged at `ERROR`, counted in `hearth_control_epoch_bump_failures_total`, and
recorded as **owed**. What happens next depends on why it failed:

- **The node is still the leader** (a write timeout, a storage fault): a background thread on that
  node retries the owed bump with backoff (100 ms doubling to 5 s) until it succeeds, and every
  other node then reloads.
- **Leadership moved** (the node is now a follower): the retry is forwarded to the new leader like
  any follower write and succeeds there. In addition, **every node that becomes the Raft leader
  bumps the control epoch once**. The control's row was committed before that bump in the new
  leader's log, so every node, the new leader included, reloads and enforces it — which also
  covers a bump owed while **no leader could be reached**: that one is refused as
  `raft: not the leader` and dropped (logged once at `INFO`), and the gauge returns to 0.

`hearth_control_epoch_bumps_owed` is the number of controls still waiting, summed over the
process. **Alert when it stays above 0 for more than a minute**: the node that owes the bump still
believes it is the leader but cannot commit (it lost its quorum, or storage is failing), and until
it succeeds or steps down the other nodes enforce stale controls. Check `/admin/cluster/status` on
that node; if another node has been elected, step the stuck node down or restart it. Any election
— including the one that follows restarting the stuck leader — makes every node reload, and so does
the next control asserted anywhere. The owed count lives in memory: a node that stops while owing
loses the count, and the election that follows covers it. A control-epoch row that does not decode
is repaired by the state machine on the next bump (every node the same way).

---

### Graceful Shutdown

Before shutting down the leader node, step it down so the cluster elects a
replacement while the old leader is still reachable:

```bash
# Step this node down before stopping the process
curl -s -X POST http://10.0.0.1:8420/admin/cluster/transfer-leadership \
  -H "Authorization: Bearer <system-admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
# => {"new_leader_id": 2, "exact_target": false}

# Then stop the process
systemctl stop hearth
```

> **This is a step-down, not a targeted transfer.** openraft 0.9.25 — the
> version Hearth pins — has no API for handing leadership to a *chosen* peer;
> `Trigger::transfer_leader` arrived in 0.10. A request body that names a
> `target_node_id` is therefore **refused with `422`** and nothing changes —
> the server will not step down and then report success for a handover it did
> not perform. Send no body (or `{}`) and read `new_leader_id` to find out
> which voter won the election. Any other field in the body is refused with
> `400`, so a misspelled target (`targetNodeId`, `target`) is never silently
> dropped. `exact_target` is **deprecated** and always `false`; it stays in
> the response for 1.x clients and will be removed in 2.0.

> **It is not instantaneous, and it is not free.** The endpoint works by
> letting the followers' leader leases expire, so the cluster has **no leader**
> for `leader_lease + election_timeout` — 4.5 to 6 seconds under Hearth's Raft
> configuration — and every write during that window fails with
> `NoLeader`/`NotLeader`. Do not call it during a write burst. The call returns
> once a different node has won and this node has accepted that it no longer
> leads, or fails after 20 s.

> **Before task 26.57 this endpoint did not work at all.** On a healthy
> three-node cluster it always answered `leadership transfer timed out after
> 5 s` and leadership never moved: it asked openraft to run an election via
> `trigger().elect()`, which is documented as a no-op on a node that is already
> leader; it never stopped heartbeating, so no follower's lease ever expired;
> and it waited 5 s, below openraft's own 4.5–6 s floor. If you are running a
> build from before that fix, shut the leader down without this call and accept
> the election timeout — the endpoint cannot help you.

---

### Backups

Take backups from a **follower** to avoid adding I/O load to the leader.

See the [Backup and Restore Guide](./backup.md) for the full procedure.

> **Note on followers and stale state (C-5):** Follower cache invalidation is partial (see C-5), so a backup taken from a follower may reflect the storage state correctly but should not be used to audit access-control decisions — the follower may have served stale data for a cached type that is not forwarded.
