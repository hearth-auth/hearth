# Cluster Membership Runbook

Procedures for adding, removing, and recovering Hearth cluster nodes without downtime.
All membership changes use openraft's joint-consensus protocol — the cluster continues
serving reads and writes throughout.

---

## Admin API

All operations require an `Authorization: Bearer <admin-token>` header.

```
POST /admin/cluster/membership
Content-Type: application/json

{ "action": "add_learner" | "add_voter" | "remove_voter",
  "node_id": <uint64>,
  "addr":    "<host:port>"   // required for add_learner / add_voter
}
```

**Success (200)**
```json
{
  "action": "add_voter",
  "node_id": 4,
  "membership": { "voters": [1, 2, 3, 4] }
}
```

**Quorum violation (409)**
```json
{ "error": "quorum_violation", "detail": "..." }
```

---

## Add a New Node (safe join procedure)

> Approximate time: 2–5 min depending on snapshot size.

### Step 1 — Start the new node process

Start the Hearth binary on the new host with the same cluster config.
The node will not join any consensus group until the leader is told about it.

```bash
HEARTH_NODE_ID=4 hearth-axum-example
```

### Step 2 — Add as learner (non-voting replica)

Send the request to **any cluster node that is currently the leader**, or let the
proxy retry on redirect.

```bash
curl -s -X POST https://hearth.example.com/admin/cluster/membership \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"add_learner","node_id":4,"addr":"10.0.1.4:9090"}'
```

The server blocks until the learner has replicated the full log (or received a
snapshot).  This may take several seconds on large datasets.

### Step 3 — Promote to voter

Once the learner has caught up, promote it to full voter status:

```bash
curl -s -X POST https://hearth.example.com/admin/cluster/membership \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"add_voter","node_id":4,"addr":"10.0.1.4:9090"}'
```

The response includes the new voter set.  Writes now require a quorum of the
enlarged group.

> **Note:** The `add_voter` action internally performs the learner step first,
> so a single call is sufficient for most operators.  Use the explicit two-step
> flow when you want to inspect replication lag before promoting.

---

## Remove a Node (safe removal procedure)

### Step 1 — Verify quorum will be maintained

A removal is rejected if it would leave the cluster without quorum
(`⌊n/2⌋ + 1` voters, where `n` is the current voter count).

| Current voters | Minimum after | Can remove? |
|:-:|:-:|:-:|
| 5 | 3 | ✓ |
| 4 | 3 | ✓ |
| 3 | 2 | ✓ |
| 2 | 2 | ✗ (1 < 2) |
| 1 | — | ✗ always |

### Step 2 — Drain traffic from the node (optional)

Remove the node from load-balancer rotation so it stops receiving client
requests before it leaves the cluster.

### Step 3 — Remove the voter

```bash
curl -s -X POST https://hearth.example.com/admin/cluster/membership \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"remove_voter","node_id":4}'
```

The cluster uses joint consensus during the transition — writes remain available
throughout.  Confirm the response shows the node absent from `membership.voters`.

### Step 4 — Stop the removed node process

Once the leader confirms removal, stop the process on the decommissioned host.

---

## Emergency Quorum Recovery

Use this procedure only when a majority of nodes are permanently lost and the
cluster cannot elect a leader.

> **Warning:** This is a destructive, data-loss-risk operation.  Take a snapshot
> backup of each surviving node's state directory before proceeding.

1. **Identify surviving nodes.**  Pick the node with the highest `last_applied`
   log index (from metrics or logs).

2. **Stop all Hearth processes.**

3. **Reset membership on the surviving node** by setting the initial cluster
   membership to a single node in `hearth.yaml`:

   ```yaml
   cluster:
     node_id: 1
     peers: []   # empty — single-node bootstrap
   ```

4. **Restart the surviving node.**  It will self-elect as leader.

5. **Re-add remaining nodes** using the standard add-voter procedure above.

6. **Validate** by writing a canary key and reading it back from all nodes.

---

## Using the Go SDK

```go
client := backup.NewAdminClient("https://hearth.example.com", os.Getenv("ADMIN_TOKEN"))

// Add as learner then promote
resp, err := client.ChangeMembership(backup.MembershipRequest{
    Action: backup.ActionAddVoter,
    NodeID: 4,
    Addr:   "10.0.1.4:9090",
})
if err != nil {
    log.Fatalf("membership change failed: %v", err)
}
log.Printf("new voter set: %v", resp.Membership.Voters)
```
