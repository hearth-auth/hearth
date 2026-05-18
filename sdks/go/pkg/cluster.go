package hearth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ClusterRole describes the node's Raft role.
type ClusterRole string

const (
	RoleLeader     ClusterRole = "leader"
	RoleFollower   ClusterRole = "follower"
	RoleCandidate  ClusterRole = "candidate"
	RoleSingleNode ClusterRole = "single-node"
)

// ClusterState is a point-in-time snapshot fed into metrics and /cluster/health.
type ClusterState struct {
	NodeID            string
	Role              ClusterRole
	LeaderID          string
	AppliedIndex      uint64
	CommitIndex       uint64
	ReplicationLagMs  map[string]int64 // peer node-id -> milliseconds
	ReadsAllowed      bool
	SnapshotSizeBytes int64
}

var defaultSnapshotBuckets = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

type clusterMetrics struct {
	state         *ClusterState
	electionCount float64
	snapDuration  *histogram
}

func newClusterMetrics() *clusterMetrics {
	return &clusterMetrics{snapDuration: newHistogram(defaultSnapshotBuckets)}
}

// UpdateClusterState replaces the cluster snapshot used for metrics and /cluster/health.
func (o *HearthObservability) UpdateClusterState(state ClusterState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	copied := state
	if state.ReplicationLagMs != nil {
		copied.ReplicationLagMs = make(map[string]int64, len(state.ReplicationLagMs))
		for k, v := range state.ReplicationLagMs {
			copied.ReplicationLagMs[k] = v
		}
	}
	o.cluster.state = &copied
}

// RecordElection increments the cluster election counter.
func (o *HearthObservability) RecordElection() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cluster.electionCount++
}

// ObserveSnapshotDuration records a snapshot operation duration in seconds.
func (o *HearthObservability) ObserveSnapshotDuration(seconds float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cluster.snapDuration.observe(seconds, map[string]string{})
}

// ClusterHealthHandler returns an HTTP handler for GET /cluster/health.
// Returns 200 when healthy (reads_allowed=true or single-node), 503 otherwise.
func (o *HearthObservability) ClusterHealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		o.mu.Lock()
		state := o.cluster.state
		o.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		if state == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "cluster state not available"})
			return
		}

		payload := map[string]interface{}{
			"node_id":       state.NodeID,
			"role":          string(state.Role),
			"applied_index": state.AppliedIndex,
			"commit_index":  state.CommitIndex,
			"reads_allowed": state.ReadsAllowed,
		}

		if state.Role != RoleSingleNode {
			payload["leader_id"] = state.LeaderID
			lagMs := state.ReplicationLagMs
			if lagMs == nil {
				lagMs = map[string]int64{}
			}
			payload["replication_lag_ms"] = lagMs
		}

		if state.ReadsAllowed || state.Role == RoleSingleNode {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(payload)
	}
}

// renderClusterMetrics appends Prometheus lines for cluster state.
// Must be called with o.mu held.
func (o *HearthObservability) renderClusterMetrics(lines *[]string) {
	st := o.cluster.state
	if st == nil {
		return
	}

	*lines = append(*lines,
		"# HELP hearth_cluster_leader_id Current cluster leader node (value is 1 for the active leader label)",
		"# TYPE hearth_cluster_leader_id gauge",
		fmt.Sprintf(`hearth_cluster_leader_id{leader_id="%s"} 1`, escapeLabelValue(st.LeaderID)),
	)

	isLeader := 0.0
	if st.Role == RoleLeader {
		isLeader = 1.0
	}
	*lines = append(*lines,
		"# HELP hearth_cluster_is_leader 1 if this node is the current cluster leader, 0 otherwise",
		"# TYPE hearth_cluster_is_leader gauge",
		fmt.Sprintf("hearth_cluster_is_leader %g", isLeader),
	)

	*lines = append(*lines,
		"# HELP hearth_cluster_applied_log_index Last applied Raft log index on this node",
		"# TYPE hearth_cluster_applied_log_index gauge",
		fmt.Sprintf("hearth_cluster_applied_log_index %d", st.AppliedIndex),
	)

	*lines = append(*lines,
		"# HELP hearth_cluster_commit_log_index Last committed Raft log index on this node",
		"# TYPE hearth_cluster_commit_log_index gauge",
		fmt.Sprintf("hearth_cluster_commit_log_index %d", st.CommitIndex),
	)

	*lines = append(*lines,
		"# HELP hearth_cluster_replication_lag_ms Replication lag to each peer in milliseconds",
		"# TYPE hearth_cluster_replication_lag_ms gauge",
	)
	for peer, lagMs := range st.ReplicationLagMs {
		*lines = append(*lines, fmt.Sprintf(`hearth_cluster_replication_lag_ms{peer="%s"} %d`, escapeLabelValue(peer), lagMs))
	}

	*lines = append(*lines,
		"# HELP hearth_cluster_election_count_total Total leader elections observed by this node",
		"# TYPE hearth_cluster_election_count_total counter",
		fmt.Sprintf("hearth_cluster_election_count_total %g", o.cluster.electionCount),
	)

	readsAllowed := 0.0
	if st.ReadsAllowed {
		readsAllowed = 1.0
	}
	*lines = append(*lines,
		"# HELP hearth_cluster_reads_allowed 1 if this node allows follower reads, 0 otherwise",
		"# TYPE hearth_cluster_reads_allowed gauge",
		fmt.Sprintf("hearth_cluster_reads_allowed %g", readsAllowed),
	)

	*lines = append(*lines,
		"# HELP hearth_cluster_snapshot_size_bytes Size of the most recent snapshot in bytes",
		"# TYPE hearth_cluster_snapshot_size_bytes gauge",
		fmt.Sprintf("hearth_cluster_snapshot_size_bytes %d", st.SnapshotSizeBytes),
	)

	*lines = append(*lines,
		"# HELP hearth_cluster_snapshot_duration_seconds Duration of snapshot operations in seconds",
		"# TYPE hearth_cluster_snapshot_duration_seconds histogram",
	)
	o.cluster.snapDuration.render("hearth_cluster_snapshot_duration_seconds", lines)
}
