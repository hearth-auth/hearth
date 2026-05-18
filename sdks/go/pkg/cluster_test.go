package hearth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestObs() *HearthObservability {
	return NewHearthObservability()
}

func TestClusterHealthHandler_NoState(t *testing.T) {
	obs := newTestObs()
	w := httptest.NewRecorder()
	obs.ClusterHealthHandler()(w, httptest.NewRequest(http.MethodGet, "/cluster/health", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestClusterHealthHandler_Leader_Healthy(t *testing.T) {
	obs := newTestObs()
	obs.UpdateClusterState(ClusterState{
		NodeID:            "node-1",
		Role:              RoleLeader,
		LeaderID:          "node-1",
		AppliedIndex:      100,
		CommitIndex:       100,
		ReplicationLagMs:  map[string]int64{"node-2": 5, "node-3": 8},
		ReadsAllowed:      true,
		SnapshotSizeBytes: 1024,
	})

	w := httptest.NewRecorder()
	obs.ClusterHealthHandler()(w, httptest.NewRequest(http.MethodGet, "/cluster/health", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["role"] != "leader" {
		t.Errorf("expected role=leader, got %v", payload["role"])
	}
	if payload["node_id"] != "node-1" {
		t.Errorf("expected node_id=node-1, got %v", payload["node_id"])
	}
	if payload["reads_allowed"] != true {
		t.Errorf("expected reads_allowed=true, got %v", payload["reads_allowed"])
	}
	lag, ok := payload["replication_lag_ms"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected replication_lag_ms map, got %T", payload["replication_lag_ms"])
	}
	if len(lag) != 2 {
		t.Errorf("expected 2 peers in lag map, got %d", len(lag))
	}
}

func TestClusterHealthHandler_Follower_Unhealthy(t *testing.T) {
	obs := newTestObs()
	obs.UpdateClusterState(ClusterState{
		NodeID:           "node-2",
		Role:             RoleFollower,
		LeaderID:         "node-1",
		AppliedIndex:     80,
		CommitIndex:      100,
		ReplicationLagMs: map[string]int64{"node-1": 500},
		ReadsAllowed:     false, // lag too high
	})

	w := httptest.NewRecorder()
	obs.ClusterHealthHandler()(w, httptest.NewRequest(http.MethodGet, "/cluster/health", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["role"] != "follower" {
		t.Errorf("expected role=follower, got %v", payload["role"])
	}
}

func TestClusterHealthHandler_SingleNode(t *testing.T) {
	obs := newTestObs()
	obs.UpdateClusterState(ClusterState{
		NodeID:       "node-1",
		Role:         RoleSingleNode,
		AppliedIndex: 42,
		CommitIndex:  42,
		ReadsAllowed: true,
	})

	w := httptest.NewRecorder()
	obs.ClusterHealthHandler()(w, httptest.NewRequest(http.MethodGet, "/cluster/health", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for single-node, got %d", w.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["role"] != "single-node" {
		t.Errorf("expected role=single-node, got %v", payload["role"])
	}
	if _, hasLag := payload["replication_lag_ms"]; hasLag {
		t.Error("single-node response should not contain replication_lag_ms")
	}
	if _, hasLeader := payload["leader_id"]; hasLeader {
		t.Error("single-node response should not contain leader_id")
	}
}

func TestClusterMetricsInMetricsText(t *testing.T) {
	obs := newTestObs()
	obs.UpdateClusterState(ClusterState{
		NodeID:            "node-1",
		Role:              RoleLeader,
		LeaderID:          "node-1",
		AppliedIndex:      200,
		CommitIndex:       200,
		ReplicationLagMs:  map[string]int64{"node-2": 12},
		ReadsAllowed:      true,
		SnapshotSizeBytes: 4096,
	})
	obs.RecordElection()
	obs.RecordElection()
	obs.ObserveSnapshotDuration(0.3)

	text := obs.MetricsText()

	checks := []string{
		`hearth_cluster_leader_id{leader_id="node-1"} 1`,
		"hearth_cluster_is_leader 1",
		"hearth_cluster_applied_log_index 200",
		"hearth_cluster_commit_log_index 200",
		`hearth_cluster_replication_lag_ms{peer="node-2"} 12`,
		"hearth_cluster_election_count_total 2",
		"hearth_cluster_reads_allowed 1",
		"hearth_cluster_snapshot_size_bytes 4096",
		"hearth_cluster_snapshot_duration_seconds",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestClusterMetrics_NoStateNoClusterLines(t *testing.T) {
	obs := newTestObs()
	text := obs.MetricsText()
	if strings.Contains(text, "hearth_cluster_") {
		t.Error("cluster metrics should not appear when no state has been set")
	}
}

func TestElectionCounter_Accumulates(t *testing.T) {
	obs := newTestObs()
	obs.UpdateClusterState(ClusterState{NodeID: "n1", Role: RoleLeader, LeaderID: "n1", ReadsAllowed: true})
	obs.RecordElection()
	obs.RecordElection()
	obs.RecordElection()

	text := obs.MetricsText()
	if !strings.Contains(text, "hearth_cluster_election_count_total 3") {
		t.Errorf("expected election count 3 in output, got:\n%s", text)
	}
}
