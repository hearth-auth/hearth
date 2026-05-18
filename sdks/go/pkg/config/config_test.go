package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hearthauth/hearth-go/pkg/config"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "hearth-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_MissingFile_SingleNodeMode(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "hearth.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsSingleNode() {
		t.Fatal("expected single-node mode when file is absent")
	}
}

func TestLoad_EmptyFile_SingleNodeMode(t *testing.T) {
	path := writeYAML(t, "")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsSingleNode() {
		t.Fatal("expected single-node mode for empty yaml")
	}
}

func TestLoad_ValidCluster(t *testing.T) {
	path := writeYAML(t, `
cluster:
  node_id: "node-1"
  peers:
    - id: "node-2"
      addr: "10.0.1.2:9090"
    - id: "node-3"
      addr: "10.0.1.3:9090"
  election_timeout_min_ms: 150
  election_timeout_max_ms: 300
  heartbeat_interval_ms: 50
  max_log_entries_per_batch: 500
  snapshot_threshold: 10000
  read_lag_threshold_ms: 500
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation error: %v", err)
	}
	if cfg.IsSingleNode() {
		t.Fatal("expected cluster mode")
	}
	if cfg.Cluster.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want node-1", cfg.Cluster.NodeID)
	}
	if len(cfg.Cluster.Peers) != 2 {
		t.Errorf("len(Peers) = %d, want 2", len(cfg.Cluster.Peers))
	}
}

func TestValidate_EmptyNodeID(t *testing.T) {
	cfg := config.HearthConfig{
		Cluster: &config.ClusterConfig{
			NodeID:               "",
			Peers:                []config.PeerConfig{{ID: "node-2", Addr: "10.0.1.2:9090"}},
			ElectionTimeoutMinMs: 150,
			ElectionTimeoutMaxMs: 300,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty node_id")
	}
}

func TestValidate_EmptyPeers(t *testing.T) {
	cfg := config.HearthConfig{
		Cluster: &config.ClusterConfig{
			NodeID:               "node-1",
			Peers:                nil,
			ElectionTimeoutMinMs: 150,
			ElectionTimeoutMaxMs: 300,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty peers")
	}
}

func TestValidate_BadPeerAddr(t *testing.T) {
	cfg := config.HearthConfig{
		Cluster: &config.ClusterConfig{
			NodeID:               "node-1",
			Peers:                []config.PeerConfig{{ID: "node-2", Addr: "not-a-valid::addr"}},
			ElectionTimeoutMinMs: 150,
			ElectionTimeoutMaxMs: 300,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid peer addr")
	}
}

func TestValidate_ElectionTimeoutMinGEMax(t *testing.T) {
	cfg := config.HearthConfig{
		Cluster: &config.ClusterConfig{
			NodeID:               "node-1",
			Peers:                []config.PeerConfig{{ID: "node-2", Addr: "10.0.1.2:9090"}},
			ElectionTimeoutMinMs: 300,
			ElectionTimeoutMaxMs: 150,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when min >= max")
	}
}

func TestValidate_ElectionTimeoutMinEqualsMax(t *testing.T) {
	cfg := config.HearthConfig{
		Cluster: &config.ClusterConfig{
			NodeID:               "node-1",
			Peers:                []config.PeerConfig{{ID: "node-2", Addr: "10.0.1.2:9090"}},
			ElectionTimeoutMinMs: 150,
			ElectionTimeoutMaxMs: 150,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when min == max")
	}
}

func TestValidate_NilCluster_SingleNode(t *testing.T) {
	cfg := config.HearthConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error in single-node mode: %v", err)
	}
}
