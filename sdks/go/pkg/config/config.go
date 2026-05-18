// Package config loads and validates hearth.yaml server configuration.
// Absence of the cluster: section puts Hearth in single-node mode without error.
package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// PeerConfig describes a single cluster peer.
type PeerConfig struct {
	ID   string `yaml:"id"`
	Addr string `yaml:"addr"`
}

// ClusterConfig holds Raft cluster settings.
// All duration fields are in milliseconds.
type ClusterConfig struct {
	NodeID                string       `yaml:"node_id"`
	Peers                 []PeerConfig `yaml:"peers"`
	ElectionTimeoutMinMs  int          `yaml:"election_timeout_min_ms"`
	ElectionTimeoutMaxMs  int          `yaml:"election_timeout_max_ms"`
	HeartbeatIntervalMs   int          `yaml:"heartbeat_interval_ms"`
	MaxLogEntriesPerBatch int          `yaml:"max_log_entries_per_batch"`
	SnapshotThreshold     int          `yaml:"snapshot_threshold"`
	ReadLagThresholdMs    int          `yaml:"read_lag_threshold_ms"`
}

// HearthConfig is the top-level hearth.yaml structure.
// Cluster is nil when the cluster: section is absent (single-node mode).
type HearthConfig struct {
	Cluster *ClusterConfig `yaml:"cluster"`
}

// Load reads hearth.yaml from path. If the file does not exist, a zero-value
// HearthConfig (single-node mode) is returned without error.
func Load(path string) (HearthConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return HearthConfig{}, nil
		}
		return HearthConfig{}, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg HearthConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return HearthConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// IsSingleNode reports whether the config is running in single-node mode
// (no cluster section present).
func (cfg HearthConfig) IsSingleNode() bool {
	return cfg.Cluster == nil
}

// Validate checks ClusterConfig for consistency. Returns nil in single-node mode.
// All errors carry descriptive messages; none panic.
func (cfg HearthConfig) Validate() error {
	c := cfg.Cluster
	if c == nil {
		return nil
	}
	if c.NodeID == "" {
		return fmt.Errorf("cluster.node_id must not be empty")
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("cluster.peers must not be empty in cluster mode")
	}
	for i, p := range c.Peers {
		if p.ID == "" {
			return fmt.Errorf("cluster.peers[%d].id must not be empty", i)
		}
		if _, err := net.ResolveTCPAddr("tcp", p.Addr); err != nil {
			return fmt.Errorf("cluster.peers[%d].addr %q is not a valid socket address: %w", i, p.Addr, err)
		}
	}
	if c.ElectionTimeoutMinMs <= 0 {
		return fmt.Errorf("cluster.election_timeout_min_ms must be positive, got %d", c.ElectionTimeoutMinMs)
	}
	if c.ElectionTimeoutMaxMs <= 0 {
		return fmt.Errorf("cluster.election_timeout_max_ms must be positive, got %d", c.ElectionTimeoutMaxMs)
	}
	if c.ElectionTimeoutMinMs >= c.ElectionTimeoutMaxMs {
		return fmt.Errorf(
			"cluster.election_timeout_min_ms (%d) must be less than election_timeout_max_ms (%d)",
			c.ElectionTimeoutMinMs, c.ElectionTimeoutMaxMs,
		)
	}
	return nil
}
