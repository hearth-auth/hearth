package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MembershipAction identifies the type of cluster membership change.
type MembershipAction string

const (
	ActionAddLearner  MembershipAction = "add_learner"
	ActionAddVoter    MembershipAction = "add_voter"
	ActionRemoveVoter MembershipAction = "remove_voter"
)

// MembershipRequest is the JSON body for POST /admin/cluster/membership.
type MembershipRequest struct {
	Action MembershipAction `json:"action"`
	NodeID uint64           `json:"node_id"`
	Addr   string           `json:"addr,omitempty"`
}

// MembershipResponse is the JSON body returned on a successful membership change.
type MembershipResponse struct {
	Action     MembershipAction `json:"action"`
	NodeID     uint64           `json:"node_id"`
	Membership struct {
		Voters []uint64 `json:"voters"`
	} `json:"membership"`
}

// ChangeMembership submits a cluster membership change to the Hearth admin API.
//
// Actions:
//   - AddLearner  — add addr as a non-voting replica (addr required)
//   - AddVoter    — add addr as learner then promote to voter
//   - RemoveVoter — remove node_id from the voter set (quorum guard enforced server-side)
func (c *AdminClient) ChangeMembership(req MembershipRequest) (*MembershipResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal membership request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/admin/cluster/membership", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.authorise(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("membership request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("quorum violation: %s", strings.TrimSpace(string(raw)))
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("membership HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out MembershipResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode membership response: %w", err)
	}
	return &out, nil
}
