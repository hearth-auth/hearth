package hearth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// These tests pin the admin client to the JSON the server really accepts and
// sends (docs/api/openapi.json, held to the handlers by
// tests/openapi_contract.rs). The bodies below are copied from a live
// `hearth serve --dev`.

const (
	liveRoleID  = "aebc7b0f-c73b-49fb-9913-d0d49ebd1861"
	liveGroupID = "97ad795d-7407-4c43-80bc-f5d4bac22e60"
	liveRealmID = "eb770faa-c521-49c8-be9d-365e97f90332"
	liveUserID  = "67e94d0b-46ee-4e67-aa5e-e6b74a193255"
)

// captureServer answers every request with `reply` and records the last
// request body.
func captureServer(t *testing.T, status int, reply string, body *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 && body != nil {
			*body = map[string]any{}
			if err := json.Unmarshal(raw, body); err != nil {
				t.Errorf("request body is not JSON: %s", raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
}

func TestAdminCreateGroupSendsSlug(t *testing.T) {
	var sent map[string]any
	srv := captureServer(t, http.StatusCreated, `{"id":"`+liveGroupID+`","realm_id":"`+liveRealmID+
		`","name":"g1","slug":"g1","description":null,"created_at":1791060597648381,"updated_at":1791060597648381}`, &sent)
	defer srv.Close()

	grp, err := newTestAdminClient(srv).CreateGroup(context.Background(),
		CreateGroupRequest{Name: "g1", Slug: "g1"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	// The server refuses a group without a slug: 422 "missing field `slug`".
	if sent["slug"] != "g1" || sent["name"] != "g1" {
		t.Errorf("request body = %v, want name and slug", sent)
	}
	if grp.ID != liveGroupID || grp.Slug != "g1" || grp.CreatedAt != 1791060597648381 {
		t.Errorf("group = %+v", grp)
	}
}

func TestAdminCreateRoleSendsPermissions(t *testing.T) {
	var sent map[string]any
	srv := captureServer(t, http.StatusCreated, `{"id":"`+liveRoleID+`","realm_id":"`+liveRealmID+
		`","name":"r1","description":"d","permissions":["user.read"],"parent_roles":[],"scope_kind":"realm",`+
		`"status":"active","yaml_managed":false,"created_at":1791060597644279,"updated_at":1791060597644279}`, &sent)
	defer srv.Close()

	role, err := newTestAdminClient(srv).CreateRole(context.Background(),
		CreateRoleRequest{Name: "r1", Description: "d", Permissions: []string{"user.read"}})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	perms, _ := sent["permissions"].([]any)
	if sent["name"] != "r1" || len(perms) != 1 || perms[0] != "user.read" {
		t.Errorf("request body = %v", sent)
	}
	if role.ID != liveRoleID || role.Description != "d" || len(role.Permissions) != 1 {
		t.Errorf("role = %+v", role)
	}
}

func TestAdminUpdateUserSendsProtoStatus(t *testing.T) {
	var sent map[string]any
	srv := captureServer(t, http.StatusOK, `{"created_at":1791060597179952,"display_name":"Dev Admin",`+
		`"email":"admin@dev.local","id":"`+liveUserID+`","status":"USER_STATUS_ACTIVE","updated_at":1791060597664541}`, &sent)
	defer srv.Close()

	active := "active"
	user, err := newTestAdminClient(srv).UpdateUser(context.Background(), liveUserID,
		UpdateUserRequest{Status: &active})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	// The server refuses `active`: "unknown variant `active`, expected one of
	// `USER_STATUS_UNSPECIFIED`, `USER_STATUS_ACTIVE`, ...".
	if sent["status"] != "USER_STATUS_ACTIVE" {
		t.Errorf("status sent = %v, want USER_STATUS_ACTIVE", sent["status"])
	}
	if user.ID != liveUserID || user.Status != "USER_STATUS_ACTIVE" || user.DisplayName != "Dev Admin" {
		t.Errorf("user = %+v", user)
	}
}

func TestAdminUpdateUserRejectsUnknownStatus(t *testing.T) {
	srv := captureServer(t, http.StatusOK, `{}`, nil)
	defer srv.Close()

	bogus := "sleeping"
	if _, err := newTestAdminClient(srv).UpdateUser(context.Background(), liveUserID,
		UpdateUserRequest{Status: &bogus}); err == nil {
		t.Fatal("UpdateUser accepted an unknown status")
	}
}

func TestAdminCreateClientDecodesServerJSON(t *testing.T) {
	var sent map[string]any
	srv := captureServer(t, http.StatusCreated, `{"client_id":"4a3ece84-801a-40e6-be6e-1e6fad241eed",`+
		`"client_name":"c","created_at":1791060597668535,"grant_types":["authorization_code"],`+
		`"id_token_signed_response_alg":"EdDSA","redirect_uris":["http://localhost/cb"]}`, &sent)
	defer srv.Close()

	cl, err := newTestAdminClient(srv).CreateClient(context.Background(), CreateClientRequest{
		ClientName: "c", RedirectURIs: []string{"http://localhost/cb"}, GrantTypes: []string{"authorization_code"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if sent["client_name"] != "c" {
		t.Errorf("request body = %v", sent)
	}
	if cl.ClientID != "4a3ece84-801a-40e6-be6e-1e6fad241eed" || len(cl.RedirectURIs) != 1 || cl.GrantTypes[0] != "authorization_code" {
		t.Errorf("client = %+v", cl)
	}
}

func TestAdminListGroupsDecodesTotal(t *testing.T) {
	srv := captureServer(t, http.StatusOK, `{"items":[{"id":"`+liveGroupID+`","realm_id":"`+liveRealmID+
		`","name":"g1","slug":"g1","description":"team","created_at":1,"updated_at":2}],"next_cursor":null,"total":1}`, nil)
	defer srv.Close()

	page, err := newTestAdminClient(srv).ListGroups(context.Background(), ListOptions{})
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Description != "team" || page.NextCursor != nil {
		t.Errorf("page = %+v", page)
	}
}
