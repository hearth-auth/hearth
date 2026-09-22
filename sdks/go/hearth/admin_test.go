package hearth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestAdminClient(srv *httptest.Server) *AdminClient {
	return &AdminClient{
		baseURL:     srv.URL,
		realmID:     "r1",
		accessToken: "tok",
		http:        &http.Client{},
	}
}

// ─── ListUsers cursor ─────────────────────────────────────────────────────────

func TestAdminListUsersWithCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/users" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("cursor"); got != "cursor-abc" {
			t.Errorf("cursor param: %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Errorf("limit param: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		next := "cursor-def"
		_ = json.NewEncoder(w).Encode(PageResponse[User]{
			Items:      []User{{ID: "u1", Email: "a@b.com"}},
			NextCursor: &next,
		})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	page, err := admin.ListUsers(context.Background(), ListOptions{Limit: 5, Cursor: "cursor-abc"})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "u1" {
		t.Fatalf("items: %v", page.Items)
	}
	if page.NextCursor == nil || *page.NextCursor != "cursor-def" {
		t.Errorf("next_cursor: %v", page.NextCursor)
	}
}

func TestAdminListUsersNoCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cursor"); got != "" {
			t.Errorf("cursor should be absent, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PageResponse[User]{Items: []User{}})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	_, err := admin.ListUsers(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
}

// ─── ListRealms ───────────────────────────────────────────────────────────────

func TestAdminListRealms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/realms" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PageResponse[Realm]{
			Items: []Realm{{ID: "realm1", Name: "test-realm"}},
		})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	page, err := admin.ListRealms(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListRealms: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "realm1" {
		t.Fatalf("items: %v", page.Items)
	}
}

// ─── Client CRUD ──────────────────────────────────────────────────────────────

func TestAdminCreateClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/applications" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OAuthClient{ClientID: "cl1", ClientName: "my-app"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	cl, err := admin.CreateClient(context.Background(), CreateClientRequest{
		ClientName:   "my-app",
		RedirectURIs: []string{"https://app.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if cl.ClientID != "cl1" {
		t.Errorf("ClientID = %q", cl.ClientID)
	}
}

func TestAdminGetClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/applications/cl1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OAuthClient{ClientID: "cl1", ClientName: "my-app"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	cl, err := admin.GetClient(context.Background(), "cl1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if cl.ClientID != "cl1" {
		t.Errorf("ClientID = %q", cl.ClientID)
	}
}

// The server mounts the whole client family at /admin/applications*: the
// mutation route is PATCH /admin/applications/{id}. /admin/clients* is not a
// route at all — every call to it 404s (audit 2026-08-28 §25.4, §25.18).
func TestAdminUpdateClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/applications/cl1" || r.Method != "PATCH" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OAuthClient{ClientID: "cl1", ClientName: "updated-app"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	name := "updated-app"
	cl, err := admin.UpdateClient(context.Background(), "cl1", UpdateClientRequest{ClientName: &name})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if cl.ClientName != "updated-app" {
		t.Errorf("ClientName = %q", cl.ClientName)
	}
}

func TestAdminDeleteClient(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/applications/cl1" && r.Method == "DELETE" {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	if err := admin.DeleteClient(context.Background(), "cl1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if !called {
		t.Error("DELETE /admin/applications/cl1 was not called")
	}
}

func TestAdminListClients(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/applications" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PageResponse[OAuthClient]{
			Items: []OAuthClient{{ClientID: "cl1"}},
		})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	page, err := admin.ListClients(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items: %v", page.Items)
	}
}

// ─── Role CRUD ────────────────────────────────────────────────────────────────

func TestAdminCreateRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/roles" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Role{ID: "role1", Name: "editor"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	role, err := admin.CreateRole(context.Background(), CreateRoleRequest{Name: "editor"})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if role.ID != "role1" || role.Name != "editor" {
		t.Errorf("role: %+v", role)
	}
}

func TestAdminGetRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/roles/role1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Role{ID: "role1", Name: "editor"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	role, err := admin.GetRole(context.Background(), "role1")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if role.ID != "role1" {
		t.Errorf("ID = %q", role.ID)
	}
}

func TestAdminUpdateRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/roles/role1" || r.Method != "PATCH" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Role{ID: "role1", Name: "senior-editor"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	name := "senior-editor"
	role, err := admin.UpdateRole(context.Background(), "role1", UpdateRoleRequest{Name: &name})
	if err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if role.Name != "senior-editor" {
		t.Errorf("Name = %q", role.Name)
	}
}

func TestAdminDeleteRole(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/roles/role1" && r.Method == "DELETE" {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	if err := admin.DeleteRole(context.Background(), "role1"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if !called {
		t.Error("DELETE /admin/roles/role1 was not called")
	}
}

func TestAdminListRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/roles" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PageResponse[Role]{
			Items: []Role{{ID: "role1", Name: "editor"}},
		})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	page, err := admin.ListRoles(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Name != "editor" {
		t.Fatalf("items: %v", page.Items)
	}
}

// ─── Group CRUD ───────────────────────────────────────────────────────────────

func TestAdminCreateGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/groups" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Group{ID: "grp1", Name: "engineering"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	grp, err := admin.CreateGroup(context.Background(), CreateGroupRequest{Name: "engineering"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if grp.ID != "grp1" || grp.Name != "engineering" {
		t.Errorf("group: %+v", grp)
	}
}

func TestAdminGetGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/groups/grp1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Group{ID: "grp1", Name: "engineering"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	grp, err := admin.GetGroup(context.Background(), "grp1")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if grp.ID != "grp1" {
		t.Errorf("ID = %q", grp.ID)
	}
}

func TestAdminUpdateGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/groups/grp1" || r.Method != "PATCH" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Group{ID: "grp1", Name: "platform-engineering"})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	name := "platform-engineering"
	grp, err := admin.UpdateGroup(context.Background(), "grp1", UpdateGroupRequest{Name: &name})
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if grp.Name != "platform-engineering" {
		t.Errorf("Name = %q", grp.Name)
	}
}

func TestAdminDeleteGroup(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/groups/grp1" && r.Method == "DELETE" {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	if err := admin.DeleteGroup(context.Background(), "grp1"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if !called {
		t.Error("DELETE /admin/groups/grp1 was not called")
	}
}

func TestAdminListGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/groups" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PageResponse[Group]{
			Items: []Group{{ID: "grp1", Name: "engineering"}},
		})
	}))
	defer srv.Close()

	admin := newTestAdminClient(srv)
	page, err := admin.ListGroups(context.Background(), ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Name != "engineering" {
		t.Fatalf("items: %v", page.Items)
	}
}

// ─── Org Membership CRUD ──────────────────────────────────────────────────────
//
// Removed with the methods. Hearth serves no organization route over HTTP, so
// these tests only ever proved that the SDK could talk to a stub server that
// the real server does not resemble (audit 2026-08-28 §25.19).
