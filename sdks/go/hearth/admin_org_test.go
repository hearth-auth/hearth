package hearth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// orgServer answers one expected request and records what it received.
type orgCall struct {
	method, path, query string
	realm, auth         string
	body                map[string]any
}

func orgServer(t *testing.T, status int, reply string, got *orgCall) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.query = r.Method, r.URL.EscapedPath(), r.URL.RawQuery
		got.realm, got.auth = r.Header.Get("X-Realm-ID"), r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &got.body); err != nil {
				t.Errorf("request body is not JSON: %s", raw)
			}
		}
		if reply != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
}

func assertCall(t *testing.T, got orgCall, method, path string) {
	t.Helper()
	if got.method != method || got.path != path {
		t.Errorf("request = %s %s, want %s %s", got.method, got.path, method, path)
	}
	if got.realm != "r1" || got.auth != "Bearer tok" {
		t.Errorf("auth headers: X-Realm-ID=%q Authorization=%q", got.realm, got.auth)
	}
}

const orgJSON = `{"id":"0b6b1d1e-8f3a-4c55-9d0e-3c1b2a4d5e6f","slug":"acme","display_name":"Acme",
"status":"active","member_limit":10,"mfa_required":true,"attributes":{"tier":"gold"},
"created_at":1700000000000000,"updated_at":1700000000000001}`

func assertAcme(t *testing.T, org *Organization) {
	t.Helper()
	if org.Slug != "acme" || org.DisplayName != "Acme" || org.Status != "active" ||
		!org.MfaRequired || org.MemberLimit == nil || *org.MemberLimit != 10 ||
		org.Attributes["tier"] != "gold" || org.CreatedAt != 1700000000000000 ||
		org.Id.String() != "0b6b1d1e-8f3a-4c55-9d0e-3c1b2a4d5e6f" {
		t.Errorf("decoded organization = %+v", *org)
	}
}

func TestAdminListOrganizations(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 200, `{"items":[`+orgJSON+`],"next_cursor":"20"}`, &got)
	defer srv.Close()

	page, err := newTestAdminClient(srv).ListOrganizations(context.Background(),
		ListOptions{Limit: 5, Cursor: "10"})
	if err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "GET", "/admin/organizations")
	if got.query != "cursor=10&limit=5" {
		t.Errorf("query = %q", got.query)
	}
	if len(page.Items) != 1 || page.NextCursor == nil || *page.NextCursor != "20" {
		t.Fatalf("page = %+v", page)
	}
	assertAcme(t, &page.Items[0])
}

func TestAdminCreateOrganization(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 201, orgJSON, &got)
	defer srv.Close()

	mfa := true
	org, err := newTestAdminClient(srv).CreateOrganization(context.Background(),
		CreateOrganizationRequest{Slug: "acme", DisplayName: "Acme", MfaRequired: &mfa})
	if err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "POST", "/admin/organizations")
	if got.body["slug"] != "acme" || got.body["display_name"] != "Acme" || got.body["mfa_required"] != true {
		t.Errorf("body = %v", got.body)
	}
	if _, sent := got.body["member_limit"]; sent {
		t.Errorf("unset member_limit was sent: %v", got.body)
	}
	assertAcme(t, org)
}

func TestAdminGetOrganization(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 200, orgJSON, &got)
	defer srv.Close()

	org, err := newTestAdminClient(srv).GetOrganization(context.Background(), "org 1")
	if err != nil {
		t.Fatal(err)
	}
	// The generated client escapes path parameters.
	assertCall(t, got, "GET", "/admin/organizations/org%201")
	assertAcme(t, org)
}

func TestAdminUpdateOrganization(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 200, orgJSON, &got)
	defer srv.Close()

	name := "Acme Corp"
	status := UpdateOrganizationStatus("suspended")
	_, err := newTestAdminClient(srv).UpdateOrganization(context.Background(), "o1",
		UpdateOrganizationRequest{DisplayName: &name, Status: &status})
	if err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "PATCH", "/admin/organizations/o1")
	if len(got.body) != 2 || got.body["display_name"] != "Acme Corp" || got.body["status"] != "suspended" {
		t.Errorf("body = %v (only the set fields may be sent)", got.body)
	}
}

func TestAdminDeleteOrganization(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 204, "", &got)
	defer srv.Close()

	if err := newTestAdminClient(srv).DeleteOrganization(context.Background(), "o1"); err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "DELETE", "/admin/organizations/o1")
}

func TestAdminListMemberRoles(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 200, `{"items":["billing","support"]}`, &got)
	defer srv.Close()

	roles, err := newTestAdminClient(srv).ListMemberRoles(context.Background(), "o1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "GET", "/admin/organizations/o1/members/u1/roles")
	if len(roles) != 2 || roles[0] != "billing" || roles[1] != "support" {
		t.Errorf("roles = %v", roles)
	}
}

func TestAdminAddMemberRole(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 204, "", &got)
	defer srv.Close()

	if err := newTestAdminClient(srv).AddMemberRole(context.Background(), "o1", "u1", "billing"); err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "POST", "/admin/organizations/o1/members/u1/roles")
	if len(got.body) != 1 || got.body["role_name"] != "billing" {
		t.Errorf("body = %v", got.body)
	}
}

func TestAdminRemoveMemberRole(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 204, "", &got)
	defer srv.Close()

	if err := newTestAdminClient(srv).RemoveMemberRole(context.Background(), "o1", "u1", "billing"); err != nil {
		t.Fatal(err)
	}
	assertCall(t, got, "DELETE", "/admin/organizations/o1/members/u1/roles/billing")
}

func TestAdminAddMemberRoleNotAMemberIsAPIError(t *testing.T) {
	var got orgCall
	srv := orgServer(t, 409, `{"error":"not a member"}`, &got)
	defer srv.Close()

	err := newTestAdminClient(srv).AddMemberRole(context.Background(), "o1", "u1", "billing")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 409 {
		t.Fatalf("err = %v, want *APIError with status 409", err)
	}
}
