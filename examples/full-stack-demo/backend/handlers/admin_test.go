package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hearth-auth/hearth/examples/full-stack-demo/backend/handlers"
	"github.com/hearth-auth/hearth/examples/full-stack-demo/backend/middleware"
)

// buildAdminRouter creates a test router for the admin routes. The fake Hearth
// signs the tokens, and api answers its userinfo and permissions endpoints.
func buildAdminRouter(t *testing.T, api http.Handler) *gin.Engine {
	t.Helper()
	hearthFake.serveAPI(t, api)
	client := hearthFake.client()
	adminH := handlers.NewAdmin(client)

	r := gin.New()
	requireAdmin := middleware.RequireRole(client, "admin")
	admin := r.Group("/admin", testAuthMiddleware, requireAdmin)
	admin.GET("/users", adminH.ListUsers)
	return r
}

// adminAPI answers GET /userinfo and GET /v1/me/permissions with these statuses.
func adminAPI(t *testing.T, userinfoStatus, permissionsStatus int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(userinfoStatus)
			_, _ = w.Write([]byte(`{"sub":"admin-1","email":"admin@test","name":"Admin"}`))
		case "/v1/me/permissions":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(permissionsStatus)
			_, _ = w.Write([]byte(`{"roles":["admin"],"permissions":["content.admin"],"groups":[]}`))
		default:
			t.Errorf("unexpected Hearth API call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestAdminListUsers(t *testing.T) {
	cases := []struct {
		name              string
		token             string
		userinfoStatus    int
		permissionsStatus int
		wantStatus        int
	}{
		{
			name:       "non-admin token forbidden",
			token:      makeToken("viewer-1", []string{"viewer"}, []string{"content.read"}),
			wantStatus: http.StatusForbidden,
		},
		{
			name:              "admin token returns the caller's profile",
			token:             makeToken("admin-1", []string{"admin"}, []string{"content.admin"}),
			userinfoStatus:    http.StatusOK,
			permissionsStatus: http.StatusOK,
			wantStatus:        http.StatusOK,
		},
		{
			name:           "Hearth userinfo error returns 502",
			token:          makeToken("admin-1", []string{"admin"}, []string{"content.admin"}),
			userinfoStatus: http.StatusInternalServerError,
			wantStatus:     http.StatusBadGateway,
		},
		{
			name:              "Hearth permissions error returns 502",
			token:             makeToken("admin-1", []string{"admin"}, []string{"content.admin"}),
			userinfoStatus:    http.StatusOK,
			permissionsStatus: http.StatusInternalServerError,
			wantStatus:        http.StatusBadGateway,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var api http.Handler = adminAPI(t, tc.userinfoStatus, tc.permissionsStatus)
			if tc.userinfoStatus == 0 {
				// A non-admin is refused before the handler calls Hearth.
				api = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("unexpected Hearth API call for a non-admin token: %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
				})
			}
			r := buildAdminRouter(t, api)

			req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("got %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			var users []struct {
				ID          string   `json:"id"`
				Email       string   `json:"email"`
				DisplayName string   `json:"display_name"`
				Roles       []string `json:"roles"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&users); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(users) != 1 {
				t.Fatalf("want 1 user, got %d", len(users))
			}
			u := users[0]
			if u.ID != "admin-1" || u.Email != "admin@test" || u.DisplayName != "Admin" {
				t.Errorf("profile = %+v, want admin-1 / admin@test / Admin", u)
			}
			if len(u.Roles) != 1 || u.Roles[0] != "admin" {
				t.Errorf("roles = %v, want [admin]", u.Roles)
			}
		})
	}
}

func TestAdminUsersRequiresAuth(t *testing.T) {
	r := buildAdminRouter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Hearth should not be called when unauthenticated")
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	// No Authorization header.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}
