package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anthropics/hearth/examples/full-stack-demo/backend/handlers"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

// buildAdminRouter creates a test router with a mock Hearth server for admin tests.
// hearthHandler is served by a httptest.Server that stands in for Hearth's admin API.
func buildAdminRouter(t *testing.T, hearthHandler http.Handler) (*gin.Engine, func()) {
	t.Helper()

	srv := httptest.NewServer(hearthHandler)

	client := hearth.NewClient(srv.URL, "demo")
	adminH := handlers.NewAdmin(client)

	r := gin.New()
	requireAdmin := middleware.RequireRole(client, "admin")

	admin := r.Group("/admin", testAuthMiddleware, requireAdmin)
	admin.GET("/users", adminH.ListUsers)

	return r, srv.Close
}

func TestAdminListUsers(t *testing.T) {
	cases := []struct {
		name         string
		token        string
		hearthStatus int
		hearthBody   string
		wantStatus   int
	}{
		{
			name:       "non-admin token forbidden",
			token:      makeToken("viewer-1", []string{"viewer"}, []string{"content.read"}),
			wantStatus: http.StatusForbidden,
		},
		{
			name:         "admin token proxies Hearth response",
			token:        makeToken("admin-1", []string{"admin"}, []string{"content.admin"}),
			hearthStatus: http.StatusOK,
			hearthBody:   `{"items":[{"id":"u1","email":"user@test","display_name":"User","status":"active"}],"next_cursor":null}`,
			wantStatus:   http.StatusOK,
		},
		{
			name:         "Hearth API error returns 502",
			token:        makeToken("admin-1", []string{"admin"}, []string{"content.admin"}),
			hearthStatus: http.StatusInternalServerError,
			hearthBody:   `{"error":"internal"}`,
			wantStatus:   http.StatusBadGateway,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hearthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.hearthStatus == 0 {
					// Non-admin case: Hearth should never be reached.
					t.Errorf("unexpected Hearth API call for non-admin token")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.hearthStatus)
				_, _ = w.Write([]byte(tc.hearthBody))
			})

			r, cleanup := buildAdminRouter(t, hearthHandler)
			defer cleanup()

			req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("got %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			// For the success case, verify the JSON structure is passed through.
			if tc.wantStatus == http.StatusOK {
				var page hearth.PageResponse[hearth.User]
				if err := json.NewDecoder(rec.Body).Decode(&page); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if len(page.Items) != 1 {
					t.Errorf("want 1 user, got %d", len(page.Items))
				}
				if page.Items[0].Email != "user@test" {
					t.Errorf("want email=user@test, got %q", page.Items[0].Email)
				}
			}
		})
	}
}

func TestAdminUsersRequiresAuth(t *testing.T) {
	r, cleanup := buildAdminRouter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Hearth should not be called when unauthenticated")
	}))
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	// No Authorization header.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}
