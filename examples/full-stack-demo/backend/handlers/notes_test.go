package handlers_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/hearth/examples/full-stack-demo/backend/handlers"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/store"
	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// makeToken returns a structurally valid (but unsigned) JWT with the given
// roles and permissions embedded in the payload.
// hearth.Client.HasRole / HasPermission decode claims locally without verifying
// the signature, so unsigned tokens are sufficient for RBAC testing.
func makeToken(sub string, roles, perms []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"sub":         sub,
		"roles":       roles,
		"permissions": perms,
	})
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + payloadB64 + ".test_sig"
}

// testAuthMiddleware bypasses JWKS signature verification and injects the raw
// token directly into the context. Used in place of middleware.JWKSValidator.Auth()
// so tests are hermetic and fast.
func testAuthMiddleware(c *gin.Context) {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Set(middleware.KeyRawToken, strings.TrimPrefix(h, "Bearer "))
	c.Next()
}

// buildRouter constructs a Gin engine wired up identically to main.go but with
// the test auth shim instead of JWKS validation.
func buildRouter(t *testing.T) *gin.Engine {
	t.Helper()
	client := hearth.NewClient("http://hearth.test", "demo")
	noteStore := store.NewNotes()
	notesH := handlers.NewNotes(noteStore, client)

	r := gin.New()
	requireEditor := middleware.RequirePermission(client, "content.write")
	requireAdmin := middleware.RequireRole(client, "admin")

	notes := r.Group("/notes", testAuthMiddleware)
	notes.GET("", notesH.List)
	notes.POST("", requireEditor, notesH.Create)
	notes.PATCH("/:id", requireEditor, notesH.Update)
	notes.DELETE("/:id", requireAdmin, notesH.Delete)

	return r
}

func TestNotesRoutes(t *testing.T) {
	viewerToken := makeToken("viewer-1", []string{"viewer"}, []string{"content.read"})
	editorToken := makeToken("editor-1", []string{"editor"}, []string{"content.read", "content.write"})
	adminToken := makeToken("admin-1", []string{"admin"}, []string{"content.read", "content.write", "content.admin"})

	cases := []struct {
		name       string
		method     string
		path       string
		body       string
		token      string
		wantStatus int
	}{
		// Health-like: unauthenticated GET blocked
		{
			name:       "GET /notes requires auth",
			method:     http.MethodGet,
			path:       "/notes",
			token:      "",
			wantStatus: http.StatusUnauthorized,
		},
		// Viewer can list notes
		{
			name:       "GET /notes viewer ok",
			method:     http.MethodGet,
			path:       "/notes",
			token:      viewerToken,
			wantStatus: http.StatusOK,
		},
		// Viewer cannot create notes (missing content.write)
		{
			name:       "POST /notes viewer forbidden",
			method:     http.MethodPost,
			path:       "/notes",
			body:       `{"title":"test"}`,
			token:      viewerToken,
			wantStatus: http.StatusForbidden,
		},
		// Editor can create notes
		{
			name:       "POST /notes editor created",
			method:     http.MethodPost,
			path:       "/notes",
			body:       `{"title":"hello","body":"world"}`,
			token:      editorToken,
			wantStatus: http.StatusCreated,
		},
		// Missing required title field returns 400
		{
			name:       "POST /notes missing title bad request",
			method:     http.MethodPost,
			path:       "/notes",
			body:       `{"body":"no title"}`,
			token:      editorToken,
			wantStatus: http.StatusBadRequest,
		},
		// Editor can update notes
		{
			name:       "PATCH /notes/:id editor ok",
			method:     http.MethodPatch,
			path:       "/notes/note-1",
			body:       `{"title":"updated"}`,
			token:      editorToken,
			wantStatus: http.StatusOK,
		},
		// Viewer cannot update notes
		{
			name:       "PATCH /notes/:id viewer forbidden",
			method:     http.MethodPatch,
			path:       "/notes/note-1",
			body:       `{"title":"updated"}`,
			token:      viewerToken,
			wantStatus: http.StatusForbidden,
		},
		// Non-existent note returns 404 (editor has permission but note is gone)
		{
			name:       "PATCH /notes/missing not found",
			method:     http.MethodPatch,
			path:       "/notes/missing",
			body:       `{"title":"x"}`,
			token:      editorToken,
			wantStatus: http.StatusNotFound,
		},
		// Non-admin cannot delete
		{
			name:       "DELETE /notes/:id editor forbidden",
			method:     http.MethodDelete,
			path:       "/notes/note-1",
			token:      editorToken,
			wantStatus: http.StatusForbidden,
		},
		// Admin can delete
		{
			name:       "DELETE /notes/:id admin ok",
			method:     http.MethodDelete,
			path:       "/notes/note-1",
			token:      adminToken,
			wantStatus: http.StatusNoContent,
		},
		// Deleting non-existent note returns 404
		{
			name:       "DELETE /notes/missing not found",
			method:     http.MethodDelete,
			path:       "/notes/missing",
			token:      adminToken,
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := buildRouter(t)

			// Seed a note so PATCH and DELETE have a target.
			if tc.path == "/notes/note-1" {
				// Ensure a note exists by creating one first.
				createBody := `{"title":"seed","body":"seed"}`
				createReq := httptest.NewRequest(http.MethodPost, "/notes",
					bytes.NewBufferString(createBody))
				createReq.Header.Set("Content-Type", "application/json")
				createReq.Header.Set("Authorization", "Bearer "+editorToken)
				createRec := httptest.NewRecorder()
				r.ServeHTTP(createRec, createReq)
				if createRec.Code != http.StatusCreated {
					t.Fatalf("seed create failed: %d", createRec.Code)
				}
			}

			var bodyReader *bytes.Buffer
			if tc.body != "" {
				bodyReader = bytes.NewBufferString(tc.body)
			} else {
				bodyReader = &bytes.Buffer{}
			}

			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			req.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}

			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("got status %d, want %d (body: %s)",
					rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestNoteCreateSetsAuthorID(t *testing.T) {
	r := buildRouter(t)
	token := makeToken("user-abc", []string{"editor"}, []string{"content.write"})

	req := httptest.NewRequest(http.MethodPost, "/notes",
		bytes.NewBufferString(`{"title":"my note"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var note store.Note
	if err := json.NewDecoder(rec.Body).Decode(&note); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if note.Author != "user-abc" {
		t.Errorf("want author=user-abc, got %q", note.Author)
	}
}
