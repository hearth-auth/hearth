package hearth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// registerAndCapture registers a client against a stub server and returns the
// JSON body the SDK sent.
func registerAndCapture(t *testing.T, req RegisterClientRequest) map[string]any {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"c1","client_name":"app","redirect_uris":[],"grant_types":[]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	if _, err := c.RegisterClient(context.Background(), req, "admin-token"); err != nil {
		t.Fatalf("register client: %v", err)
	}
	return body
}

func TestRegisterClientSendsTrustLevel(t *testing.T) {
	body := registerAndCapture(t, RegisterClientRequest{
		ClientName:   "app",
		RedirectURIs: []string{"http://app.test/cb"},
		TrustLevel:   TrustLevelFirstParty,
	})
	if got := body["trust_level"]; got != "CLIENT_TRUST_LEVEL_FIRST_PARTY" {
		t.Fatalf("trust_level = %v, want CLIENT_TRUST_LEVEL_FIRST_PARTY", got)
	}
}

func TestRegisterClientOmitsUnsetTrustLevel(t *testing.T) {
	body := registerAndCapture(t, RegisterClientRequest{
		ClientName:   "app",
		RedirectURIs: []string{"http://app.test/cb"},
	})
	if _, present := body["trust_level"]; present {
		t.Fatalf("trust_level was sent although unset: %v", body)
	}
}
