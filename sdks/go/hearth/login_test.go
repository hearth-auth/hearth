package hearth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBeginLogin_ReturnsWellFormedAuthorizeURL(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1",
		WithClientCredentials("my-app", "s3cr3t"),
	)

	result, err := client.BeginLogin(context.Background(), "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	parsed, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type: %q", q.Get("response_type"))
	}
	if q.Get("client_id") != "my-app" {
		t.Errorf("client_id: %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Errorf("redirect_uri: %q", q.Get("redirect_uri"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method: %q", q.Get("code_challenge_method"))
	}
	if q.Get("scope") == "" {
		t.Error("scope must not be empty")
	}
}

func TestBeginLogin_CodeChallengeMatchesVerifier(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1",
		WithClientCredentials("my-app", "s3cr3t"),
	)

	result, err := client.BeginLogin(context.Background(), "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	parsed, _ := url.Parse(result.AuthorizationURL)
	challenge := parsed.Query().Get("code_challenge")

	hash := sha256.Sum256([]byte(result.CodeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	if challenge != expected {
		t.Errorf("code_challenge %q does not match SHA256(codeVerifier) %q", challenge, expected)
	}
}

func TestBeginLogin_StateIsNonEmptyAndMatchesURL(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1",
		WithClientCredentials("my-app", ""),
	)

	result, err := client.BeginLogin(context.Background(), "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	if result.State == "" {
		t.Error("State must not be empty")
	}
	parsed, _ := url.Parse(result.AuthorizationURL)
	if parsed.Query().Get("state") != result.State {
		t.Error("state in URL must match returned State")
	}
}

func TestBeginLogin_DefaultsScopeToOpenID(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1",
		WithClientCredentials("my-app", ""),
	)

	result, err := client.BeginLogin(context.Background(), "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	parsed, _ := url.Parse(result.AuthorizationURL)
	if parsed.Query().Get("scope") != "openid" {
		t.Errorf("expected scope=openid, got %q", parsed.Query().Get("scope"))
	}
}

func TestBeginLogin_AcceptsCustomScopes(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1",
		WithClientCredentials("my-app", ""),
	)

	result, err := client.BeginLogin(context.Background(), "https://app.example.com/callback", "openid profile email")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	parsed, _ := url.Parse(result.AuthorizationURL)
	if parsed.Query().Get("scope") != "openid profile email" {
		t.Errorf("scope: %q", parsed.Query().Get("scope"))
	}
}

func TestBeginLogin_RaisesConfigurationErrorWhenNoClientID(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1")
	_, err := client.BeginLogin(context.Background(), "https://app.example.com/callback")
	if err == nil {
		t.Fatal("expected error when client_id is not set")
	}
	if _, ok := err.(*ConfigurationError); !ok {
		t.Fatalf("expected *ConfigurationError, got %T: %v", err, err)
	}
}

func TestCompleteLogin_CallsTokenEndpointWithVerifier(t *testing.T) {
	// Hearth's /token endpoint parses the body with an axum Json extractor and
	// rejects a form-encoded body with HTTP 415, so CompleteLogin must send the
	// authorization-code exchange as application/json. This test pins that wire
	// format: it fails loudly if the request body is not decodable JSON or the
	// Content-Type regresses to application/x-www-form-urlencoded.
	var capturedBody map[string]string
	var capturedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		capturedCT = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Errorf("token request body was not valid JSON (form-encoded regression?): %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "eyJ...",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("my-app", ""),
	)

	resp, err := client.CompleteLogin(context.Background(), "auth-code-xyz", "my-verifier-abc", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if resp.AccessToken != "eyJ..." {
		t.Fatalf("access_token: %q", resp.AccessToken)
	}
	if !strings.Contains(capturedCT, "application/json") {
		t.Fatalf("expected application/json content-type, got %q", capturedCT)
	}
	if capturedBody["code_verifier"] != "my-verifier-abc" {
		t.Errorf("code_verifier missing from request body; got body: %v", capturedBody)
	}
	if !strings.Contains(capturedBody["code"], "auth-code-xyz") {
		t.Errorf("code missing from request body; got body: %v", capturedBody)
	}
}
