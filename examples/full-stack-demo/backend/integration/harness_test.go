//go:build integration

// Package integration drives a deliberately *misconfigured* relying party
// against a real Hearth server and asserts that Hearth — not merely the demo's
// Go middleware — refuses the request. See misconfigured_client_test.go for the
// individual negative cases and their vulnerability-class annotations.
//
// # Running
//
//	go test -tags integration ./integration/...
//
// The suite boots the release `hearth` binary in --dev mode (in-memory storage)
// with the full-stack demo's hearth.yaml, bootstraps the system realm, and mints
// real Ed25519-signed tokens over the wire. It requires no browser, no scanner,
// and no external services — every assertion is deterministic.
//
// # Boot path (HEA-2057)
//
// This file provides a minimal, self-contained bootstrap so the negative suite
// can run standalone. It intentionally mirrors examples/full-stack-demo/demo.sh
// (the canonical boot sequence) rather than inventing a second one. When the
// sibling reference-integration-flows harness lands, its shared fixtures should
// replace bootMain() here — the case bodies depend only on the package globals
// documented below, not on how they are populated.
package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Package globals populated once by TestMain. Case bodies read these.
// ---------------------------------------------------------------------------

var (
	// hBase is the base URL of the running Hearth server, e.g. http://127.0.0.1:PORT.
	hBase string
	// hAdmin is the system-realm admin Bearer token from /admin/bootstrap.
	hAdmin string
	// hSys is the system realm UUID (X-Realm-ID for admin calls).
	hSys string
	// hDemo is the "demo" realm UUID resolved from config.
	hDemo string
	// hAccessToken / hIDToken are real Ed25519-signed tokens minted for a
	// SYSTEM-realm principal via a co-realm authorization-code + PKCE exchange.
	// They are genuine, correctly-signed Hearth tokens — used to prove that a
	// validly-signed token is still refused when presented to the WRONG realm /
	// resource (audience + issuer binding), which no forged token could show.
	hAccessToken string
	hIDToken     string
	// hPublicClientID is a public (no-secret) OAuth client registered in the
	// system realm, used to exercise the PKCE-mandatory authorization path.
	hPublicClientID string
	// hCallerUUID is a valid user_id UUID accepted by POST /authorize (the value
	// is overridden by the caller's token `sub` per HEA-1721, but must parse).
	hCallerUUID string
	// hDemoIssuer is the "demo" realm's advertised OIDC issuer.
	hDemoIssuer string

	// skipReason, when non-empty, causes every test to t.Skip — set when the
	// hearth binary or config cannot be located (e.g. a checkout without a build).
	skipReason string
)

// The demo's public OAuth client + redirect, kept in sync with demo.sh /
// hearth.yaml. Used only in documentation assertions; the PKCE path uses a
// freshly-registered system-realm public client so the admin token is co-realm.
const (
	demoClientID    = "f7057d27-61fd-555e-b2af-ba8edd112237"
	demoRedirectURI = "http://localhost:5173/callback"
)

func TestMain(m *testing.M) {
	if err := bootMain(); err != nil {
		// Do not fail the whole package on a missing binary — skip instead so
		// `go test -tags integration ./...` degrades cleanly on a fresh checkout.
		skipReason = err.Error()
	}
	code := m.Run()
	if stopHearth != nil {
		stopHearth()
	}
	os.Exit(code)
}

var stopHearth func()

func bootMain() error {
	bin, err := findHearthBin()
	if err != nil {
		return err
	}
	cfg, err := findDemoConfig()
	if err != nil {
		return err
	}
	port, err := freePort()
	if err != nil {
		return fmt.Errorf("pick free port: %w", err)
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.Command(bin, "serve", "--dev", "--config", cfg,
		"--bind", "127.0.0.1", "--port", fmt.Sprintf("%d", port))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start hearth: %w", err)
	}
	stopHearth = func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }

	if err := waitHealthy(base, 30*time.Second); err != nil {
		stopHearth()
		return err
	}

	// First /admin/bootstrap on a fresh --dev instance returns the admin token
	// and the system realm id (subsequent calls require the Bearer token).
	var bs struct {
		AccessToken string `json:"access_token"`
		RealmID     string `json:"realm_id"`
	}
	if err := postJSON(base, "/admin/bootstrap", "", "", nil, &bs); err != nil {
		stopHearth()
		return fmt.Errorf("bootstrap: %w", err)
	}
	if bs.AccessToken == "" || bs.RealmID == "" {
		stopHearth()
		return fmt.Errorf("bootstrap returned empty token/realm")
	}
	hBase, hAdmin, hSys = base, bs.AccessToken, bs.RealmID

	demo, err := resolveRealm(base, bs.AccessToken, bs.RealmID, "demo")
	if err != nil {
		stopHearth()
		return err
	}
	hDemo = demo

	if err := mintSystemRealmToken(); err != nil {
		stopHearth()
		return err
	}

	// Record the demo realm's advertised issuer for the wrong-iss assertions.
	var disc struct {
		Issuer string `json:"issuer"`
	}
	if err := getJSON(base, "/realms/demo/.well-known/openid-configuration", nil, &disc); err != nil {
		stopHearth()
		return fmt.Errorf("demo discovery: %w", err)
	}
	hDemoIssuer = disc.Issuer
	return nil
}

// mintSystemRealmToken registers a public client in the system realm and runs a
// full authorization-code + PKCE exchange (the same wire flow oidc.rs exercises)
// to obtain genuinely signed access/ID tokens. Co-realm with the admin token, so
// no browser login is required.
func mintSystemRealmToken() error {
	// Derive a parseable user_id UUID from the admin token's `sub` (`user_<uuid>`).
	sub, err := jwtClaimString(hAdmin, "sub")
	if err != nil {
		return fmt.Errorf("read admin sub: %w", err)
	}
	hCallerUUID = strings.TrimPrefix(sub, "user_")

	var reg struct {
		ClientID string `json:"client_id"`
	}
	body := map[string]any{
		"client_name":   "hea2057-neg-public",
		"redirect_uris": []string{"https://app.example.com/cb"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	}
	if err := postJSON(hBase, "/clients", hAdmin, hSys, body, &reg); err != nil {
		return fmt.Errorf("register public client: %w", err)
	}
	hPublicClientID = reg.ClientID

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallengeS256(verifier)

	var az struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	azBody := map[string]any{
		"client_id":             hPublicClientID,
		"redirect_uri":          "https://app.example.com/cb",
		"scope":                 "openid",
		"state":                 "mint-state",
		"response_type":         "code",
		"user_id":               hCallerUUID,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
	if err := postJSON(hBase, "/authorize", hAdmin, hSys, azBody, &az); err != nil {
		return fmt.Errorf("authorize (mint): %w", err)
	}
	if az.Code == "" {
		return fmt.Errorf("authorize (mint) returned no code")
	}

	var tk struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	tkBody := map[string]any{
		"client_id":     hPublicClientID,
		"code":          az.Code,
		"redirect_uri":  "https://app.example.com/cb",
		"code_verifier": verifier,
	}
	if err := postJSON(hBase, "/token", "", hSys, tkBody, &tk); err != nil {
		return fmt.Errorf("token exchange (mint): %w", err)
	}
	if tk.AccessToken == "" || tk.IDToken == "" {
		return fmt.Errorf("token exchange (mint) returned empty tokens")
	}
	hAccessToken, hIDToken = tk.AccessToken, tk.IDToken
	return nil
}

// ---------------------------------------------------------------------------
// Small stdlib-only HTTP + JWT helpers (no third-party deps).
// ---------------------------------------------------------------------------

// requireLive skips the test when the harness could not boot Hearth.
func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skipf("hearth harness unavailable: %s", skipReason)
	}
}

// doRequest issues a request and returns (status, body). headers may be nil.
func doRequest(t *testing.T, method, url string, headers map[string]string, body io.Reader) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// getStatus is a convenience for header-only GET assertions.
func getStatus(t *testing.T, path string, headers map[string]string) (int, []byte) {
	t.Helper()
	return doRequest(t, http.MethodGet, hBase+path, headers, nil)
}

func findHearthBin() (string, error) {
	if b := os.Getenv("HEARTH_BIN"); b != "" {
		if fileExists(b) {
			return b, nil
		}
		return "", fmt.Errorf("HEARTH_BIN=%s not found", b)
	}
	var candidates []string
	if td := os.Getenv("CARGO_TARGET_DIR"); td != "" {
		candidates = append(candidates, filepath.Join(td, "release", "hearth"))
	}
	// Repo root is three levels up from examples/full-stack-demo/backend/integration.
	if wd, err := os.Getwd(); err == nil {
		root := filepath.Clean(filepath.Join(wd, "..", "..", "..", ".."))
		candidates = append(candidates, filepath.Join(root, "target", "release", "hearth"))
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("hearth binary not found (set HEARTH_BIN or build --release); tried %v", candidates)
}

func findDemoConfig() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// integration dir → backend → full-stack-demo/hearth.yaml
	cfg := filepath.Clean(filepath.Join(wd, "..", "..", "hearth.yaml"))
	if !fileExists(cfg) {
		return "", fmt.Errorf("demo hearth.yaml not found at %s", cfg)
	}
	return cfg, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitHealthy(base string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("hearth did not become healthy within %s", timeout)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func resolveRealm(base, token, sysRealm, name string) (string, error) {
	var out struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	headers := map[string]string{"Authorization": "Bearer " + token, "X-Realm-ID": sysRealm}
	if err := getJSON(base, "/admin/realms", headers, &out); err != nil {
		return "", fmt.Errorf("list realms: %w", err)
	}
	for _, r := range out.Items {
		if r.Name == name {
			return r.ID, nil
		}
	}
	return "", fmt.Errorf("realm %q not present in config", name)
}

func getJSON(base, path string, headers map[string]string, out any) error {
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s → %d: %s", path, resp.StatusCode, truncate(b))
	}
	return json.Unmarshal(b, out)
}

func postJSON(base, path, bearer, realm string, body any, out any) error {
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, base+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if realm != "" {
		req.Header.Set("X-Realm-ID", realm)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s → %d: %s", path, resp.StatusCode, truncate(b))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jwtClaimString decodes a compact JWT and returns the named string claim.
func jwtClaimString(token, claim string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a compact JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", err
	}
	v, ok := claims[claim].(string)
	if !ok {
		return "", fmt.Errorf("claim %q absent or non-string", claim)
	}
	return v, nil
}

// jwtClaimAny decodes a compact JWT and returns the named claim as any.
func jwtClaimAny(t *testing.T, token, claim string) any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims[claim]
}

// forgeUnsignedJWT builds a compact token with the given header alg and claims
// and an EMPTY signature segment — i.e. an `alg:none` / unsigned token that a
// correct verifier MUST reject. Hearth is Ed25519-only (CLAUDE.md § Security).
func forgeUnsignedJWT(alg string, claims map[string]any) string {
	header := map[string]any{"alg": alg, "typ": "JWT"}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(c) + "."
}
