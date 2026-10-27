package hearth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Client is a Go client for the Hearth identity API.
type Client struct {
	baseURL string
	realmID string
	http    *http.Client
	svCache *SessionVersionCache

	// optional client credentials for client_credentials and device_flow grants.
	clientID     string
	clientSecret string

	// audience is the aud VerifyToken expects (RFC 9068 §4). Defaults to
	// DefaultAudience; WithAudience sets an API's resource URI.
	audience string

	// jwksTTL overrides the default JWKS cache TTL.
	jwksTTL time.Duration

	// jwksURLOverride lets tests point the JWKS fetch at a different server.
	jwksURLOverride string

	// now is the clock VerifyToken checks exp/nbf/iat against. nil means
	// time.Now; tests set it to pin the clock.
	now func() time.Time

	// Lazy-initialised JWKS cache and discovery document.
	jwksMu    sync.Mutex
	jwksCache *JwksCache

	discMu  sync.Mutex
	discDoc *oidcDiscovery
}

// oidcDiscovery holds the fields we need from the OIDC discovery document.
type oidcDiscovery struct {
	Issuer                      string `json:"issuer"`
	JwksURI                     string `json:"jwks_uri"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	IntrospectionEndpoint       string `json:"introspection_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
}

// DefaultHTTPTimeout bounds every outbound HTTP call of a client built by
// NewClient, unless WithHTTPTimeout sets another bound.
const DefaultHTTPTimeout = 10 * time.Second

// ClientOption is a functional option for NewClient.
type ClientOption func(*Client)

// WithClientCredentials configures client_id and client_secret for M2M flows.
//
// Required for ClientCredentials and StartDeviceFlow.
func WithClientCredentials(clientID, clientSecret string) ClientOption {
	return func(c *Client) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// DefaultAudience is the audience Hearth mints in an access token when the
// client names no resource. VerifyToken checks aud against it unless the
// client is configured with WithAudience.
const DefaultAudience = "hearth"

// WithAudience sets the aud VerifyToken expects: the name of the API that
// verifies the token (RFC 9068 §4). An API registered as a protected resource
// sets its resource URI. The audience check is always on; an empty value keeps
// DefaultAudience.
func WithAudience(audience string) ClientOption {
	return func(c *Client) {
		if audience != "" {
			c.audience = audience
		}
	}
}

// WithHTTPTimeout sets the time limit for each outbound HTTP call, including
// discovery, JWKS and session-version fetches. A zero or negative value keeps
// DefaultHTTPTimeout: the limit cannot be turned off.
func WithHTTPTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		if timeout > 0 {
			c.http.Timeout = timeout
		}
	}
}

// WithJWKSTTL overrides the default JWKS cache TTL.
func WithJWKSTTL(ttl time.Duration) ClientOption {
	return func(c *Client) {
		c.jwksTTL = ttl
	}
}

// WithSessionVersions attaches a session-version cache to the client.
//
// The cache immediately starts a background goroutine that fetches a
// snapshot and polls the delta feed at cfg.PollIntervalMs intervals.
// Call client.Stop() when the client is no longer needed to release the
// goroutine.
//
// If cfg.StaleThresholdMs <= cfg.PollIntervalMs a warning is printed to
// stderr.
func WithSessionVersions(cfg SessionVersionConfig) ClientOption {
	return func(c *Client) {
		cache := newSessionVersionCache(c.baseURL, c.realmID, cfg, c.http)
		cache.Start()
		c.svCache = cache
	}
}

// setRealmHeader sends X-Realm-ID only when the client's realm is a UUID and
// the request goes to a global endpoint. A realm endpoint
// (/realms/{realm}/...) names the realm in its path, and the server refuses a
// header that does not resolve to that realm (400 realm_mismatch). A realm
// NAME is never a valid value.
func (c *Client) setRealmHeader(req *http.Request) {
	if strings.Contains(req.URL.Path, "/realms/") {
		return
	}
	if _, err := uuid.Parse(c.realmID); err == nil {
		req.Header.Set("X-Realm-ID", c.realmID)
	}
}

// NewClient creates a new Hearth client.
//
// Every outbound HTTP call is bounded by DefaultHTTPTimeout; WithHTTPTimeout
// sets another bound. Optional ClientOption values (e.g. WithSessionVersions)
// may be provided and are applied in order after the client struct is
// initialised.
func NewClient(baseURL, realmID string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:  baseURL,
		realmID:  realmID,
		http:     &http.Client{Timeout: DefaultHTTPTimeout},
		audience: DefaultAudience,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Stop releases background resources held by the client (e.g. the
// session-version poll goroutine). It is safe to call even when no
// options were configured.
func (c *Client) Stop() {
	if c.svCache != nil {
		c.svCache.Stop()
	}
}

// SessionVersionCacheAge returns the time elapsed since the session-version
// cache was last successfully refreshed.
//
// Returns a very large duration (10 years) when session-version tracking is
// not configured or the cache has never been seeded. Use this in health-check
// handlers to confirm the cache is fresh.
func (c *Client) SessionVersionCacheAge() time.Duration {
	if c.svCache == nil {
		return 24 * time.Hour * 365 * 10
	}
	return c.svCache.Age()
}

// Bootstrap calls POST /admin/bootstrap in dev mode.
// It creates a realm, admin user, session, and admin role assignment.
func Bootstrap(ctx context.Context, baseURL string) (*BootstrapResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/admin/bootstrap", nil)
	if err != nil {
		return nil, err
	}
	var result BootstrapResponse
	if err := doRequest(&http.Client{}, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RegisterClient registers a new OAuth 2.0 client.
//
// Registration is an admin operation: the server answers
// `401 missing authorization header` without a bearer token. Pass one as the
// optional third argument — variadic so that existing callers still compile,
// matching how StartDeviceFlow takes its optional scope.
func (c *Client) RegisterClient(
	ctx context.Context,
	req RegisterClientRequest,
	accessToken ...string,
) (*OAuthClient, error) {
	token := ""
	if len(accessToken) > 0 {
		token = accessToken[0]
	}
	var result OAuthClient
	if err := c.postWithToken(ctx, "/clients", req, &result, token); err != nil {
		return nil, err
	}
	return &result, nil
}

// Authorize initiates an authorization code flow.
//
// A bearer token is required whenever UserID selects the subject directly
// instead of the caller holding a session: that is an administrative act and
// the server answers `401 invalid_token` without one. Variadic so existing
// callers still compile.
func (c *Client) Authorize(
	ctx context.Context,
	req AuthorizeRequest,
	accessToken ...string,
) (*AuthorizeResponse, error) {
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}
	token := ""
	if len(accessToken) > 0 {
		token = accessToken[0]
	}
	var result AuthorizeResponse
	if err := c.postWithToken(ctx, "/authorize", req, &result, token); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExchangeCode exchanges an authorization code for tokens: a form-encoded POST
// to the discovered token endpoint.
func (c *Client) ExchangeCode(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	var result TokenResponse
	if err := c.postTokenRequest(ctx, endpointToken, req.form(), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RefreshTokens exchanges a refresh token for new tokens at the discovered
// token endpoint.
func (c *Client) RefreshTokens(ctx context.Context, clientID, refreshToken string) (*TokenResponse, error) {
	req := TokenRequest{
		ClientID:     clientID,
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	}
	var result TokenResponse
	if err := c.postTokenRequest(ctx, endpointToken, req.form(), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// form encodes the request as token-endpoint form fields, leaving out the
// empty ones.
func (r TokenRequest) form() url.Values {
	v := url.Values{}
	for key, value := range map[string]string{
		"client_id":     r.ClientID,
		"grant_type":    r.GrantType,
		"code":          r.Code,
		"redirect_uri":  r.RedirectURI,
		"refresh_token": r.RefreshToken,
		"code_verifier": r.CodeVerifier,
	} {
		if value != "" {
			v.Set(key, value)
		}
	}
	return v
}

// rbacClaims mirrors the RBAC-relevant subset of Hearth TokenClaims.
// Only fields required by HasPermission/HasRole/InGroup/InOrg, the
// session-version check, and the required-action guard are decoded;
// everything else is ignored.
type rbacClaims struct {
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	Groups      []string `json:"groups"`
	OID         string   `json:"oid"`
	// SV is the session version claim (u64). Pointer so absence is detectable.
	SV              *uint64  `json:"sv"`
	Sid             string   `json:"sid"`
	TokenType       string   `json:"token_type"`
	RequiredActions []string `json:"required_actions"`
}

// decodeClaims returns the parsed RBAC claim set from a JWT's middle
// segment. The signature is NOT verified.
//
// This is an internal helper and MUST NOT be used to make an authorization
// decision on a token the process did not mint itself. Every authorization
// gate in this package goes through verifiedClaims instead. Returns nil when
// the token is absent, malformed, or the claim segment fails to decode/parse.
func decodeClaims(token string) *rbacClaims {
	if token == "" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers produce padded base64url; try the padded variant.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims rbacClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return &claims
}

func contains(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}

// verifiedClaims verifies token end-to-end via VerifyToken — EdDSA signature
// against the issuer's JWKS, plus exp, nbf, iat, iss and aud — and only then returns
// the RBAC subset of the (now authenticated) payload.
//
// Returns nil when verification fails for any reason, so every caller is
// fail-closed. The JWKS is cached, so the common case is CPU-only.
func (c *Client) verifiedClaims(ctx context.Context, token string) *rbacClaims {
	if _, err := c.VerifyToken(ctx, token); err != nil {
		return nil
	}
	return decodeClaims(token)
}

// HasPermission returns true iff the token verifies against the realm's JWKS
// and its `permissions` claim contains the given permission.
//
// The signature, exp, nbf and iss are all checked before any claim is read;
// an unverifiable, expired or foreign token returns false. The first call
// populates the JWKS cache (one HTTP round trip); subsequent calls are local.
func (c *Client) HasPermission(ctx context.Context, token, permission string) bool {
	claims := c.verifiedClaims(ctx, token)
	return claims != nil && contains(claims.Permissions, permission)
}

// HasRole returns true iff the token verifies and its `roles` claim contains
// the given role. See HasPermission for the verification performed.
func (c *Client) HasRole(ctx context.Context, token, role string) bool {
	claims := c.verifiedClaims(ctx, token)
	return claims != nil && contains(claims.Roles, role)
}

// InGroup returns true iff the token verifies and its `groups` claim contains
// the given group slug. See HasPermission for the verification performed.
func (c *Client) InGroup(ctx context.Context, token, groupSlug string) bool {
	claims := c.verifiedClaims(ctx, token)
	return claims != nil && contains(claims.Groups, groupSlug)
}

// InOrg returns true iff the token verifies and its `oid` claim equals the
// given org ID. See HasPermission for the verification performed.
func (c *Client) InOrg(ctx context.Context, token, orgID string) bool {
	claims := c.verifiedClaims(ctx, token)
	return claims != nil && claims.OID == orgID && orgID != ""
}

// Permissions fetches the freshly-resolved permission set via
// GET /v1/me/permissions. Returns the claim set as the server resolves
// it right now — not the possibly-stale set baked into the JWT.
func (c *Client) Permissions(ctx context.Context, token string) (*MePermissionsResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/me/permissions", nil)
	if err != nil {
		return nil, err
	}
	c.setRealmHeader(httpReq)
	httpReq.Header.Set("Authorization", "Bearer "+token)

	var result MePermissionsResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UserInfo retrieves user claims from the discovered userinfo endpoint using
// an access token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	endpoint, err := c.discoveredEndpoint(ctx, endpointUserinfo)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	c.setRealmHeader(httpReq)
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	var result UserInfoResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Introspect posts to the discovered introspection endpoint (RFC 7662) to
// validate a token and retrieve live RBAC claims. Requires the credentials of
// a CONFIDENTIAL resource-server client: Hearth refuses a public client with
// 401 invalid_client, so a missing ClientSecret is rejected here with a
// *ConfigurationError before any request.
//
// For ModeIntrospection middleware, prefer using RequirePermission which checks
// the echoed mode for you. Call Introspect directly when you need the full
// claim set.
func (c *Client) Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error) {
	if req.ClientID == "" || req.ClientSecret == "" {
		return nil, &ConfigurationError{
			Field:   "ClientSecret",
			Message: "introspection requires a confidential client's ClientID and ClientSecret",
		}
	}
	endpoint, err := c.discoveredEndpoint(ctx, endpointIntrospection)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{
		"token":           req.Token,
		"token_type_hint": req.TokenTypeHint,
		"client_id":       req.ClientID,
		"client_secret":   req.ClientSecret,
	})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setRealmHeader(httpReq)

	var result IntrospectResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		return nil, &IntrospectionError{Message: "request failed", Cause: err}
	}
	return &result, nil
}

// CheckPermission calls POST /oauth/authorize (the decision endpoint, HEA-922)
// to determine whether the token holder has a specific permission.
//
// The token is sent as a Bearer credential; the server resolves live RBAC.
// This is the network call underlying ModeDecision middleware. Fail-closed:
// any error (network, 4xx, 5xx) returns false.
func (c *Client) CheckPermission(ctx context.Context, token string, req CheckPermissionRequest) (*CheckPermissionResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/oauth/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setRealmHeader(httpReq)
	httpReq.Header.Set("Authorization", "Bearer "+token)

	var result CheckPermissionResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		// Fail-closed per spec: network errors deny.
		return &CheckPermissionResponse{Allowed: false}, nil
	}
	return &result, nil
}

// Admin creates an AdminClient using the given access token.
func (c *Client) Admin(accessToken string) *AdminClient {
	return &AdminClient{
		baseURL:     c.baseURL,
		realmID:     c.realmID,
		accessToken: accessToken,
		http:        c.http,
	}
}

// postWithToken posts a JSON body to path under the base URL, with an optional
// bearer token.
//
// The token is passed per call rather than attached to every request, because
// the OAuth endpoints (/token, /authorize) authenticate the *client*, and an
// unexpected Authorization header there changes how the server reads the
// request. Only the admin-authenticated routes pass one.
func (c *Client) postWithToken(ctx context.Context, path string, body, result any, token string) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setRealmHeader(httpReq)
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	return doRequest(c.http, httpReq, result)
}

func doRequest(client *http.Client, req *http.Request, result any) error {
	resp, err := client.Do(req)
	return decodeResponse(resp, err, result)
}

// decodeResponse maps an HTTP response onto the SDK error taxonomy (any
// status >= 400 is an *APIError) and decodes a JSON body into result.
// It closes the body.
func decodeResponse(resp *http.Response, err error, result any) error {
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}
	}

	if result != nil {
		return json.Unmarshal(body, result)
	}
	return nil
}
