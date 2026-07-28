package hearth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ClientCredentials performs the OAuth 2.0 client credentials grant (RFC 6749 §4.4).
//
// Requires the client to be configured with WithClientCredentials.
// The request is sent as an application/json body: Hearth's token endpoint
// parses the body with an axum `Json` extractor and rejects a form-encoded
// body with HTTP 415. Optional scope may be passed as a single argument.
func (c *Client) ClientCredentials(ctx context.Context, scope ...string) (*TokenResponse, error) {
	if c.clientID == "" {
		return nil, &ConfigurationError{Field: "client_id", Message: "required for client credentials grant"}
	}
	if c.clientSecret == "" {
		return nil, &ConfigurationError{Field: "client_secret", Message: "required for client credentials grant"}
	}

	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_id", c.clientID)
	body.Set("client_secret", c.clientSecret)
	if len(scope) > 0 && scope[0] != "" {
		body.Set("scope", scope[0])
	}

	var result TokenResponse
	if err := c.postTokenRequest(ctx, "/token", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StartDeviceFlow begins an OAuth 2.0 device authorization flow (RFC 8628).
//
// Requires the client to be configured with WithClientCredentials (client_id at minimum).
// Returns the DeviceAuthorizationResponse containing the user code and verification URI.
// Optional scope may be passed as a single argument.
func (c *Client) StartDeviceFlow(ctx context.Context, scope ...string) (*DeviceAuthorizationResponse, error) {
	if c.clientID == "" {
		return nil, &ConfigurationError{Field: "client_id", Message: "required for device authorization flow"}
	}

	body := url.Values{}
	body.Set("client_id", c.clientID)
	if len(scope) > 0 && scope[0] != "" {
		body.Set("scope", scope[0])
	}

	var result DeviceAuthorizationResponse
	if err := c.postTokenRequest(ctx, "/device_authorization", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// deviceOAuthError is the error shape returned by the token endpoint for device flow.
type deviceOAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// PollDeviceToken polls the token endpoint for a device authorization result (RFC 8628 §3.5).
//
// Returns (nil, nil) when the server signals authorization_pending or slow_down —
// the caller should wait and poll again.
// Returns (*TokenResponse, nil) when the user approved the request.
// Returns (nil, *TokenExpiredError) when the device code has expired (expired_token).
// Returns (nil, *APIError) for any other error response.
func (c *Client) PollDeviceToken(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	body := map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode,
		"client_id":   c.clientID,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/token", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Realm-ID", c.realmID)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		var result TokenResponse
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
		return &result, nil
	}

	// 4xx: parse the OAuth error code.
	var oauthErr deviceOAuthError
	_ = json.Unmarshal(raw, &oauthErr)

	switch oauthErr.Error {
	case "authorization_pending", "slow_down":
		// Still waiting — caller should poll again after the interval.
		return nil, nil
	case "expired_token":
		return nil, &TokenExpiredError{}
	default:
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(raw)),
		}
	}
}

// RequestMagicLink sends a magic-link email to the given address (spec §4.5.3).
//
// Per spec and enumeration-resistance requirements, the server always returns
// 202 whether or not the email address is registered.  Any 202 response
// succeeds without surfacing detail.  HTTP 429 raises *APIError.
func (c *Client) RequestMagicLink(ctx context.Context, email string) error {
	path := fmt.Sprintf("/v1/%s/auth/magic-link", c.realmID)
	body, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Realm-ID", c.realmID)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusAccepted {
		return nil
	}

	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(raw)),
	}
}

// ExchangeMagicLink exchanges a magic-link token for tokens (spec §4.5.3 / §7.2 C-12).
//
// Completes the passwordless flow started by RequestMagicLink: posts
// grant_type=urn:hearth:grant-type:magic-link with the opaque token from the
// magic-link URL to the token endpoint. The token is sent in the JSON request
// body, never the URL.
func (c *Client) ExchangeMagicLink(ctx context.Context, token string) (*TokenResponse, error) {
	body := url.Values{}
	body.Set("grant_type", "urn:hearth:grant-type:magic-link")
	body.Set("token", token)
	if c.clientID != "" {
		body.Set("client_id", c.clientID)
	}

	var result TokenResponse
	if err := c.postTokenRequest(ctx, "/token", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// postTokenRequest sends a POST to a Hearth OAuth endpoint and decodes the JSON
// response into result.
//
// Hearth's `/token` and `/device_authorization` endpoints parse their request
// bodies with an axum `Json` extractor: a form-encoded body
// (`application/x-www-form-urlencoded`) is rejected with HTTP 415 before any
// grant dispatch. The values are therefore marshalled into a flat JSON object
// (one value per key) and sent with `Content-Type: application/json`, matching
// [Client.ExchangeCode] and [Client.RefreshTokens].
func (c *Client) postTokenRequest(ctx context.Context, path string, body url.Values, result any) error {
	obj := make(map[string]string, len(body))
	for key := range body {
		obj[key] = body.Get(key)
	}
	jsonBody, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+path,
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Realm-ID", c.realmID)
	return doRequest(c.http, req, result)
}
