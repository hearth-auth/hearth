package hearth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// StartWebAuthnRegistration begins a WebAuthn passkey registration ceremony.
//
// Returns PublicKeyCredentialCreationOptions for the browser's
// navigator.credentials.create() call. The caller supplies accessToken —
// the authenticated user's bearer token — so the server can identify who is
// registering the credential.
func (c *Client) StartWebAuthnRegistration(
	ctx context.Context,
	accessToken string,
) (*WebAuthnRegistrationBeginResponse, error) {
	var result WebAuthnRegistrationBeginResponse
	if err := c.postJSON(ctx, "/webauthn/register/begin", accessToken, map[string]any{}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// FinishWebAuthnRegistration completes a WebAuthn passkey registration ceremony.
//
// Send the attestation response from navigator.credentials.create() in req.
// accessToken must be the same session token used in StartWebAuthnRegistration.
func (c *Client) FinishWebAuthnRegistration(
	ctx context.Context,
	accessToken string,
	req WebAuthnRegistrationCompleteRequest,
) (*WebAuthnRegistrationCompleteResponse, error) {
	var result WebAuthnRegistrationCompleteResponse
	if err := c.postJSON(ctx, "/webauthn/register/complete", accessToken, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StartWebAuthnAuthentication begins a WebAuthn passkey authentication ceremony.
//
// userID is optional; pass an empty string for a discoverable-credential /
// resident-key flow. When non-empty, the server constrains allow_credentials
// to that user's registered passkeys.
func (c *Client) StartWebAuthnAuthentication(
	ctx context.Context,
	userID string,
) (*WebAuthnAuthenticationBeginResponse, error) {
	body := map[string]any{}
	if userID != "" {
		body["user_id"] = userID
	}
	var result WebAuthnAuthenticationBeginResponse
	if err := c.postJSON(ctx, "/webauthn/auth/begin", "", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// FinishWebAuthnAuthentication completes a WebAuthn passkey authentication ceremony.
//
// Send the assertion response from navigator.credentials.get() in req.
// Returns a full TokenResponse (access + refresh tokens) on success.
func (c *Client) FinishWebAuthnAuthentication(
	ctx context.Context,
	req WebAuthnAuthenticationCompleteRequest,
) (*TokenResponse, error) {
	var result TokenResponse
	if err := c.postJSON(ctx, "/webauthn/auth/complete", "", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// postJSON sends a JSON-encoded POST request, optionally with a Bearer token.
// When bearer is empty no Authorization header is set.
func (c *Client) postJSON(ctx context.Context, path, bearer string, body, result any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Realm-ID", c.realmID)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	return doRequest(c.http, req, result)
}
