package hearth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// BeginLogin generates a PKCE pair, builds the authorization URL, and returns
// the values the caller must persist before redirecting the browser.
//
// Developer flow:
//  1. Call BeginLogin — get AuthorizationURL, State, CodeVerifier.
//  2. Persist State and CodeVerifier in your session (one line you own).
//  3. Redirect the browser to AuthorizationURL.
//  4. On the callback route, call CompleteLogin(code, codeVerifier, redirectURI).
//
// scopes is the space-delimited scope string; defaults to "openid" when empty.
func (c *Client) BeginLogin(ctx context.Context, redirectURI string, scopes ...string) (BeginLoginResult, error) {
	if c.clientID == "" {
		return BeginLoginResult{}, &ConfigurationError{
			Field:   "client_id",
			Message: "required for BeginLogin",
		}
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		return BeginLoginResult{}, err
	}

	state, err := generateRandomState()
	if err != nil {
		return BeginLoginResult{}, err
	}

	scope := "openid"
	if len(scopes) > 0 && scopes[0] != "" {
		scope = strings.Join(scopes, " ")
	}

	authURL, err := url.Parse(c.baseURL + "/authorize")
	if err != nil {
		return BeginLoginResult{}, fmt.Errorf("invalid base_url: %w", err)
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", pkce.Method)
	authURL.RawQuery = q.Encode()

	return BeginLoginResult{
		AuthorizationURL: authURL.String(),
		State:            state,
		CodeVerifier:     pkce.Verifier,
	}, nil
}

// CompleteLogin exchanges the authorization code from the callback URL for
// tokens. codeVerifier must be the value returned by [Client.BeginLogin].
func (c *Client) CompleteLogin(ctx context.Context, code, codeVerifier, redirectURI string) (*TokenResponse, error) {
	return c.ExchangeCode(ctx, TokenRequest{
		ClientID:     c.clientID,
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
	})
}

// generateRandomState returns 16 bytes of CSPRNG entropy encoded as base64url.
func generateRandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateRandomState: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
