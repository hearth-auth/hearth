package hearth

import (
	"fmt"
	"time"
)

// Spec §5 — Hearth SDK error types.
//
// All errors implement the standard error interface and can be matched
// with errors.As / errors.Is.

// ConfigurationError is returned when the client is misconfigured
// (e.g. missing BaseURL or RealmID).
type ConfigurationError struct {
	Field   string
	Message string
}

func (e *ConfigurationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("configuration error (%s): %s", e.Field, e.Message)
	}
	return "configuration error: " + e.Message
}

// DiscoveryError is returned when the OIDC discovery document cannot be
// fetched or parsed.
type DiscoveryError struct {
	URL   string
	Cause error
}

func (e *DiscoveryError) Error() string {
	return fmt.Sprintf("discovery error fetching %s: %v", e.URL, e.Cause)
}

func (e *DiscoveryError) Unwrap() error { return e.Cause }

// JWKSFetchError is returned when the JWKS document cannot be retrieved
// or parsed.
type JWKSFetchError struct {
	URL   string
	Cause error
}

func (e *JWKSFetchError) Error() string {
	return fmt.Sprintf("JWKS fetch error from %s: %v", e.URL, e.Cause)
}

func (e *JWKSFetchError) Unwrap() error { return e.Cause }

// TokenExpiredError is returned when a token's exp claim is in the past.
type TokenExpiredError struct {
	ExpiredAt int64 // Unix timestamp
}

func (e *TokenExpiredError) Error() string {
	return fmt.Sprintf("token expired at unix=%d", e.ExpiredAt)
}

// TokenNotYetValidError is returned when a token's nbf claim is in the future.
type TokenNotYetValidError struct {
	NotBefore int64 // Unix timestamp
}

func (e *TokenNotYetValidError) Error() string {
	return fmt.Sprintf("token not yet valid until unix=%d", e.NotBefore)
}

// TokenInvalidError is returned when a token fails structural or signature
// validation.
type TokenInvalidError struct {
	Reason string
}

func (e *TokenInvalidError) Error() string {
	return "token invalid: " + e.Reason
}

// TokenIssuerError is returned when the token's iss claim does not match
// the expected issuer.
type TokenIssuerError struct {
	Expected string
	Actual   string
}

func (e *TokenIssuerError) Error() string {
	return fmt.Sprintf("token issuer mismatch: expected %q, got %q", e.Expected, e.Actual)
}

// TokenAudienceError is returned when the token's aud claim does not contain
// the expected audience.
type TokenAudienceError struct {
	Expected string
	Actual   []string
}

func (e *TokenAudienceError) Error() string {
	return fmt.Sprintf("token audience mismatch: expected %q, got %v", e.Expected, e.Actual)
}

// IntrospectionError is returned when a token introspection request fails
// or returns an inactive token.
type IntrospectionError struct {
	Message string
	Cause   error
}

func (e *IntrospectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("introspection error: %s: %v", e.Message, e.Cause)
	}
	return "introspection error: " + e.Message
}

func (e *IntrospectionError) Unwrap() error { return e.Cause }

// ModeMismatchError is returned when an introspection response echoes an
// access_token_authorization mode that does not match the SDK's configured
// ExpectedMode. This is always a hard rejection — the middleware never
// silently falls back to a different check strategy.
type ModeMismatchError struct {
	Expected AccessTokenAuthorizationMode
	Actual   string
}

func (e *ModeMismatchError) Error() string {
	return fmt.Sprintf("mode mismatch: expected %q, server echoed %q", e.Expected, e.Actual)
}

// AuthorizationDeniedError is returned by CheckPermission when the decision
// endpoint responds allowed=false.
type AuthorizationDeniedError struct {
	Permission string
}

func (e *AuthorizationDeniedError) Error() string {
	return fmt.Sprintf("authorization denied: permission %q not granted", e.Permission)
}

// SessionVersionRevokedError is returned when a token's sv claim is below
// the minimum accepted session version (RFC HEA-930 § 8).
//
// Resource servers should translate this into an HTTP 401 response.
type SessionVersionRevokedError struct {
	SessionID string
	TokenSV   uint64
	MinSV     uint64
}

func (e *SessionVersionRevokedError) Error() string {
	return fmt.Sprintf(
		"session version revoked: sid=%s, sv=%d < min=%d",
		e.SessionID, e.TokenSV, e.MinSV,
	)
}

// SessionVersionCacheStaleError is returned when the session-version cache
// has not been refreshed within StaleThresholdMs (RFC HEA-930 § 8.1).
//
// When OnStale is "reject", resource servers should return HTTP 401.
// When OnStale is "introspect", fall back to per-request introspection.
type SessionVersionCacheStaleError struct {
	Age     time.Duration
	OnStale string
}

func (e *SessionVersionCacheStaleError) Error() string {
	return fmt.Sprintf("session version cache stale: age=%s, onStale=%s", e.Age, e.OnStale)
}

// RequiredActionError is returned when a token has token_type == "required_action"
// (spec §5, §6). The token is structurally valid but scoped only to completing
// the pending actions — it must NOT be accepted for general API access.
//
// Middleware writes HTTP 401 and surfaces this error instead of a generic
// unauthorized error so callers can redirect the user to the appropriate
// required-action flow.
type RequiredActionError struct {
	// RequiredActions lists the pending action names embedded in the token's
	// required_actions claim (e.g. ["VERIFY_EMAIL", "UPDATE_PASSWORD"]).
	RequiredActions []string
	// RedirectURI is an optional URL to the Hearth interstitial page, when
	// one is provided by the server. May be empty.
	RedirectURI string
}

func (e *RequiredActionError) Error() string {
	return fmt.Sprintf("required action pending: %v", e.RequiredActions)
}
