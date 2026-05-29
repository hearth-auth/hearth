package hearth

import (
	"net/http"
)

// MiddlewareConfig configures a RequirePermission middleware factory.
type MiddlewareConfig struct {
	// ExpectedMode is required. Controls how the middleware evaluates permissions.
	//   ModeEmbedded      — decodes JWT locally; no network call.
	//   ModeIntrospection — calls POST /introspect; requires ClientID + ClientSecret.
	//   ModeDecision      — calls POST /oauth/authorize; fail-closed on network errors.
	//
	// The middleware never silently falls back from one mode to another regardless
	// of what claims are present in the token.
	ExpectedMode AccessTokenAuthorizationMode

	// ClientID and ClientSecret are required when ExpectedMode is ModeIntrospection.
	ClientID     string
	ClientSecret string

	// TokenExtractor extracts the bearer token from an incoming request.
	// Defaults to extracting from the Authorization: Bearer <token> header.
	TokenExtractor func(r *http.Request) string

	// OnDenied is called when the middleware rejects a request due to missing
	// permission (403 Forbidden). Defaults to writing HTTP 403.
	OnDenied func(w http.ResponseWriter, r *http.Request)

	// OnUnauthorized is called when the middleware rejects a request due to an
	// invalid token — session-version revoked, cache stale, or inactive token
	// (401 Unauthorized). Defaults to writing HTTP 401.
	//
	// Note: when cfg.ExpectedMode is ModeEmbedded and WithSessionVersions was
	// configured on the client, sv-related rejections call OnUnauthorized, not
	// OnDenied, to match the 401 semantics prescribed by RFC HEA-930 § 8.
	OnUnauthorized func(w http.ResponseWriter, r *http.Request)
}

// bearerToken is the default TokenExtractor: strips "Bearer " prefix.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// forbiddenHandler is the default OnDenied handler.
func forbiddenHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Forbidden", http.StatusForbidden)
}

// unauthorizedHandler is the default OnUnauthorized handler.
func unauthorizedHandler(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// RequirePermission returns a middleware that enforces a permission check before
// calling next. The check strategy is controlled by cfg.ExpectedMode.
//
// Behavior per mode:
//   - ModeEmbedded:      decodes JWT claims locally; no network round-trip.
//     When the client has a SessionVersionCache configured, the sv claim is
//     validated first (RFC HEA-930 § 8). Revoked or stale → OnUnauthorized (401).
//   - ModeIntrospection: calls POST /introspect, verifies the echoed mode matches
//     cfg.ExpectedMode, then checks the live permissions claim. Returns
//     ModeMismatchError (mapped to denial) when modes disagree.
//   - ModeDecision:      calls POST /oauth/authorize; fail-closed on any error.
//
// The middleware NEVER silently falls back from decision→embedded or
// introspection→embedded based on whether `permissions` is absent in the token.
func RequirePermission(c *Client, permission string, cfg MiddlewareConfig) func(http.Handler) http.Handler {
	extract := cfg.TokenExtractor
	if extract == nil {
		extract = bearerToken
	}
	deny := cfg.OnDenied
	if deny == nil {
		deny = forbiddenHandler
	}
	unauth := cfg.OnUnauthorized
	if unauth == nil {
		unauth = unauthorizedHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extract(r)
			if token == "" {
				deny(w, r)
				return
			}

			var allowed bool

			switch cfg.ExpectedMode {
			case ModeEmbedded:
				claims := decodeClaims(token)
				if claims == nil {
					deny(w, r)
					return
				}
				// Session-version check when cache is configured (RFC HEA-930 § 8).
				if c.svCache != nil {
					svPresent := claims.SV != nil
					var sv uint64
					if svPresent {
						sv = *claims.SV
					}
					result := c.svCache.Check(svPresent, sv, claims.Sid)
					switch result {
					case SvRevoked:
						unauth(w, r)
						return
					case SvStale:
						unauth(w, r)
						return
					case SvOK, SvSkip:
						// continue to permission check
					}
				}
				allowed = contains(claims.Permissions, permission)

			case ModeIntrospection:
				resp, err := c.Introspect(r.Context(), IntrospectRequest{
					Token:        token,
					ClientID:     cfg.ClientID,
					ClientSecret: cfg.ClientSecret,
				})
				if err != nil {
					deny(w, r)
					return
				}
				if !resp.Active {
					deny(w, r)
					return
				}
				// Verify the echoed mode matches the configured expectation.
				// An absent mode field defaults to "embedded" (server omits it for Embedded clients).
				echoedMode := resp.Mode
				if echoedMode == "" {
					echoedMode = string(ModeEmbedded)
				}
				if echoedMode != string(cfg.ExpectedMode) {
					// Hard rejection — do not fall back to local check.
					deny(w, r)
					return
				}
				allowed = contains(resp.Permissions, permission)

			case ModeDecision:
				// CheckPermission is fail-closed: network errors return Allowed=false.
				resp, _ := c.CheckPermission(r.Context(), token, CheckPermissionRequest{
					Permission: permission,
				})
				allowed = resp != nil && resp.Allowed

			default:
				// Unknown mode is a misconfiguration — deny.
				deny(w, r)
				return
			}

			if !allowed {
				deny(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
