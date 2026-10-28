package hearth

import (
	"context"
	"net/http"
)

// MiddlewareConfig configures a RequirePermission middleware factory.
type MiddlewareConfig struct {
	// ExpectedMode is required. Controls how the middleware evaluates permissions.
	//   ModeEmbedded      — verifies the JWT against the cached JWKS, then reads
	//                       its permissions claim. No per-request network call.
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

	// OnDenied is called when the middleware rejects a request with a valid
	// token that lacks the permission, or when introspection or the mode check
	// fails (403 Forbidden). Defaults to writing HTTP 403.
	OnDenied func(w http.ResponseWriter, r *http.Request)

	// OnUnauthorized is called when the middleware rejects a request for its
	// token (401 Unauthorized): no token, a token that does not verify
	// (ModeEmbedded), a token that introspection reports inactive, or a
	// session version that is revoked or stale. Defaults to writing HTTP 401.
	//
	// Before calling it, the middleware sets the WWW-Authenticate challenge
	// (RFC 6750 §3): `Bearer realm="hearth"` for a request without a token,
	// with `error="invalid_token"` added for a token it rejects.
	//
	// Note: when cfg.ExpectedMode is ModeEmbedded and WithSessionVersions was
	// configured on the client, sv-related rejections call OnUnauthorized, not
	// OnDenied, to match the 401 semantics prescribed by RFC HEA-930 § 8.
	OnUnauthorized func(w http.ResponseWriter, r *http.Request)

	// OnRequiredAction is called when the token has token_type == "required_action"
	// (spec §6 rule 6). It must answer HTTP 401; the middleware never calls
	// next for such a token, and sets the WWW-Authenticate challenge first.
	//
	// When nil, the middleware falls back to OnUnauthorized. Providing this
	// handler lets callers distinguish a required-action rejection (and access the
	// typed RequiredActionError with pending action names) from a generic 401.
	OnRequiredAction func(w http.ResponseWriter, r *http.Request, err *RequiredActionError)
}

// contextKey is the type of the request-context keys this package sets.
type contextKey struct{ name string }

// ClaimsContextKey is the request-context key under which RequirePermission
// stores the verified token's *Claims before it calls the next handler. Read
// it with ClaimsFromContext.
var ClaimsContextKey = &contextKey{"hearth-claims"}

// ClaimsFromContext returns the claims of the token that RequirePermission
// verified for this request. It reports false when no claims are stored:
// the request did not pass RequirePermission, or the middleware ran in
// ModeIntrospection or ModeDecision, where the server decides and the SDK
// verifies no token itself.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok && claims != nil
}

// WWW-Authenticate challenges for a 401 (RFC 6750 §3).
const (
	// bearerChallenge answers a request without a bearer token.
	bearerChallenge = `Bearer realm="hearth"`
	// invalidTokenChallenge answers a token the middleware rejects.
	invalidTokenChallenge = `Bearer realm="hearth", error="invalid_token"`
)

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
// A request without a token → OnUnauthorized (401, `WWW-Authenticate: Bearer
// realm="hearth"`), in every mode. A valid token without the permission →
// OnDenied (403). The next handler runs only when the check passes.
//
// Behavior per mode:
//   - ModeEmbedded:      verifies the JWT's EdDSA signature against the realm's
//     JWKS (cached) and its exp/nbf/iss/aud, then reads the permissions claim.
//     A token that fails verification → OnUnauthorized (401,
//     `error="invalid_token"`). When the client has a SessionVersionCache
//     configured, the sv claim is validated next (RFC HEA-930 § 8). Revoked or
//     stale → OnUnauthorized (401). On success the verified *Claims are in the
//     request context (ClaimsFromContext).
//   - ModeIntrospection: posts to the discovered introspection endpoint. An
//     inactive token → OnUnauthorized (401, `error="invalid_token"`). It then
//     verifies the echoed mode matches cfg.ExpectedMode (a mismatch denies),
//     and checks the live permissions claim.
//   - ModeDecision:      calls POST /oauth/authorize; fail-closed on any error.
//     The decision endpoint answers a bad token like a missing permission, so
//     both are denied with 403.
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
	onRequiredAction := cfg.OnRequiredAction

	// challenge answers 401 with the WWW-Authenticate value RFC 7235 §3.1
	// requires on every 401.
	challenge := func(w http.ResponseWriter, r *http.Request, value string) {
		w.Header().Set("WWW-Authenticate", value)
		unauth(w, r)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extract(r)
			if token == "" {
				challenge(w, r, bearerChallenge)
				return
			}

			// Spec §6 rule 6: required_action tokens must be rejected with 401
			// regardless of mode — they are valid but scoped only to completing
			// pending actions and must never be accepted for general API access.
			//
			// This read is deliberately unverified: it can only ever *reject*,
			// so a forged token_type costs the forger their own request and
			// grants nothing. Every path that can *grant* verifies first.
			if raw := decodeClaims(token); raw != nil && raw.TokenType == "required_action" {
				rae := &RequiredActionError{RequiredActions: raw.RequiredActions}
				if onRequiredAction != nil {
					w.Header().Set("WWW-Authenticate", invalidTokenChallenge)
					onRequiredAction(w, r, rae)
				} else {
					challenge(w, r, invalidTokenChallenge)
				}
				return
			}

			var allowed bool
			// verified holds the claims of a token the SDK verified itself
			// (ModeEmbedded); the next handler reads them from the context.
			var verified *Claims

			switch cfg.ExpectedMode {
			case ModeEmbedded:
				// Verify the signature, exp, nbf, iss and aud against the
				// realm's JWKS BEFORE reading any claim. A token that does not
				// verify is unauthenticated, not merely unauthorized — 401,
				// not 403.
				var err error
				verified, err = c.VerifyToken(r.Context(), token)
				if err != nil {
					challenge(w, r, invalidTokenChallenge)
					return
				}
				claims := decodeClaims(token)
				if claims == nil {
					challenge(w, r, invalidTokenChallenge)
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
						challenge(w, r, invalidTokenChallenge)
						return
					case SvStale:
						challenge(w, r, invalidTokenChallenge)
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
					// An inactive token is invalid, not short of a permission.
					challenge(w, r, invalidTokenChallenge)
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
			if verified != nil {
				r = r.WithContext(context.WithValue(r.Context(), ClaimsContextKey, verified))
			}
			next.ServeHTTP(w, r)
		})
	}
}
