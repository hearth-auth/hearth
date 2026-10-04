// Command conformance runs the shared SDK conformance cases
// (sdks/conformance/README.md) through the Go SDK's public API and prints one
// JSON result line per case.
//
// Usage: go run ./conformance <cases.json>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hearth-auth/hearth/sdks/go/hearth"
)

type caseConfig struct {
	BaseURL      string  `json:"base_url"`
	Realm        string  `json:"realm"`
	Issuer       string  `json:"issuer"`
	Audience     *string `json:"audience"`
	ClientID     *string `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
}

type testCase struct {
	ID     string     `json:"id"`
	Kind   string     `json:"kind"`
	Token  string     `json:"token"`
	Config caseConfig `json:"config"`
	Scope  string     `json:"scope"`
	Claims []string   `json:"claims"`
}

type caseFile struct {
	Cases []testCase `json:"cases"`
}

type result struct {
	ID      string         `json:"id"`
	Outcome string         `json:"outcome"`
	Claims  map[string]any `json:"claims,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: conformance <cases.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var file caseFile
	if err := json.Unmarshal(raw, &file); err != nil {
		fmt.Fprintln(os.Stderr, "bad case file:", err)
		os.Exit(2)
	}
	out := json.NewEncoder(os.Stdout)
	for _, c := range file.Cases {
		if err := out.Encode(run(c)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}

// run executes one case on a fresh client, so no case reuses another's JWKS cache.
func run(c testCase) result {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var opts []hearth.ClientOption
	if c.Config.ClientID != nil && c.Config.ClientSecret != nil {
		opts = append(opts, hearth.WithClientCredentials(*c.Config.ClientID, *c.Config.ClientSecret))
	}
	// The Go client's base URL is the realm issuer: discovery, JWKS and the
	// token endpoint all hang off it.
	client := hearth.NewClient(c.Config.Issuer, c.Config.Realm, opts...)

	token := c.Token
	switch c.Kind {
	case "verify_token":
	case "client_credentials":
		resp, err := client.ClientCredentials(ctx, c.Scope)
		if err != nil {
			return failure(c.ID, err)
		}
		token = resp.AccessToken
	default:
		return result{ID: c.ID, Outcome: "error", Error: "Unexpected:unknown kind " + c.Kind}
	}

	var audience []string
	if c.Config.Audience != nil {
		audience = []string{*c.Config.Audience}
	}
	claims, err := client.VerifyToken(ctx, token, audience...)
	if err != nil {
		return failure(c.ID, err)
	}
	return result{ID: c.ID, Outcome: "ok", Claims: pick(claims, c.Claims)}
}

// pick reads the requested claims through the public Claims API.
func pick(claims *hearth.Claims, names []string) map[string]any {
	out := map[string]any{}
	for _, name := range names {
		switch name {
		case "sub":
			out["sub"] = claims.Subject()
		case "scope":
			if s := claims.Scope(); s != "" {
				out["scope"] = s
			} else {
				out["scope"] = nil
			}
		case "permissions":
			perms := []string{}
			if raw := claims.Get("permissions"); raw != nil {
				_ = json.Unmarshal(raw, &perms)
			}
			out["permissions"] = perms
		default:
			var v any
			if raw := claims.Get(name); raw != nil {
				_ = json.Unmarshal(raw, &v)
			}
			out[name] = v
		}
	}
	return out
}

// failure maps an SDK error to its SDK.md §5 name.
func failure(id string, err error) result {
	return result{ID: id, Outcome: "error", Error: errorName(err)}
}

func errorName(err error) string {
	var (
		configErr    *hearth.ConfigurationError
		discoveryErr *hearth.DiscoveryError
		jwksErr      *hearth.JWKSFetchError
		expiredErr   *hearth.TokenExpiredError
		nbfErr       *hearth.TokenNotYetValidError
		invalidErr   *hearth.TokenInvalidError
		issuerErr    *hearth.TokenIssuerError
		audienceErr  *hearth.TokenAudienceError
		introErr     *hearth.IntrospectionError
		requiredErr  *hearth.RequiredActionError
	)
	switch {
	case errors.As(err, &configErr):
		return "ConfigurationError"
	case errors.As(err, &discoveryErr):
		return "DiscoveryError"
	case errors.As(err, &jwksErr):
		return "JWKSFetchError"
	case errors.As(err, &expiredErr):
		return "TokenExpiredError"
	case errors.As(err, &nbfErr):
		return "TokenNotYetValidError"
	case errors.As(err, &invalidErr):
		return "TokenInvalidError"
	case errors.As(err, &issuerErr):
		return "TokenIssuerError"
	case errors.As(err, &audienceErr):
		return "TokenAudienceError"
	case errors.As(err, &introErr):
		return "IntrospectionError"
	case errors.As(err, &requiredErr):
		return "RequiredActionError"
	default:
		return fmt.Sprintf("Unexpected:%T", err)
	}
}
