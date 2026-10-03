package hearth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/hearth-auth/hearth/sdks/go/generated/admin"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Conversions between the generated admin types (sdks/go/generated/admin)
// and the SDK's public types.

// decodeMapped decodes a response into the generated type G, then maps it.
func decodeMapped[G, T any](resp *http.Response, err error, mapper func(G) T) (*T, error) {
	var g G
	if err := decodeResponse(resp, err, &g); err != nil {
		return nil, err
	}
	t := mapper(g)
	return &t, nil
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

func mapAll[G, T any](in []G, mapper func(G) T) []T {
	out := make([]T, 0, len(in))
	for _, g := range in {
		out = append(out, mapper(g))
	}
	return out
}

// optString sends a non-empty string, and leaves an empty one out.
func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// optSlice sends a non-nil slice, and leaves a nil one out.
func optSlice(v []string) *[]string {
	if v == nil {
		return nil
	}
	return &v
}

func parseUUIDs(ids []string) (*[]openapi_types.UUID, error) {
	if ids == nil {
		return nil, nil
	}
	out := make([]openapi_types.UUID, 0, len(ids))
	for _, id := range ids {
		u, err := uuid.Parse(id)
		if err != nil {
			return nil, &ConfigurationError{Field: "ParentRoles", Message: fmt.Sprintf("parent role %q is not a UUID", id)}
		}
		out = append(out, u)
	}
	return &out, nil
}

func uuidStrings(ids []openapi_types.UUID) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// userStatus turns `active` or `USER_STATUS_ACTIVE` into the proto name, the
// only form the server accepts.
func userStatus(s string) (admin.V1UserStatus, error) {
	name := strings.ToUpper(s)
	if !strings.HasPrefix(name, "USER_STATUS_") {
		name = "USER_STATUS_" + name
	}
	switch status := admin.V1UserStatus(name); status {
	case admin.USERSTATUSACTIVE, admin.USERSTATUSDISABLED, admin.USERSTATUSPENDINGVERIFICATION:
		return status, nil
	default:
		return "", &ConfigurationError{Field: "Status", Message: fmt.Sprintf("unknown user status %q", s)}
	}
}

func userFrom(u admin.V1User) User {
	return User{
		ID:          deref(u.Id),
		Email:       deref(u.Email),
		DisplayName: deref(u.DisplayName),
		Status:      string(deref(u.Status)),
		CreatedAt:   deref(u.CreatedAt),
		UpdatedAt:   deref(u.UpdatedAt),
	}
}

func clientFrom(c admin.V1OAuthClient) OAuthClient {
	return OAuthClient{
		ClientID:     deref(c.ClientId),
		ClientName:   deref(c.ClientName),
		RedirectURIs: deref(c.RedirectUris),
		GrantTypes:   deref(c.GrantTypes),
		ClientSecret: deref(c.ClientSecret),
	}
}

func roleFrom(r admin.AdminRole) Role {
	return Role{
		ID:          r.Id.String(),
		Name:        r.Name,
		Description: deref(r.Description),
		Permissions: r.Permissions,
		ParentRoles: uuidStrings(r.ParentRoles),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func groupFrom(g admin.AdminGroup) Group {
	return Group{
		ID:          g.Id.String(),
		Name:        g.Name,
		Slug:        g.Slug,
		Description: deref(g.Description),
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
}
