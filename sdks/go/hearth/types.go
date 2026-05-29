// Package hearth provides a Go client for the Hearth identity API.
package hearth

// BootstrapResponse is returned by the dev bootstrap endpoint.
type BootstrapResponse struct {
	RealmID      string `json:"realm_id"`
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// AuthorizeRequest contains parameters for the authorization code flow.
type AuthorizeRequest struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	ResponseType string `json:"response_type"`
	UserID       string `json:"user_id"`
}

// AuthorizeResponse is returned by the authorize endpoint.
type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// TokenRequest contains parameters for the token exchange.
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	GrantType    string `json:"grant_type,omitempty"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse is returned by the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token"`
}

// UserInfoResponse is returned by the userinfo endpoint.
type UserInfoResponse struct {
	Sub           string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// CreateUserRequest contains parameters for creating a user.
type CreateUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// User represents a user record from the API.
type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// UpdateUserRequest contains parameters for updating a user.
type UpdateUserRequest struct {
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// CreateRealmRequest contains parameters for creating a realm.
type CreateRealmRequest struct {
	Name string `json:"name"`
}

// Realm represents a realm record from the API.
type Realm struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Config    any    `json:"config"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// UpdateRealmRequest contains parameters for updating a realm.
type UpdateRealmRequest struct {
	Name   *string `json:"name,omitempty"`
	Status *string `json:"status,omitempty"`
}

// PageResponse represents a paginated list response.
type PageResponse[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// RegisterClientRequest contains parameters for registering an OAuth client.
type RegisterClientRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// OAuthClient represents an OAuth client record.
type OAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// MePermissionsResponse is returned by GET /v1/me/permissions.
//
// It carries the freshly-resolved RBAC claim set for the bearer-token
// user. Unlike HasPermission/HasRole/InGroup/InOrg (which read the
// cached set from the JWT), this response reflects the server's
// current role and group assignments.
type MePermissionsResponse struct {
	Roles       []string `json:"roles"`
	Groups      []string `json:"groups"`
	Permissions []string `json:"permissions"`
	Scope       string   `json:"scope"`
}

// AccessTokenAuthorizationMode controls how the SDK and middleware verify
// permissions for a given resource server client.
//
// Must be configured explicitly — the middleware will NOT silently fall back
// from one mode to another based on what claims happen to be present in the
// token.
type AccessTokenAuthorizationMode string

const (
	// ModeEmbedded uses JWT claims decoded locally. Zero network calls.
	// Requires the client to be registered with access_token_authorization=embedded.
	ModeEmbedded AccessTokenAuthorizationMode = "embedded"

	// ModeIntrospection calls POST /introspect on each request.
	// The server re-resolves live RBAC and echoes the configured mode.
	// Requires ClientID + ClientSecret in MiddlewareConfig.
	ModeIntrospection AccessTokenAuthorizationMode = "introspection"

	// ModeDecision calls POST /oauth/authorize on each request.
	// The server performs a per-request permission decision and returns allowed/denied.
	// Fail-closed: network errors result in denial.
	ModeDecision AccessTokenAuthorizationMode = "decision"
)

// IntrospectRequest contains parameters for token introspection (RFC 7662).
type IntrospectRequest struct {
	// Token is the access token to introspect. Required.
	Token string `json:"token"`
	// TokenTypeHint optionally hints at the token type.
	TokenTypeHint string `json:"token_type_hint,omitempty"`
	// ClientID is the authenticating resource-server client. Required.
	ClientID string `json:"client_id"`
	// ClientSecret is the client secret for confidential clients.
	ClientSecret string `json:"client_secret,omitempty"`
}

// IntrospectResponse is the RFC 7662 introspection response returned by POST /introspect.
type IntrospectResponse struct {
	// Active indicates whether the token is currently valid.
	Active bool `json:"active"`
	// Scope is the space-separated scope string.
	Scope string `json:"scope,omitempty"`
	// ClientID is the client that was issued this token.
	ClientID string `json:"client_id,omitempty"`
	// Sub is the subject (user or client) of the token.
	Sub string `json:"sub,omitempty"`
	// Exp is the expiration time (Unix seconds).
	Exp int64 `json:"exp,omitempty"`
	// Iat is the issued-at time (Unix seconds).
	Iat int64 `json:"iat,omitempty"`
	// TokenType describes the token type.
	TokenType string `json:"token_type,omitempty"`
	// Iss is the issuer.
	Iss string `json:"iss,omitempty"`
	// Mode is the access-token authorization mode echoed from the issuing client.
	Mode string `json:"mode,omitempty"`
	// Permissions is the live-resolved permission set (Introspection/Decision modes only).
	Permissions []string `json:"permissions,omitempty"`
	// Roles is the live-resolved role set.
	Roles []string `json:"roles,omitempty"`
	// Groups is the live-resolved group set.
	Groups []string `json:"groups,omitempty"`
}

// CheckPermissionRequest contains parameters for POST /oauth/authorize (decision endpoint).
type CheckPermissionRequest struct {
	// Permission is the permission string to check. Required.
	Permission string `json:"permission"`
	// OrganizationID scopes the check to a specific organization.
	OrganizationID string `json:"organization_id,omitempty"`
	// Resource is an optional RFC 8707 resource indicator.
	Resource string `json:"resource,omitempty"`
}

// CheckPermissionResponse is returned by POST /oauth/authorize.
type CheckPermissionResponse struct {
	// Allowed indicates whether the token holder has the requested permission.
	Allowed bool `json:"allowed"`
}

// ListOptions controls pagination for list endpoints (spec §12).
type ListOptions struct {
	// Limit is the maximum number of items to return. The server applies its
	// own default when Limit is zero.
	Limit int
	// Cursor is an opaque continuation token from a previous PageResponse.
	// Leave empty to start from the beginning.
	Cursor string
}

// CreateClientRequest contains parameters for creating an OAuth client via the admin API.
type CreateClientRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types,omitempty"`
}

// UpdateClientRequest contains parameters for updating an OAuth client via the admin API.
type UpdateClientRequest struct {
	ClientName   *string  `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
}

// Role represents a realm-level role definition.
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// CreateRoleRequest contains parameters for creating a role via the admin API.
type CreateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdateRoleRequest contains parameters for updating a role via the admin API.
type UpdateRoleRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// Group represents a realm-level group definition.
type Group struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// CreateGroupRequest contains parameters for creating a group via the admin API.
type CreateGroupRequest struct {
	Name string `json:"name"`
}

// UpdateGroupRequest contains parameters for updating a group via the admin API.
type UpdateGroupRequest struct {
	Name *string `json:"name,omitempty"`
}

// OrgMember represents an organization membership record.
type OrgMember struct {
	UserID    string `json:"user_id"`
	OrgID     string `json:"org_id"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

// AddOrgMemberRequest contains parameters for adding a member to an organization.
type AddOrgMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

// UpdateOrgMemberRequest contains parameters for updating an org membership.
type UpdateOrgMemberRequest struct {
	Role *string `json:"role,omitempty"`
}

// APIError represents an error from the Hearth API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}
