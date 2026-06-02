package hearth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AdminClient provides access to the Hearth admin API.
type AdminClient struct {
	baseURL     string
	realmID    string
	accessToken string
	http        *http.Client
}

// CreateUser creates a new user via the admin API.
func (a *AdminClient) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	var result User
	if err := a.post(ctx, "/admin/users", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUser retrieves a user by ID via the admin API.
func (a *AdminClient) GetUser(ctx context.Context, userID string) (*User, error) {
	var result User
	if err := a.get(ctx, fmt.Sprintf("/admin/users/%s", userID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateUser updates a user via the admin API.
func (a *AdminClient) UpdateUser(ctx context.Context, userID string, req UpdateUserRequest) (*User, error) {
	var result User
	if err := a.request(ctx, "PATCH", fmt.Sprintf("/admin/users/%s", userID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteUser deletes a user via the admin API.
func (a *AdminClient) DeleteUser(ctx context.Context, userID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/users/%s", userID), nil, nil)
}

// ListUsers lists users with optional cursor-based pagination (spec §12).
func (a *AdminClient) ListUsers(ctx context.Context, opts ListOptions) (*PageResponse[User], error) {
	path := buildListPath("/admin/users", opts)
	var result PageResponse[User]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListRealms lists realms with optional cursor-based pagination (spec §12).
func (a *AdminClient) ListRealms(ctx context.Context, opts ListOptions) (*PageResponse[Realm], error) {
	path := buildListPath("/admin/realms", opts)
	var result PageResponse[Realm]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateRealm creates a new realm via the admin API.
func (a *AdminClient) CreateRealm(ctx context.Context, req CreateRealmRequest) (*Realm, error) {
	var result Realm
	if err := a.post(ctx, "/admin/realms", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRealm retrieves a realm by ID via the admin API.
func (a *AdminClient) GetRealm(ctx context.Context, realmID string) (*Realm, error) {
	var result Realm
	if err := a.get(ctx, fmt.Sprintf("/admin/realms/%s", realmID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateRealm updates a realm via the admin API.
func (a *AdminClient) UpdateRealm(ctx context.Context, realmID string, req UpdateRealmRequest) (*Realm, error) {
	var result Realm
	if err := a.request(ctx, "PATCH", fmt.Sprintf("/admin/realms/%s", realmID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteRealm deletes a realm via the admin API.
func (a *AdminClient) DeleteRealm(ctx context.Context, realmID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/realms/%s", realmID), nil, nil)
}

// ─── OAuth Clients ────────────────────────────────────────────────────────────

// CreateClient creates an OAuth client via the admin API.
func (a *AdminClient) CreateClient(ctx context.Context, req CreateClientRequest) (*OAuthClient, error) {
	var result OAuthClient
	if err := a.post(ctx, "/admin/clients", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetClient retrieves an OAuth client by ID via the admin API.
func (a *AdminClient) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	var result OAuthClient
	if err := a.get(ctx, fmt.Sprintf("/admin/clients/%s", clientID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateClient updates an OAuth client via the admin API.
func (a *AdminClient) UpdateClient(ctx context.Context, clientID string, req UpdateClientRequest) (*OAuthClient, error) {
	var result OAuthClient
	if err := a.request(ctx, "PATCH", fmt.Sprintf("/admin/clients/%s", clientID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteClient deletes an OAuth client via the admin API.
func (a *AdminClient) DeleteClient(ctx context.Context, clientID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/clients/%s", clientID), nil, nil)
}

// ListClients lists OAuth clients with optional cursor-based pagination.
func (a *AdminClient) ListClients(ctx context.Context, opts ListOptions) (*PageResponse[OAuthClient], error) {
	path := buildListPath("/admin/clients", opts)
	var result PageResponse[OAuthClient]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ─── Roles ────────────────────────────────────────────────────────────────────

// CreateRole creates a realm-level role via the admin API.
func (a *AdminClient) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	var result Role
	if err := a.post(ctx, "/admin/roles", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRole retrieves a role by ID via the admin API.
func (a *AdminClient) GetRole(ctx context.Context, roleID string) (*Role, error) {
	var result Role
	if err := a.get(ctx, fmt.Sprintf("/admin/roles/%s", roleID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateRole updates a role via the admin API.
func (a *AdminClient) UpdateRole(ctx context.Context, roleID string, req UpdateRoleRequest) (*Role, error) {
	var result Role
	if err := a.request(ctx, "PATCH", fmt.Sprintf("/admin/roles/%s", roleID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteRole deletes a role via the admin API.
func (a *AdminClient) DeleteRole(ctx context.Context, roleID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/roles/%s", roleID), nil, nil)
}

// ListRoles lists roles with optional cursor-based pagination.
func (a *AdminClient) ListRoles(ctx context.Context, opts ListOptions) (*PageResponse[Role], error) {
	path := buildListPath("/admin/roles", opts)
	var result PageResponse[Role]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ─── Groups ───────────────────────────────────────────────────────────────────

// CreateGroup creates a realm-level group via the admin API.
func (a *AdminClient) CreateGroup(ctx context.Context, req CreateGroupRequest) (*Group, error) {
	var result Group
	if err := a.post(ctx, "/admin/groups", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGroup retrieves a group by ID via the admin API.
func (a *AdminClient) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	var result Group
	if err := a.get(ctx, fmt.Sprintf("/admin/groups/%s", groupID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateGroup updates a group via the admin API.
func (a *AdminClient) UpdateGroup(ctx context.Context, groupID string, req UpdateGroupRequest) (*Group, error) {
	var result Group
	if err := a.request(ctx, "PATCH", fmt.Sprintf("/admin/groups/%s", groupID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteGroup deletes a group via the admin API.
func (a *AdminClient) DeleteGroup(ctx context.Context, groupID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/groups/%s", groupID), nil, nil)
}

// ListGroups lists groups with optional cursor-based pagination.
func (a *AdminClient) ListGroups(ctx context.Context, opts ListOptions) (*PageResponse[Group], error) {
	path := buildListPath("/admin/groups", opts)
	var result PageResponse[Group]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ─── Organization Memberships ─────────────────────────────────────────────────

// AddOrgMember adds a user to an organization via the admin API.
func (a *AdminClient) AddOrgMember(ctx context.Context, orgID string, req AddOrgMemberRequest) (*OrgMember, error) {
	var result OrgMember
	if err := a.post(ctx, fmt.Sprintf("/admin/orgs/%s/members", orgID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetOrgMember retrieves an organization membership by user ID via the admin API.
func (a *AdminClient) GetOrgMember(ctx context.Context, orgID, userID string) (*OrgMember, error) {
	var result OrgMember
	if err := a.get(ctx, fmt.Sprintf("/admin/orgs/%s/members/%s", orgID, userID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateOrgMember updates an organization membership via the admin API.
func (a *AdminClient) UpdateOrgMember(ctx context.Context, orgID, userID string, req UpdateOrgMemberRequest) (*OrgMember, error) {
	var result OrgMember
	if err := a.request(ctx, "PATCH", fmt.Sprintf("/admin/orgs/%s/members/%s", orgID, userID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RemoveOrgMember removes a user from an organization via the admin API.
func (a *AdminClient) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/orgs/%s/members/%s", orgID, userID), nil, nil)
}

// ListOrgMembers lists members of an organization with optional cursor-based pagination.
func (a *AdminClient) ListOrgMembers(ctx context.Context, orgID string, opts ListOptions) (*PageResponse[OrgMember], error) {
	path := buildListPath(fmt.Sprintf("/admin/orgs/%s/members", orgID), opts)
	var result PageResponse[OrgMember]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// buildListPath appends limit and cursor query parameters to base when provided.
func buildListPath(base string, opts ListOptions) string {
	sep := "?"
	path := base
	if opts.Limit > 0 {
		path += fmt.Sprintf("%slimit=%d", sep, opts.Limit)
		sep = "&"
	}
	if opts.Cursor != "" {
		path += fmt.Sprintf("%scursor=%s", sep, opts.Cursor)
	}
	return path
}

func (a *AdminClient) headers(req *http.Request) {
	req.Header.Set("X-Realm-ID", a.realmID)
	req.Header.Set("Authorization", "Bearer "+a.accessToken)
	req.Header.Set("Content-Type", "application/json")
}

func (a *AdminClient) get(ctx context.Context, path string, result any) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+path, nil)
	if err != nil {
		return err
	}
	a.headers(httpReq)
	return doRequest(a.http, httpReq, result)
}

func (a *AdminClient) post(ctx context.Context, path string, body, result any) error {
	return a.request(ctx, "POST", path, body, result)
}

func (a *AdminClient) request(ctx context.Context, method, path string, body, result any) error {
	var bodyReader *bytes.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	var httpReq *http.Request
	var err error
	if bodyReader != nil {
		httpReq, err = http.NewRequestWithContext(ctx, method, a.baseURL+path, bodyReader)
	} else {
		httpReq, err = http.NewRequestWithContext(ctx, method, a.baseURL+path, nil)
	}
	if err != nil {
		return err
	}
	a.headers(httpReq)
	return doRequest(a.http, httpReq, result)
}
