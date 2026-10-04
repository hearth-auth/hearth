package hearth

import (
	"context"
	"net/http"

	"github.com/hearth-auth/hearth/sdks/go/generated/admin"
)

// AdminClient provides access to the Hearth admin API.
//
// It wraps the client generated from docs/api/openapi.json
// (sdks/go/generated/admin, `make sdk-admin-gen`), which owns every route,
// method and query parameter. This layer adds the bearer token and
// X-Realm-ID header, the ergonomic method names and the SDK error taxonomy.
//
// Request bodies are the generated types, and responses decode into the
// generated types before they are mapped onto the SDK's public types
// (admin_convert.go). Realms are the exception on the response side:
// Realm.Config is an untyped `any` in the public API, so realm responses
// decode directly into Realm.
type AdminClient struct {
	baseURL     string
	realmID     string
	accessToken string
	http        *http.Client
}

// Organization is an organization as the admin API returns it.
type Organization = admin.AdminOrganization

// OrganizationStatus is `active`, `suspended` or `archived`.
type OrganizationStatus = admin.AdminOrganizationStatus

// CreateOrganizationRequest is the body of CreateOrganization. Slug and
// DisplayName are required.
type CreateOrganizationRequest = admin.AdminCreateOrganizationRequest

// UpdateOrganizationRequest is the body of UpdateOrganization. Nil fields are
// unchanged; Status accepts `active` or `suspended`; the slug is immutable.
type UpdateOrganizationRequest = admin.AdminUpdateOrganizationRequest

// UpdateOrganizationStatus is the status an UpdateOrganizationRequest may set.
type UpdateOrganizationStatus = admin.AdminUpdateOrganizationRequestStatus

// api returns the generated client, authenticated for this AdminClient.
func (a *AdminClient) api() *admin.Client {
	// NewClient fails only on an invalid option; both options here are fixed.
	c, _ := admin.NewClient(a.baseURL,
		admin.WithHTTPClient(a.http),
		admin.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("X-Realm-ID", a.realmID)
			req.Header.Set("Authorization", "Bearer "+a.accessToken)
			return nil
		}),
	)
	return c
}

// listParams converts ListOptions to the generated cursor/limit pointers.
func listParams(opts ListOptions) (cursor *string, limit *int64) {
	if opts.Cursor != "" {
		cursor = &opts.Cursor
	}
	if opts.Limit > 0 {
		l := int64(opts.Limit)
		limit = &l
	}
	return cursor, limit
}

// intListParams is listParams for the operations whose limit is a plain int.
func intListParams(opts ListOptions) (cursor *string, limit *int) {
	if opts.Cursor != "" {
		cursor = &opts.Cursor
	}
	if opts.Limit > 0 {
		limit = &opts.Limit
	}
	return cursor, limit
}

// ─── Users ────────────────────────────────────────────────────────────────────

// CreateUser creates a new user via the admin API.
func (a *AdminClient) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	resp, err := a.api().IdentityAdminServiceCreateUser(ctx, admin.V1CreateUserRequest{
		Email:       &req.Email,
		DisplayName: &req.DisplayName,
	})
	return decodeMapped(resp, err, userFrom)
}

// GetUser retrieves a user by ID via the admin API.
func (a *AdminClient) GetUser(ctx context.Context, userID string) (*User, error) {
	resp, err := a.api().IdentityAdminServiceGetUser(ctx, userID)
	return decodeMapped(resp, err, userFrom)
}

// UpdateUser updates a user via the admin API. A Status in short form
// (`active`) is sent as its proto name (`USER_STATUS_ACTIVE`).
func (a *AdminClient) UpdateUser(ctx context.Context, userID string, req UpdateUserRequest) (*User, error) {
	body := admin.V1UpdateUserRequest{Email: req.Email, DisplayName: req.DisplayName}
	if req.Status != nil {
		status, err := userStatus(*req.Status)
		if err != nil {
			return nil, err
		}
		body.Status = &status
	}
	resp, err := a.api().IdentityAdminServiceUpdateUser(ctx, userID, body)
	return decodeMapped(resp, err, userFrom)
}

// DeleteUser deletes a user via the admin API.
func (a *AdminClient) DeleteUser(ctx context.Context, userID string) error {
	resp, err := a.api().IdentityAdminServiceDeleteUser(ctx, userID)
	return decodeResponse(resp, err, nil)
}

// ListUsers lists users with optional cursor-based pagination (spec §12).
func (a *AdminClient) ListUsers(ctx context.Context, opts ListOptions) (*PageResponse[User], error) {
	cursor, limit := listParams(opts)
	resp, err := a.api().IdentityAdminServiceListUsers(ctx,
		&admin.IdentityAdminServiceListUsersParams{Cursor: cursor, Limit: limit})
	return decodeMapped(resp, err, func(p admin.V1UserPage) PageResponse[User] {
		return PageResponse[User]{Items: mapAll(deref(p.Items), userFrom), NextCursor: p.NextCursor}
	})
}

// ─── Realms ───────────────────────────────────────────────────────────────────

// ListRealms lists realms with optional cursor-based pagination (spec §12).
func (a *AdminClient) ListRealms(ctx context.Context, opts ListOptions) (*PageResponse[Realm], error) {
	cursor, limit := listParams(opts)
	var result PageResponse[Realm]
	resp, err := a.api().IdentityAdminServiceListRealms(ctx,
		&admin.IdentityAdminServiceListRealmsParams{Cursor: cursor, Limit: limit})
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRealm retrieves a realm by ID via the admin API.
func (a *AdminClient) GetRealm(ctx context.Context, realmID string) (*Realm, error) {
	var result Realm
	resp, err := a.api().IdentityAdminServiceGetRealm(ctx, realmID)
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Realms are provisioned via hearth.yaml, not the admin API. There is no
// CreateRealm and no UpdateRealm method: the server answers 405 with "Realms
// are managed via hearth.yaml" to both POST /admin/realms and
// PATCH /admin/realms/{id} (HEA-2171, audit 2026-08-28 §25.4).

// DeleteRealm deletes a realm via the admin API.
func (a *AdminClient) DeleteRealm(ctx context.Context, realmID string) error {
	resp, err := a.api().IdentityAdminServiceDeleteRealm(ctx, realmID)
	return decodeResponse(resp, err, nil)
}

// ─── OAuth Clients ────────────────────────────────────────────────────────────

// CreateClient creates an OAuth client via the admin API.
func (a *AdminClient) CreateClient(ctx context.Context, req CreateClientRequest) (*OAuthClient, error) {
	resp, err := a.api().ApplicationAdminServiceCreateApplication(ctx, admin.V1RegisterClientRequest{
		ClientName:   &req.ClientName,
		RedirectUris: optSlice(req.RedirectURIs),
		GrantTypes:   optSlice(req.GrantTypes),
	})
	return decodeMapped(resp, err, clientFrom)
}

// GetClient retrieves an OAuth client by ID via the admin API.
func (a *AdminClient) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	resp, err := a.api().ApplicationAdminServiceGetApplication(ctx, clientID)
	return decodeMapped(resp, err, clientFrom)
}

// UpdateClient updates an OAuth client via the admin API.
func (a *AdminClient) UpdateClient(ctx context.Context, clientID string, req UpdateClientRequest) (*OAuthClient, error) {
	resp, err := a.api().ApplicationAdminServiceUpdateApplication(ctx, clientID, admin.V1UpdateClientRequest{
		ClientName:   req.ClientName,
		RedirectUris: optSlice(req.RedirectURIs),
	})
	return decodeMapped(resp, err, clientFrom)
}

// RegenerateClientSecret replaces a confidential client's secret
// (POST /admin/applications/{id}/regenerate-secret). The returned client
// carries the new secret in ClientSecret, once; the old secret stops working
// immediately.
func (a *AdminClient) RegenerateClientSecret(ctx context.Context, clientID string) (*OAuthClient, error) {
	resp, err := a.api().ApplicationAdminServiceRegenerateApplicationSecret(ctx, clientID)
	return decodeMapped(resp, err, clientFrom)
}

// DeleteClient deletes an OAuth client via the admin API.
func (a *AdminClient) DeleteClient(ctx context.Context, clientID string) error {
	resp, err := a.api().ApplicationAdminServiceDeleteApplication(ctx, clientID)
	return decodeResponse(resp, err, nil)
}

// ListClients lists OAuth clients with optional cursor-based pagination.
func (a *AdminClient) ListClients(ctx context.Context, opts ListOptions) (*PageResponse[OAuthClient], error) {
	cursor, limit := listParams(opts)
	resp, err := a.api().ApplicationAdminServiceListApplications(ctx,
		&admin.ApplicationAdminServiceListApplicationsParams{Cursor: cursor, Limit: limit})
	return decodeMapped(resp, err, func(p admin.V1OAuthClientPage) PageResponse[OAuthClient] {
		return PageResponse[OAuthClient]{Items: mapAll(deref(p.Items), clientFrom), NextCursor: p.NextCursor}
	})
}

// ─── Roles ────────────────────────────────────────────────────────────────────

// CreateRole creates a realm-level role via the admin API.
func (a *AdminClient) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	parents, err := parseUUIDs(req.ParentRoles)
	if err != nil {
		return nil, err
	}
	resp, err := a.api().AdminCreateRole(ctx, admin.AdminCreateRoleRequest{
		Name:        req.Name,
		Description: optString(req.Description),
		Permissions: optSlice(req.Permissions),
		ParentRoles: parents,
	})
	return decodeMapped(resp, err, roleFrom)
}

// GetRole retrieves a role by ID via the admin API.
func (a *AdminClient) GetRole(ctx context.Context, roleID string) (*Role, error) {
	resp, err := a.api().AdminGetRole(ctx, roleID)
	return decodeMapped(resp, err, roleFrom)
}

// UpdateRole updates a role via the admin API.
func (a *AdminClient) UpdateRole(ctx context.Context, roleID string, req UpdateRoleRequest) (*Role, error) {
	parents, err := parseUUIDs(req.ParentRoles)
	if err != nil {
		return nil, err
	}
	resp, err := a.api().AdminUpdateRole(ctx, roleID, admin.AdminUpdateRoleRequest{
		Name:        req.Name,
		Description: req.Description,
		Permissions: optSlice(req.Permissions),
		ParentRoles: parents,
	})
	return decodeMapped(resp, err, roleFrom)
}

// DeleteRole deletes a role via the admin API.
func (a *AdminClient) DeleteRole(ctx context.Context, roleID string) error {
	resp, err := a.api().AdminDeleteRole(ctx, roleID, nil)
	return decodeResponse(resp, err, nil)
}

// ListRoles lists roles with optional cursor-based pagination.
func (a *AdminClient) ListRoles(ctx context.Context, opts ListOptions) (*PageResponse[Role], error) {
	cursor, limit := intListParams(opts)
	resp, err := a.api().AdminListRoles(ctx, &admin.AdminListRolesParams{Cursor: cursor, Limit: limit})
	return decodeMapped(resp, err, func(p admin.AdminRolePage) PageResponse[Role] {
		return PageResponse[Role]{Items: mapAll(p.Items, roleFrom), NextCursor: p.NextCursor}
	})
}

// ─── Groups ───────────────────────────────────────────────────────────────────

// CreateGroup creates a realm-level group via the admin API.
func (a *AdminClient) CreateGroup(ctx context.Context, req CreateGroupRequest) (*Group, error) {
	resp, err := a.api().AdminCreateGroup(ctx, admin.AdminCreateGroupRequest{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: optString(req.Description),
	})
	return decodeMapped(resp, err, groupFrom)
}

// GetGroup retrieves a group by ID via the admin API.
func (a *AdminClient) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	resp, err := a.api().AdminGetGroup(ctx, groupID)
	return decodeMapped(resp, err, groupFrom)
}

// UpdateGroup updates a group via the admin API.
func (a *AdminClient) UpdateGroup(ctx context.Context, groupID string, req UpdateGroupRequest) (*Group, error) {
	resp, err := a.api().AdminUpdateGroup(ctx, groupID, admin.AdminUpdateGroupRequest{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
	})
	return decodeMapped(resp, err, groupFrom)
}

// DeleteGroup deletes a group via the admin API.
func (a *AdminClient) DeleteGroup(ctx context.Context, groupID string) error {
	resp, err := a.api().AdminDeleteGroup(ctx, groupID)
	return decodeResponse(resp, err, nil)
}

// ListGroups lists groups with optional cursor-based pagination.
func (a *AdminClient) ListGroups(ctx context.Context, opts ListOptions) (*PageResponse[Group], error) {
	cursor, limit := intListParams(opts)
	resp, err := a.api().AdminListGroups(ctx, &admin.AdminListGroupsParams{Cursor: cursor, Limit: limit})
	return decodeMapped(resp, err, func(p admin.AdminGroupPage) PageResponse[Group] {
		return PageResponse[Group]{Items: mapAll(p.Items, groupFrom), NextCursor: p.NextCursor}
	})
}

// ─── Organizations ────────────────────────────────────────────────────────────

// ListOrganizations lists the realm's organizations with cursor-based
// pagination. NextCursor is nil on the last page.
func (a *AdminClient) ListOrganizations(ctx context.Context, opts ListOptions) (*PageResponse[Organization], error) {
	cursor, limit := intListParams(opts)
	var result PageResponse[Organization]
	resp, err := a.api().AdminListOrganizations(ctx, &admin.AdminListOrganizationsParams{Cursor: cursor, Limit: limit})
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateOrganization creates an organization. The server refuses it in the
// system realm.
func (a *AdminClient) CreateOrganization(ctx context.Context, req CreateOrganizationRequest) (*Organization, error) {
	var result Organization
	resp, err := a.api().AdminCreateOrganization(ctx, req)
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetOrganization retrieves an organization by ID.
func (a *AdminClient) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	var result Organization
	resp, err := a.api().AdminGetOrganization(ctx, orgID)
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateOrganization changes the fields set in req; the slug is immutable.
func (a *AdminClient) UpdateOrganization(ctx context.Context, orgID string, req UpdateOrganizationRequest) (*Organization, error) {
	var result Organization
	resp, err := a.api().AdminUpdateOrganization(ctx, orgID, req)
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteOrganization deletes an organization. The server refuses it when a
// member holds admin authority the caller lacks.
func (a *AdminClient) DeleteOrganization(ctx context.Context, orgID string) error {
	resp, err := a.api().AdminDeleteOrganization(ctx, orgID)
	return decodeResponse(resp, err, nil)
}

// ListMemberRoles lists the extra org roles a member holds in an
// organization, by role name.
func (a *AdminClient) ListMemberRoles(ctx context.Context, orgID, userID string) ([]string, error) {
	var result admin.AdminRoleNameList
	resp, err := a.api().AdminListAdditionalRoles(ctx, orgID, userID)
	if err := decodeResponse(resp, err, &result); err != nil {
		return nil, err
	}
	return result.Items, nil
}

// AddMemberRole gives an organization member an extra org role. The user
// must already be a member (409 otherwise).
func (a *AdminClient) AddMemberRole(ctx context.Context, orgID, userID, roleName string) error {
	resp, err := a.api().AdminAddAdditionalRole(ctx, orgID, userID,
		admin.AdminAddAdditionalRoleRequest{RoleName: roleName})
	return decodeResponse(resp, err, nil)
}

// RemoveMemberRole removes an extra org role from an organization member.
func (a *AdminClient) RemoveMemberRole(ctx context.Context, orgID, userID, roleName string) error {
	resp, err := a.api().AdminRemoveAdditionalRole(ctx, orgID, userID, roleName)
	return decodeResponse(resp, err, nil)
}
