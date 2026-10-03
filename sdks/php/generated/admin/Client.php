<?php

namespace Hearth\Generated\Admin;

class Client extends \Hearth\Generated\Admin\Runtime\Client\Client
{
    /**
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1OAuthClientPage|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function applicationAdminServiceListApplications(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\ApplicationAdminServiceListApplications($queryParameters), $fetch);
    }
    /**
     * @param null|\Hearth\Generated\Admin\Model\V1RegisterClientRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1OAuthClient|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function applicationAdminServiceCreateApplication(?\Hearth\Generated\Admin\Model\V1RegisterClientRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\ApplicationAdminServiceCreateApplication($requestBody), $fetch);
    }
    /**
     * @param string $clientId
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function applicationAdminServiceDeleteApplication(string $clientId, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\ApplicationAdminServiceDeleteApplication($clientId), $fetch);
    }
    /**
     * @param string $clientId
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1OAuthClient|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function applicationAdminServiceGetApplication(string $clientId, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\ApplicationAdminServiceGetApplication($clientId), $fetch);
    }
    /**
     * @param string $clientId
     * @param null|\Hearth\Generated\Admin\Model\V1UpdateClientRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1OAuthClient|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function applicationAdminServiceUpdateApplication(string $clientId, ?\Hearth\Generated\Admin\Model\V1UpdateClientRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\ApplicationAdminServiceUpdateApplication($clientId, $requestBody), $fetch);
    }
    /**
     * @param string $clientId
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1OAuthClient|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function applicationAdminServiceRegenerateApplicationSecret(string $clientId, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\ApplicationAdminServiceRegenerateApplicationSecret($clientId), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminUnassignRole(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminUnassignRole($id), $fetch);
    }
    /**
     * Requires `hearth.realm.admin`. Newest first.
     * @param array{
     *    "actor"?: string,
     *    "action"?: string, //An audit action name, e.g. `UserCreated`.
     *    "start_time"?: int, //Microseconds since the Unix epoch.
     *    "end_time"?: int, //Microseconds since the Unix epoch.
     *    "limit"?: int, //Default 50, at most 200.
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminListAuditEventsBadRequestException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminAuditEventList : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListAuditEvents(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListAuditEvents($queryParameters), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminVerifyAudit(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminVerifyAudit(), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminBackupCreate(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminBackupCreate(), $fetch);
    }
    /**
     * @param null|string|resource|\Psr\Http\Message\StreamInterface $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminBackupRestore($requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminBackupRestore($requestBody), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminBootstrapNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminBootstrapPostResponse200 : \Psr\Http\Message\ResponseInterface)
     */
    public function adminBootstrap(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminBootstrap(), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminClusterBootstrap(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminClusterBootstrap(), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminClusterStatus(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminClusterStatus(), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipConflictException
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipUnprocessableEntityException
     * @throws \Hearth\Generated\Admin\Exception\AdminClusterTransferLeadershipServiceUnavailableException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminClusterTransferLeadership(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminClusterTransferLeadership(), $fetch);
    }
    /**
     * `cursor` is a decimal offset; follow `next_cursor` until it is null.
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminGroupPage : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListGroups(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListGroups($queryParameters), $fetch);
    }
    /**
     * @param null|\Hearth\Generated\Admin\Model\AdminCreateGroupRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateGroupConflictException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminGroup : \Psr\Http\Message\ResponseInterface)
     */
    public function adminCreateGroup(?\Hearth\Generated\Admin\Model\AdminCreateGroupRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminCreateGroup($requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminDeleteGroupNotFoundException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminDeleteGroup(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminDeleteGroup($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminGetGroupNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminGroup : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGetGroup(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGetGroup($id), $fetch);
    }
    /**
     * Absent fields are unchanged; `description` null clears it.
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminUpdateGroupRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminUpdateGroupNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminGroup : \Psr\Http\Message\ResponseInterface)
     */
    public function adminUpdateGroup(string $id, ?\Hearth\Generated\Admin\Model\AdminUpdateGroupRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminUpdateGroup($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminListGroupMembersNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminGroupMemberPage : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListGroupMembers(string $id, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListGroupMembers($id, $queryParameters), $fetch);
    }
    /**
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminAddGroupMemberRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminAddGroupMemberBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminAddGroupMemberNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminGroupMembership : \Psr\Http\Message\ResponseInterface)
     */
    public function adminAddGroupMember(string $id, ?\Hearth\Generated\Admin\Model\AdminAddGroupMemberRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminAddGroupMember($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $memberId
     * @param array{
     *    "type"?: string, //Member kind; defaults to `user`.
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminRemoveGroupMemberBadRequestException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminRemoveGroupMember(string $id, string $memberId, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminRemoveGroupMember($id, $memberId, $queryParameters), $fetch);
    }
    /**
     * Body: `{role_id, org_id?}`. Same ceiling and org-existence rules as `POST /admin/users/{id}/roles`. Unassign with `DELETE /admin/assignments/{id}`.
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminAssignGroupRoleForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminAssignGroupRoleNotFoundException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminAssignGroupRole(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminAssignGroupRole($id), $fetch);
    }
    /**
     * Requires `hearth.realm.admin`. `cursor` is a decimal offset; follow `next_cursor` until it is null.
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminOrganizationPage : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListOrganizations(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListOrganizations($queryParameters), $fetch);
    }
    /**
     * Requires `hearth.realm.admin`. Body: `{slug, display_name, member_limit?, mfa_required?, attributes?}`. `mfa_required` (default `false`) makes members need MFA even where the realm does not; it can only tighten. Refused in the system realm.
     * @param null|\Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateOrganizationForbiddenException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminOrganization : \Psr\Http\Message\ResponseInterface)
     */
    public function adminCreateOrganization(?\Hearth\Generated\Admin\Model\AdminCreateOrganizationRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminCreateOrganization($requestBody), $fetch);
    }
    /**
     * Refused when a member holds admin authority in the organization that the caller lacks.
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminDeleteOrganizationForbiddenException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminDeleteOrganization(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminDeleteOrganization($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminGetOrganizationNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminOrganization : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGetOrganization(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGetOrganization($id), $fetch);
    }
    /**
     * Body: `{display_name?, status? (active|suspended), member_limit?, mfa_required?, attributes?}`. A field left out keeps its value. A `slug` is refused with 400 (it is immutable). Suspending is checked against the admin privilege ceiling, like a delete.
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminUpdateOrganizationRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminUpdateOrganizationBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminUpdateOrganizationForbiddenException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminOrganization : \Psr\Http\Message\ResponseInterface)
     */
    public function adminUpdateOrganization(string $id, ?\Hearth\Generated\Admin\Model\AdminUpdateOrganizationRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminUpdateOrganization($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $userId
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRoleNameList : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListAdditionalRoles(string $id, string $userId, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListAdditionalRoles($id, $userId), $fetch);
    }
    /**
     * Body: `{role_name}`. The user must be a member (409 otherwise); a sub-admin may only give roles within its own permissions.
     * @param string $id
     * @param string $userId
     * @param null|\Hearth\Generated\Admin\Model\AdminAddAdditionalRoleRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\AdminAddAdditionalRoleConflictException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminAddAdditionalRole(string $id, string $userId, ?\Hearth\Generated\Admin\Model\AdminAddAdditionalRoleRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminAddAdditionalRole($id, $userId, $requestBody), $fetch);
    }
    /**
     * Checked against the admin privilege ceiling.
     * @param string $id
     * @param string $userId
     * @param string $roleName
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminRemoveAdditionalRole(string $id, string $userId, string $roleName, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminRemoveAdditionalRole($id, $userId, $roleName), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListPermissions(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListPermissions(), $fetch);
    }
    /**
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1RealmPage|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceListRealms(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceListRealms($queryParameters), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceDeleteRealm(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceDeleteRealm($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1Realm|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceGetRealm(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceGetRealm($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGetRealmBranding(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGetRealmBranding($id), $fetch);
    }
    /**
     * @param string $id
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminPatchRealmBranding(string $id, ?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminPatchRealmBranding($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListRealmEmailTemplates(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListRealmEmailTemplates($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $kind
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminDeleteRealmEmailTemplate(string $id, string $kind, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminDeleteRealmEmailTemplate($id, $kind), $fetch);
    }
    /**
     * @param string $id
     * @param string $kind
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGetRealmEmailTemplate(string $id, string $kind, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGetRealmEmailTemplate($id, $kind), $fetch);
    }
    /**
     * @param string $id
     * @param string $kind
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminPutRealmEmailTemplate(string $id, string $kind, ?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminPutRealmEmailTemplate($id, $kind, $requestBody), $fetch);
    }
    /**
     * Publishes a new signing key and revokes every retired key for the realm. Tokens signed with the old key stop validating immediately, which is what makes this a usable remedy for a leaked key. A planned rotation may opt into a grace window with `grace_period_secs`; do not use it after a compromise, because the window protects whoever holds the leaked key too.
     * @param string $id
     * @param array{
     *    "grace_period_secs"?: int, //Seconds the retired key stays valid. Omit, or pass 0, to revoke it immediately. A value that is not a non-negative integer is rejected with 400.
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminRotateRealmSigningKeyBadRequestException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminRotateRealmSigningKey(string $id, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminRotateRealmSigningKey($id, $queryParameters), $fetch);
    }
    /**
     * Every token of the realm stops validating, its sessions are revoked and no new session starts until the realm is reinstated. Caller must be a system-realm admin (`hearth.realm.admin` or `hearth.admin`, with `X-Realm-ID` set to the system realm); the target realm's cross-realm trust policy applies. The system realm cannot be suspended. Audited in the target realm with the actor and old/new status. YAML reconciliation never clears a suspension.
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceSuspendRealmConflictException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1Realm : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceSuspendRealm(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceSuspendRealm($id), $fetch);
    }
    /**
     * Restores a suspended realm to active. Same gate as suspend. An archived realm is not revived (409): only reappearing in hearth.yaml does that.
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\IdentityAdminServiceUnsuspendRealmConflictException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1Realm : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceUnsuspendRealm(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceUnsuspendRealm($id), $fetch);
    }
    /**
     * @param string $realmId
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminPatchRealmConfig(string $realmId, ?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminPatchRealmConfig($realmId, $requestBody), $fetch);
    }
    /**
     * @param string $realmId
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminSvBumpAll(string $realmId, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminSvBumpAll($realmId), $fetch);
    }
    /**
     * @param string $realmId
     * @param string $userId
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminPatchUserRequiredActions(string $realmId, string $userId, ?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminPatchUserRequiredActions($realmId, $userId, $requestBody), $fetch);
    }
    /**
     * Requires `hearth.realm.admin`. Follow `next_cursor` until it is null.
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRolePage : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListRoles(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListRoles($queryParameters), $fetch);
    }
    /**
     * @param null|\Hearth\Generated\Admin\Model\AdminCreateRoleRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateRoleBadRequestException
     * @throws \Hearth\Generated\Admin\Exception\AdminCreateRoleConflictException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRole : \Psr\Http\Message\ResponseInterface)
     */
    public function adminCreateRole(?\Hearth\Generated\Admin\Model\AdminCreateRoleRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminCreateRole($requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param array{
     *    "cascade"?: bool, //Also remove the role's assignments, parent links and extra org-role rows. Without it a referenced role answers `409 role_in_use`.
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminDeleteRoleNotFoundException
     * @throws \Hearth\Generated\Admin\Exception\AdminDeleteRoleConflictException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminDeleteRole(string $id, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminDeleteRole($id, $queryParameters), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminGetRoleNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRole : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGetRole(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGetRole($id), $fetch);
    }
    /**
     * Absent fields are unchanged; `description` null clears it.
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminUpdateRoleRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminUpdateRoleNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRole : \Psr\Http\Message\ResponseInterface)
     */
    public function adminUpdateRole(string $id, ?\Hearth\Generated\Admin\Model\AdminUpdateRoleRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminUpdateRole($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListRoleMembers(string $id, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListRoleMembers($id, $queryParameters), $fetch);
    }
    /**
     * @param string $sessionId
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminSvBumpSession(string $sessionId, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminSvBumpSession($sessionId), $fetch);
    }
    /**
     * @param array{
     *    "cursor"?: string,
     *    "limit"?: int,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1UserPage|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceListUsers(array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceListUsers($queryParameters), $fetch);
    }
    /**
     * @param null|\Hearth\Generated\Admin\Model\V1CreateUserRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1User|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceCreateUser(?\Hearth\Generated\Admin\Model\V1CreateUserRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceCreateUser($requestBody), $fetch);
    }
    /**
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminBulkUsers(?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminBulkUsers($requestBody), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminExportUsers(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminExportUsers(), $fetch);
    }
    /**
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminImportUsers(?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminImportUsers($requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceDeleteUser(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceDeleteUser($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1User|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceGetUser(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceGetUser($id), $fetch);
    }
    /**
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\V1UpdateUserRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1User|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function identityAdminServiceUpdateUser(string $id, ?\Hearth\Generated\Admin\Model\V1UpdateUserRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\IdentityAdminServiceUpdateUser($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListUserPermissions(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListUserPermissions($id), $fetch);
    }
    /**
     * Body: `{permission, org_id?}`. A sub-admin may grant only a permission it holds; `granted_by` is the caller.
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminGrantUserPermissionForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminGrantUserPermissionNotFoundException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGrantUserPermission(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGrantUserPermission($id), $fetch);
    }
    /**
     * Add `?org_id=` for an org-scoped grant. Checked against the admin privilege ceiling.
     * @param string $id
     * @param string $permission
     * @param array{
     *    "org_id"?: string,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminRevokeUserPermissionForbiddenException
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminRevokeUserPermission(string $id, string $permission, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminRevokeUserPermission($id, $permission, $queryParameters), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminListUserAssignmentsNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRoleAssignmentList : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListUserAssignments(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListUserAssignments($id), $fetch);
    }
    /**
     * Realm-wide, or inside one organization when `org_id` is set.
     * @param string $id
     * @param null|\Hearth\Generated\Admin\Model\AdminAssignRoleRequest $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     * @throws \Hearth\Generated\Admin\Exception\AdminAssignUserRoleForbiddenException
     * @throws \Hearth\Generated\Admin\Exception\AdminAssignUserRoleNotFoundException
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\AdminRoleAssignment : \Psr\Http\Message\ResponseInterface)
     */
    public function adminAssignUserRole(string $id, ?\Hearth\Generated\Admin\Model\AdminAssignRoleRequest $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminAssignUserRole($id, $requestBody), $fetch);
    }
    /**
     * @param string $userId
     * @param array{
     *    "realm_id"?: string,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1ListUserConsentsResponse|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function rbacAdminServiceListUserConsents(string $userId, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\RbacAdminServiceListUserConsents($userId, $queryParameters), $fetch);
    }
    /**
     * @param string $userId
     * @param string $clientId
     * @param array{
     *    "realm_id"?: string,
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function rbacAdminServiceRevokeConsent(string $userId, string $clientId, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\RbacAdminServiceRevokeConsent($userId, $clientId, $queryParameters), $fetch);
    }
    /**
     * @param string $userId
     * @param array{
     *    "realm_id"?: string,
     *    "org_id"?: string, //optional; empty means realm-only
     *    "scope"?: string, //optional; empty means no narrowing
     * } $queryParameters
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null|\Hearth\Generated\Admin\Model\V1ResolveEffectivePermissionsResponse|\Hearth\Generated\Admin\Model\RpcStatus : \Psr\Http\Message\ResponseInterface)
     */
    public function rbacAdminServiceResolveEffectivePermissions(string $userId, array $queryParameters = [], string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\RbacAdminServiceResolveEffectivePermissions($userId, $queryParameters), $fetch);
    }
    /**
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListWebhooks(string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListWebhooks(), $fetch);
    }
    /**
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminCreateWebhook(?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminCreateWebhook($requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminDeleteWebhook(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminDeleteWebhook($id), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminGetWebhook(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminGetWebhook($id), $fetch);
    }
    /**
     * @param string $id
     * @param null|\stdClass $requestBody
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminUpdateWebhook(string $id, ?\stdClass $requestBody = null, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminUpdateWebhook($id, $requestBody), $fetch);
    }
    /**
     * @param string $id
     * @param string $fetch Fetch mode to use (can be OBJECT or RESPONSE)
     *
     * @return ($fetch is 'object' ? null : \Psr\Http\Message\ResponseInterface)
     */
    public function adminListWebhookDeliveries(string $id, string $fetch = self::FETCH_OBJECT)
    {
        return $this->executeEndpoint(new \Hearth\Generated\Admin\Endpoint\AdminListWebhookDeliveries($id), $fetch);
    }
    public static function create($httpClient = null, array $additionalPlugins = [], array $additionalNormalizers = [])
    {
        if (null === $httpClient) {
            $httpClient = \Http\Discovery\Psr18ClientDiscovery::find();
            $plugins = [];
            if (count($additionalPlugins) > 0) {
                $plugins = array_merge($plugins, $additionalPlugins);
            }
            $httpClient = new \Http\Client\Common\PluginClient($httpClient, $plugins);
        }
        $requestFactory = \Http\Discovery\Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = \Http\Discovery\Psr17FactoryDiscovery::findStreamFactory();
        $normalizers = [new \Symfony\Component\Serializer\Normalizer\ArrayDenormalizer(), new \Hearth\Generated\Admin\Normalizer\JaneObjectNormalizer()];
        if (count($additionalNormalizers) > 0) {
            $normalizers = array_merge($normalizers, $additionalNormalizers);
        }
        $serializer = new \Symfony\Component\Serializer\Serializer($normalizers, [new \Symfony\Component\Serializer\Encoder\JsonEncoder(new \Symfony\Component\Serializer\Encoder\JsonEncode(), new \Symfony\Component\Serializer\Encoder\JsonDecode(['json_decode_associative' => true])), new \Hearth\Generated\Admin\Runtime\Client\FormEncoder()]);
        return new static($httpClient, $requestFactory, $serializer, $streamFactory);
    }
}