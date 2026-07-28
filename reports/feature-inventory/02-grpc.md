## gRPC Services & Methods

Code-derived inventory of every gRPC service and RPC in the Hearth repo. Sources: `proto/hearth/**/*.proto` (definitions) and tonic server impls under `src/protocol/grpc/` and `src/cluster/`. `oauth.proto` defines only messages (no service).

Proto packages: `hearth.identity.v1`, `hearth.rbac.v1`, `hearth.events.v1`, `hearth.cluster.v1`.

---

### IdentityAdminService (`hearth.identity.v1`)

Impl: `src/protocol/grpc/identity.rs:96` (`impl IdentityAdminService for IdentityAdminSvc`). Admin interceptor: bearer token + RBAC admin check, realm via `x-realm-id` metadata, 100 req/min. Proto: `proto/hearth/identity/v1/identity.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| IdentityAdminService.ListUsers | ListUsersRequest → UserPage | identity.proto:390 | grpc/identity.rs:96 | AUTHORIZATION.md; grpc mgmt API notes |
| IdentityAdminService.GetUser | GetUserRequest → User | identity.proto:393 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.CreateUser | CreateUserRequest → User | identity.proto:396 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.UpdateUser | UpdateUserCall → User | identity.proto:402 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.DeleteUser | DeleteUserRequest → Empty | identity.proto:408 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.ListRealms | ListRealmsRequest → RealmPage | identity.proto:414 | grpc/identity.rs:96 | grpc mgmt API notes (system realm) |
| IdentityAdminService.GetRealm | GetRealmRequest → Realm | identity.proto:417 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.CreateRealm | CreateRealmRequest → Realm | identity.proto:420 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.UpdateRealm | UpdateRealmCall → Realm | identity.proto:426 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.DeleteRealm | DeleteRealmRequest → Empty | identity.proto:432 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.ListOrganizations | ListOrganizationsRequest → OrganizationPage | identity.proto:437 | grpc/identity.rs:96 | gRPC-only (HEA-969); grpc mgmt API notes |
| IdentityAdminService.GetOrganization | GetOrganizationRequest → Organization | identity.proto:438 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.CreateOrganization | CreateOrganizationRequest → Organization | identity.proto:439 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.UpdateOrganization | UpdateOrganizationCall → Organization | identity.proto:440 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.DeleteOrganization | DeleteOrganizationRequest → Empty | identity.proto:441 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.ListAgents | ListAgentsRequest → AgentPage | identity.proto:444 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A (HEA-1405) |
| IdentityAdminService.GetAgent | GetAgentRequest → Agent | identity.proto:447 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.CreateAgent | CreateAgentRequest → Agent | identity.proto:450 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.UpdateAgent | UpdateAgentCall → Agent | identity.proto:456 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.DeleteAgent | DeleteAgentRequest → Empty | identity.proto:462 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.CreateAgentApiKey | CreateAgentApiKeyRequest → CreateAgentApiKeyResponse | identity.proto:465 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.ListAgentCredentials | ListAgentCredentialsRequest → AgentCredentialPage | identity.proto:471 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.RevokeAgentCredential | RevokeAgentCredentialRequest → Empty | identity.proto:474 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |

### RbacAdminService (`hearth.rbac.v1`)

Impl: `src/protocol/grpc/rbac_admin.rs:293`. No service-to-service Check RPC — callers decode the JWT `permissions` claim locally. Proto: `proto/hearth/rbac/v1/rbac.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| RbacAdminService.ListRoles | ListRolesRequest → ListRolesResponse | rbac.proto:13 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.CreateRole | CreateRoleRequest → Role | rbac.proto:16 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.GetRole | GetRoleRequest → Role | rbac.proto:22 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.UpdateRole | UpdateRoleRequest → Role | rbac.proto:25 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.DeleteRole | DeleteRoleRequest → DeleteRoleResponse | rbac.proto:31 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.ListGroups | ListGroupsRequest → ListGroupsResponse | rbac.proto:35 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.CreateGroup | CreateGroupRequest → Group | rbac.proto:38 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.GetGroup | GetGroupRequest → Group | rbac.proto:44 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.UpdateGroup | UpdateGroupRequest → Group | rbac.proto:47 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.DeleteGroup | DeleteGroupRequest → DeleteGroupResponse | rbac.proto:53 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.ListGroupMembers | ListGroupMembersRequest → ListGroupMembersResponse | rbac.proto:57 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.AddGroupMember | AddGroupMemberRequest → GroupMembership | rbac.proto:60 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.RemoveGroupMember | RemoveGroupMemberRequest → RemoveGroupMemberResponse | rbac.proto:66 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.AssignUserRole | AssignUserRoleRequest → RoleAssignment | rbac.proto:70 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.UnassignUserRole | UnassignUserRoleRequest → UnassignUserRoleResponse | rbac.proto:76 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.ListUserAssignments | ListUserAssignmentsRequest → ListUserAssignmentsResponse | rbac.proto:79 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.AssignGroupRole | AssignGroupRoleRequest → RoleAssignment | rbac.proto:85 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.UnassignGroupRole | UnassignGroupRoleRequest → UnassignGroupRoleResponse | rbac.proto:86 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListRoleMembers | ListRoleMembersRequest → ListRoleMembersResponse | rbac.proto:87 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ResolveEffectivePermissions | ResolveEffectivePermissionsRequest → ResolveEffectivePermissionsResponse | rbac.proto:89 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.GrantUserPermission | GrantUserPermissionRequest → GrantUserPermissionResponse | rbac.proto:95 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969); AUTHZ_EXPANSION.md |
| RbacAdminService.RevokeUserPermission | RevokeUserPermissionRequest → RevokeUserPermissionResponse | rbac.proto:96 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969); AUTHZ_EXPANSION.md |
| RbacAdminService.ListUserPermissions | ListUserPermissionsRequest → ListUserPermissionsResponse | rbac.proto:97 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.AddAdditionalRole | AddAdditionalRoleRequest → AddAdditionalRoleResponse | rbac.proto:101 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.RemoveAdditionalRole | RemoveAdditionalRoleRequest → RemoveAdditionalRoleResponse | rbac.proto:102 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListAdditionalRoles | ListAdditionalRolesRequest → ListAdditionalRolesResponse | rbac.proto:103 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListRealmPermissions | ListRealmPermissionsRequest → ListRealmPermissionsResponse | rbac.proto:106 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListRealmRoles | ListRealmRolesRequest → ListRealmRolesResponse | rbac.proto:107 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.RevokeConsent | RevokeConsentRequest → RevokeConsentResponse | rbac.proto:112 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md; OIDC.md (consent) |
| RbacAdminService.ListUserConsents | ListUserConsentsRequest → ListUserConsentsResponse | rbac.proto:117 | grpc/rbac_admin.rs:293 | OIDC.md (consent) |

### AuditService (`hearth.events.v1`)

Impl: `src/protocol/grpc/audit.rs:26`. Proto: `proto/hearth/events/v1/audit.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| AuditService.ListEvents | AuditQuery → AuditEventPage | audit.proto:205 | grpc/audit.rs:26 | grpc mgmt API notes |
| AuditService.VerifyIntegrity | VerifyIntegrityRequest → VerifyIntegrityResponse | audit.proto:209 | grpc/audit.rs:26 | gRPC-only (audit hash chain) |

### RaftService (`hearth.cluster.v1`)

Impl: `src/cluster/server.rs:65` (`impl<D: IncomingRpcDispatch> RaftService for RaftRpcHandler<D>`). Internal peer-to-peer consensus (openraft); not a public/admin API. Proto: `proto/hearth/cluster/v1/raft.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| RaftService.AppendEntries | AppendEntriesRequest → AppendEntriesResponse | raft.proto:19 | cluster/server.rs:65 | ARCHITECTURE.md (Cluster layer) |
| RaftService.Vote | VoteRequest → VoteResponse | raft.proto:22 | cluster/server.rs:65 | ARCHITECTURE.md (Cluster layer) |
| RaftService.InstallSnapshot | InstallSnapshotRequest → InstallSnapshotResponse | raft.proto:26 | cluster/server.rs:65 | ARCHITECTURE.md (Cluster layer) |

---

### Summary

- **Services:** 4 (IdentityAdminService, RbacAdminService, AuditService, RaftService).
- **Total RPCs:** 60 (Identity 22, Rbac 29, Audit 2, Raft 3).
- **RPCs without a server impl:** none. Every RPC is served by one of the four `impl … Service` blocks found in `src/protocol/grpc/{identity,rbac_admin,audit}.rs` and `src/cluster/server.rs`.
- `proto/hearth/identity/v1/oauth.proto` defines OAuth message types only (no service); OAuth/OIDC flows are served over REST, not gRPC.
- Several RPCs are gRPC-only (no REST `google.api.http` binding), tracked under HEA-969.
