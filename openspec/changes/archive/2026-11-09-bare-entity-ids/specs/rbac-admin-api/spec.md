## MODIFIED Requirements

### Requirement: Group membership endpoints
Hearth SHALL serve group membership over HTTP:

| Method and path | Effect |
|-----------------|--------|
| `GET /admin/groups/{id}/members?cursor=...&limit=...` | List members: users and nested groups. |
| `POST /admin/groups/{id}/members` | Add a member. The body is `{"type": "user", "id": "<user uuid>"}` or `{"type": "group", "id": "<group uuid>"}`. The endpoint SHALL also accept the `user_` and `group_` prefixed forms that earlier releases returned. |
| `DELETE /admin/groups/{id}/members/{member_id}?type=user` or `?type=group` | Remove a member. Without `type`, the member is a user. |

#### Scenario: Nest a group
- **WHEN** an admin posts `{"type": "group", "id": "group_..."}` to another group's members
- **THEN** the listed members of the outer group include the nested group

#### Scenario: Remove a nested group
- **WHEN** an admin sends `DELETE /admin/groups/{id}/members/{member_id}?type=group` for a nested group
- **THEN** the nested group is no longer a member

#### Scenario: Remove a user without a type
- **WHEN** an admin sends `DELETE /admin/groups/{id}/members/{member_id}` with no `type`
- **THEN** `member_id` is read as a user, and that user is removed
