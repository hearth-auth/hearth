## ADDED Requirements

### Requirement: Tool permissions are RBAC permissions
Tool invocation permissions SHALL be RBAC permission strings granted through role assignments. They SHALL reuse Hearth's RBAC engine, with no tool-specific authorization machinery. An admin creates a role that includes the relevant `tool.*` permissions and assigns it to a principal, or to a group the principal belongs to. The permissions SHALL then appear in the principal's resolved claim set at token issuance.

#### Scenario: A role grants tool access
- **WHEN** an admin defines the role below and assigns `email.editor` to a principal
- **THEN** the principal's next access token carries `tool.send_email.invoke`, `tool.search_emails.invoke` and `tool.delete_email.invoke_with_approval`
- **AND** a tool check for that token allows sending and searching without approval, and deleting only with approval

```yaml
roles:
  - name: email.editor
    permissions:
      - tool.send_email.invoke
      - tool.search_emails.invoke
      - tool.delete_email.invoke_with_approval
```

### Requirement: The tool permission grammar
A tool permission SHALL follow this naming convention in the realm's permission namespace.

| Permission | Meaning |
|---|---|
| `tool.{name}.invoke` | The holder may invoke the tool without human approval. |
| `tool.{name}.invoke_with_approval` | The holder may invoke the tool only with human approval. |
| `tool.{name}.deny` | The holder is explicitly denied the tool. It takes precedence over every other grant. |

Tool groups SHALL use the same three actions with a `toolgroup.{name}.*` prefix. A role that grants `toolgroup.email_suite.invoke` gives access to every tool in the `email_suite` group. There SHALL be no other tool action. In particular there is no `tool.{name}.delegate` permission: delegation goes through token exchange.

#### Scenario: A group grant
- **WHEN** a token carries `toolgroup.email_suite.invoke` and `email_suite` contains `send_email`
- **THEN** the tool check allows `send_email`

#### Scenario: An unknown action
- **WHEN** a token carries `tool.send_email.delegate` and no other `tool.send_email.*` permission
- **THEN** the tool check denies `send_email`

#### Scenario: No matching permission
- **WHEN** a token carries no `tool.*` or `toolgroup.*` permission that covers a tool
- **THEN** the tool check denies that tool

### Requirement: Tool groups are realm configuration
Tool-to-group membership SHALL be recorded as a realm-config mapping in the tool registry (`tool_registry.groups`), not as RBAC state. Membership is a static deployment concern, not a per-principal grant. Tools SHALL be added to or removed from a group through realm config, without rewriting any RBAC state.

#### Scenario: A tool leaves a group
- **WHEN** an operator removes `send_email` from `email_suite` in `tool_registry.groups` and reloads
- **THEN** a token that holds only `toolgroup.email_suite.invoke` no longer passes the tool check for `send_email`
- **AND** no role or assignment was changed

### Requirement: Deny wins
`tool.{name}.deny` in a resolved claim set MUST make invocation of that tool fail, even when `tool.{name}.invoke` is also present. Evaluation SHALL check deny first. A deny reached through a tool group SHALL win in the same way.

#### Scenario: Invoke and deny together
- **WHEN** a token carries both `tool.send_email.invoke` and `tool.send_email.deny`
- **THEN** the tool check denies `send_email`

#### Scenario: A group deny beats a direct grant
- **WHEN** a token carries `tool.send_email.invoke` and `toolgroup.email_suite.deny`, and `email_suite` contains `send_email`
- **THEN** the tool check denies `send_email`

### Requirement: Tool checks read the access token's permissions claim
A tool permission check MUST use the `permissions` claim of the presented access token, not a separate API call. Permission resolution SHALL run at token issuance, so a tool invocation needs no network round trip for authorization.

#### Scenario: A grant changes after issuance
- **WHEN** an admin removes `tool.send_email.invoke` from a principal's role after its token was issued
- **THEN** the check for that token still reads the `permissions` claim the token carries
- **AND** the principal's next token no longer carries the permission

### Requirement: Argument constraints stay out of permission strings
Argument-level constraints MUST NOT be encoded in a permission string. A permission string SHALL answer only "may the holder invoke this tool at all". Argument-level enforcement SHALL be done by AAT validation.

#### Scenario: A constraint is needed
- **WHEN** an operator wants calls to `search_files` limited to 100 results
- **THEN** the role grants `tool.search_files.invoke`
- **AND** the limit is carried as an AAT constraint such as `{"max_results": 100}`, not in the permission string
