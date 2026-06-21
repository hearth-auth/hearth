//! Tool-level permission grammar and evaluation (AGENT_AUTH.md §5).
//!
//! Permission convention:
//! - `tool.{name}.invoke` — may invoke without approval.
//! - `tool.{name}.invoke_with_approval` — requires human approval.
//! - `tool.{name}.deny` — explicitly denied; overrides any grant.
//!
//! Tool groups use `toolgroup.{group}.{action}` and map to member tools via
//! a realm-config `ToolGroupMap` (a static deployment concern, not RBAC state).
//!
//! Evaluation order: **deny wins**. If the effective permission set contains a
//! `deny` for the tool (directly or via a group), the decision is always
//! `Deny`, regardless of other grants.

use std::collections::HashMap;

// ─── Types ───────────────────────────────────────────────────────────────────

/// The three possible per-tool permission kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolPermissionKind {
    /// Agent may invoke the tool without approval.
    Invoke,
    /// Agent must obtain human approval before invocation.
    InvokeWithApproval,
    /// Agent is explicitly denied access (highest precedence).
    Deny,
}

/// Outcome of `evaluate_tool_access`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAccessDecision {
    /// Invocation is allowed without further action.
    Allow,
    /// Invocation requires a human-approved capability token.
    RequireApproval,
    /// Invocation is denied; no path to invoke exists.
    Deny,
}

/// Mapping from tool-group name to the set of tool names it contains.
///
/// Populated from realm config (YAML `tool_registry.groups`); not an RBAC
/// concept.  An empty map disables all group-based grants.
pub type ToolGroupMap = HashMap<String, Vec<String>>;

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Parses a `tool.{name}.{action}` permission string.
///
/// Returns `Some((tool_name, kind))` when the string matches the `tool.*`
/// namespace and carries a recognized action.  Returns `None` otherwise —
/// callers should treat non-`tool.*` permissions as unrelated grants.
///
/// # Format
/// `tool.{name}.invoke` | `tool.{name}.invoke_with_approval` | `tool.{name}.deny`
pub fn parse_tool_permission(perm: &str) -> Option<(String, ToolPermissionKind)> {
    let rest = perm.strip_prefix("tool.")?;
    // Must have exactly two dots remaining: name.action
    let dot = rest.rfind('.')?;
    if dot == 0 {
        return None; // empty tool name
    }
    let tool_name = &rest[..dot];
    let action = &rest[dot + 1..];
    if tool_name.is_empty() || action.is_empty() {
        return None;
    }
    let kind = match action {
        "invoke" => ToolPermissionKind::Invoke,
        "invoke_with_approval" => ToolPermissionKind::InvokeWithApproval,
        "deny" => ToolPermissionKind::Deny,
        _ => return None,
    };
    Some((tool_name.to_string(), kind))
}

/// Parses a `toolgroup.{group}.{action}` permission string.
///
/// Returns `Some((group_name, kind))` when the string matches the
/// `toolgroup.*` namespace.  Returns `None` otherwise.
pub fn parse_toolgroup_permission(perm: &str) -> Option<(String, ToolPermissionKind)> {
    let rest = perm.strip_prefix("toolgroup.")?;
    let dot = rest.rfind('.')?;
    if dot == 0 {
        return None;
    }
    let group_name = &rest[..dot];
    let action = &rest[dot + 1..];
    if group_name.is_empty() || action.is_empty() {
        return None;
    }
    let kind = match action {
        "invoke" => ToolPermissionKind::Invoke,
        "invoke_with_approval" => ToolPermissionKind::InvokeWithApproval,
        "deny" => ToolPermissionKind::Deny,
        _ => return None,
    };
    Some((group_name.to_string(), kind))
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

/// Evaluates whether the caller may invoke `tool_name` given its resolved
/// permission set and the realm's tool-group mapping.
///
/// **Deny wins** — a `deny` for the tool (via direct permission or group
/// membership) produces `Deny` regardless of any co-present `invoke` grant.
///
/// Evaluation proceeds in three passes:
/// 1. Direct `tool.{name}.*` permissions for the requested tool.
/// 2. `toolgroup.{group}.*` permissions where the tool is a group member.
/// 3. Absence of any matching permission yields `Deny`.
pub fn evaluate_tool_access(
    permissions: &[String],
    tool_name: &str,
    groups: &ToolGroupMap,
) -> ToolAccessDecision {
    let mut best = ToolAccessDecision::Deny;
    let mut has_any = false;

    // --- Pass 1: direct tool.* permissions ---
    for perm in permissions {
        if let Some((perm_tool, kind)) = parse_tool_permission(perm) {
            if perm_tool != tool_name {
                continue;
            }
            has_any = true;
            match kind {
                ToolPermissionKind::Deny => {
                    // Deny is terminal — return immediately.
                    return ToolAccessDecision::Deny;
                }
                ToolPermissionKind::Invoke => {
                    best = ToolAccessDecision::Allow;
                }
                ToolPermissionKind::InvokeWithApproval => {
                    if best != ToolAccessDecision::Allow {
                        best = ToolAccessDecision::RequireApproval;
                    }
                }
            }
        }
    }

    // --- Pass 2: toolgroup.* permissions ---
    for perm in permissions {
        if let Some((group_name, kind)) = parse_toolgroup_permission(perm) {
            let members = match groups.get(&group_name) {
                Some(m) => m,
                None => continue,
            };
            if !members.iter().any(|m| m == tool_name) {
                continue;
            }
            has_any = true;
            match kind {
                ToolPermissionKind::Deny => {
                    return ToolAccessDecision::Deny;
                }
                ToolPermissionKind::Invoke => {
                    best = ToolAccessDecision::Allow;
                }
                ToolPermissionKind::InvokeWithApproval => {
                    if best != ToolAccessDecision::Allow {
                        best = ToolAccessDecision::RequireApproval;
                    }
                }
            }
        }
    }

    if has_any {
        best
    } else {
        // No matching permission at all — implicit deny.
        ToolAccessDecision::Deny
    }
}

// ─── Scope intersection utility ──────────────────────────────────────────────

/// Filters a space-delimited scope string to keep only `tool.*` and
/// `toolgroup.*` scopes — the actor's effective tool-permission scope.
///
/// Used to narrow the RFC 8693 scope intersection to tool-relevant
/// capabilities when the actor is an agent (C.3 scope attenuation).
#[allow(dead_code)]
pub fn extract_tool_scopes(scope: &str) -> String {
    scope
        .split_whitespace()
        .filter(|s| s.starts_with("tool.") || s.starts_with("toolgroup."))
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invoke() {
        let (name, kind) = parse_tool_permission("tool.send_email.invoke").expect("should parse");
        assert_eq!(name, "send_email");
        assert_eq!(kind, ToolPermissionKind::Invoke);
    }

    #[test]
    fn parse_invoke_with_approval() {
        let (name, kind) =
            parse_tool_permission("tool.delete_file.invoke_with_approval").expect("should parse");
        assert_eq!(name, "delete_file");
        assert_eq!(kind, ToolPermissionKind::InvokeWithApproval);
    }

    #[test]
    fn parse_deny() {
        let (name, kind) = parse_tool_permission("tool.dangerous.deny").expect("should parse");
        assert_eq!(name, "dangerous");
        assert_eq!(kind, ToolPermissionKind::Deny);
    }

    #[test]
    fn parse_rejects_unknown_action() {
        assert!(parse_tool_permission("tool.foo.read").is_none());
    }

    #[test]
    fn parse_rejects_non_tool_prefix() {
        assert!(parse_tool_permission("openid").is_none());
        assert!(parse_tool_permission("toolgroup.g.invoke").is_none());
    }

    #[test]
    fn parse_toolgroup_invoke() {
        let (g, k) =
            parse_toolgroup_permission("toolgroup.email_suite.invoke").expect("should parse");
        assert_eq!(g, "email_suite");
        assert_eq!(k, ToolPermissionKind::Invoke);
    }

    #[test]
    fn deny_wins_property() {
        let tools = ["send_email", "delete_file", "search_db"];
        for tool in tools {
            let perms = vec![
                format!("tool.{tool}.invoke"),
                format!("tool.{tool}.deny"),
                format!("tool.{tool}.invoke_with_approval"),
            ];
            let d = evaluate_tool_access(&perms, tool, &ToolGroupMap::default());
            assert_eq!(d, ToolAccessDecision::Deny, "deny must win for {tool}");
        }
    }

    #[test]
    fn group_deny_wins() {
        let mut groups = ToolGroupMap::default();
        groups.insert("suite".to_string(), vec!["tool_a".to_string()]);
        let perms = vec![
            "tool.tool_a.invoke".to_string(),
            "toolgroup.suite.deny".to_string(),
        ];
        let d = evaluate_tool_access(&perms, "tool_a", &groups);
        assert_eq!(d, ToolAccessDecision::Deny);
    }
}
