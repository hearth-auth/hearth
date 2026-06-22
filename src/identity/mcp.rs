//! MCP (Model Context Protocol) authorization helpers.
//!
//! Validates MCP scope strings per AGENT_AUTH.md §2.6 and RFC 9728 conventions.

/// Well-known MCP scopes defined in AGENT_AUTH.md §2.6.
pub const MCP_SCOPE_TOOLS_INVOKE: &str = "mcp:tools:invoke";
pub const MCP_SCOPE_TOOLS_LIST: &str = "mcp:tools:list";
pub const MCP_SCOPE_RESOURCES_READ: &str = "mcp:resources:read";
pub const MCP_SCOPE_RESOURCES_WRITE: &str = "mcp:resources:write";
pub const MCP_SCOPE_PROMPTS_READ: &str = "mcp:prompts:read";

/// All standard MCP scopes supported by Hearth.
pub const MCP_STANDARD_SCOPES: &[&str] = &[
    MCP_SCOPE_TOOLS_INVOKE,
    MCP_SCOPE_TOOLS_LIST,
    MCP_SCOPE_RESOURCES_READ,
    MCP_SCOPE_RESOURCES_WRITE,
    MCP_SCOPE_PROMPTS_READ,
];

/// Validates a single scope string per AGENT_AUTH.md §2.6 MUST rule.
///
/// MCP scopes MUST follow `{namespace}:{category}:{action}` — exactly three
/// colon-separated components, each non-empty and containing only printable
/// ASCII excluding whitespace and control characters.
///
/// # Errors
/// Returns a human-readable error string when the scope is malformed.
pub fn validate_mcp_scope_string(scope: &str) -> Result<(), String> {
    let parts: Vec<&str> = scope.split(':').collect();
    if parts.len() != 3 {
        return Err(format!(
            "MCP scope `{scope}` must have exactly three components separated by `:` \
             (got {}): expected `{{namespace}}:{{category}}:{{action}}`",
            parts.len()
        ));
    }
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(format!(
                "MCP scope `{scope}` has an empty component at position {i}; \
                 all three components must be non-empty"
            ));
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "MCP scope `{scope}` component `{part}` contains invalid characters; \
                 only ASCII alphanumeric, `_`, and `-` are allowed"
            ));
        }
    }
    Ok(())
}

/// Returns `true` if `scope` looks like an MCP scope (starts with `mcp:`).
#[must_use]
pub fn is_mcp_scope(scope: &str) -> bool {
    scope.starts_with("mcp:")
}

/// Computes the intersection of two space-delimited scope strings.
///
/// The result is a sorted, deduplicated, space-delimited scope string
/// containing only scopes present in both inputs. Empty input on either
/// side yields an empty result (no intersection → no grant).
#[must_use]
pub fn intersect_scopes(a: &str, b: &str) -> String {
    use std::collections::BTreeSet;

    let set_a: BTreeSet<&str> = a.split_whitespace().collect();
    let set_b: BTreeSet<&str> = b.split_whitespace().collect();
    let common: Vec<&str> = set_a.intersection(&set_b).copied().collect();
    common.join(" ")
}

/// Computes the three-way intersection (subject ∩ actor ∩ requested).
///
/// Any empty input results in an empty intersection. When `requested` is
/// `None` or empty, falls back to the subject ∩ actor intersection.
#[must_use]
pub fn intersect_three(subject: &str, actor: &str, requested: Option<&str>) -> String {
    let sa = intersect_scopes(subject, actor);
    match requested {
        Some(r) if !r.is_empty() => intersect_scopes(&sa, r),
        _ => sa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_mcp_scope_strings() {
        assert!(validate_mcp_scope_string("mcp:tools:invoke").is_ok());
        assert!(validate_mcp_scope_string("mcp:resources:read").is_ok());
        assert!(validate_mcp_scope_string("custom:ns:action").is_ok());
        assert!(validate_mcp_scope_string("my-ns:my-cat:my-action").is_ok());
    }

    #[test]
    fn invalid_mcp_scope_strings() {
        // Too few components
        assert!(validate_mcp_scope_string("mcp:tools").is_err());
        // Too many components
        assert!(validate_mcp_scope_string("mcp:tools:invoke:extra").is_err());
        // Empty component
        assert!(validate_mcp_scope_string("mcp::invoke").is_err());
        assert!(validate_mcp_scope_string(":tools:invoke").is_err());
        // Invalid character (space)
        assert!(validate_mcp_scope_string("mcp:tools:invoke me").is_err());
        // Invalid character (dot)
        assert!(validate_mcp_scope_string("mcp.tools.invoke").is_err());
    }

    #[test]
    fn scope_intersection() {
        let a = "openid profile email mcp:tools:invoke mcp:resources:read";
        let b = "mcp:tools:invoke mcp:resources:write";
        let result = intersect_scopes(a, b);
        assert_eq!(result, "mcp:tools:invoke");
    }

    #[test]
    fn three_way_intersection() {
        let subject = "openid profile email mcp:tools:invoke mcp:resources:read";
        let actor = "mcp:tools:invoke mcp:resources:read mcp:resources:write";
        let requested = "mcp:tools:invoke";
        let result = intersect_three(subject, actor, Some(requested));
        assert_eq!(result, "mcp:tools:invoke");
    }

    #[test]
    fn empty_intersection_when_no_overlap() {
        let result = intersect_three("openid", "mcp:tools:invoke", Some("mcp:tools:invoke"));
        // subject has no MCP scopes → intersection is empty
        assert!(result.is_empty());
    }

    #[test]
    fn intersection_falls_back_to_subject_actor_when_no_requested() {
        let result = intersect_three("mcp:tools:invoke email", "mcp:tools:invoke", None);
        assert_eq!(result, "mcp:tools:invoke");
    }
}
