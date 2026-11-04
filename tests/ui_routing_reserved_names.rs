//! #631 (OpenSpec `fix-spec-drift-defects` tasks 9.1 and 9.2).
//!
//! - R-4: every first-segment keyword of an admin route under
//!   `/ui/admin/realms/{realm}/` is a reserved realm name, so no realm can take
//!   a name that collides with an admin route.
//! - R-8: no admin template emits a realm-scoped admin URL without a realm,
//!   also in a branch that does not render today.

mod common;

use std::path::{Path, PathBuf};

use hearth::identity::{CreateRealmRequest, IdentityError};

/// Every file with the extension `extension` under `dir` and its subdirectories.
fn files_under(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            files_under(&path, extension, out);
        } else if path.extension().is_some_and(|e| e == extension) {
            out.push(path);
        }
    }
}

/// The literal first segments after `"/admin/realms/{<param>}/` in the web
/// router sources. The router nests these routes under `/ui`.
fn admin_route_keywords() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/web");
    let mut files = Vec::new();
    files_under(&root, "rs", &mut files);
    let mut keywords = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).expect("read source");
        for (at, _) in source.match_indices("\"/admin/realms/{") {
            let rest = &source[at + "\"/admin/realms/{".len()..];
            let Some(close) = rest.find('}') else {
                continue;
            };
            let Some(after) = rest[close + 1..].strip_prefix('/') else {
                continue;
            };
            let keyword: String = after
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            if !keyword.is_empty() && !keywords.contains(&keyword) {
                keywords.push(keyword);
            }
        }
    }
    keywords.sort();
    keywords
}

/// Scenarios "Every route keyword is reserved" and "Regression — route
/// keywords missing from the reserved set" (`webhooks`, `config`,
/// `identity-providers`, `abuse`, `approvals`).
#[tokio::test]
async fn r4_every_admin_route_keyword_is_a_reserved_realm_name() {
    let keywords = admin_route_keywords();
    assert!(
        keywords.len() >= 15 && keywords.iter().any(|k| k == "users"),
        "the route scan found too few keywords: {keywords:?}"
    );

    let h = common::TestHarness::in_process().await.expect("setup");
    let mut accepted = Vec::new();
    for keyword in &keywords {
        let result = h.identity().create_realm(&CreateRealmRequest {
            name: keyword.clone(),
            config: None,
        });
        match result {
            Err(IdentityError::InvalidInput { reason }) if reason.contains("reserved") => {}
            Ok(_) => accepted.push(format!("{keyword}: created")),
            Err(e) => accepted.push(format!("{keyword}: {e:?}")),
        }
    }
    assert!(
        accepted.is_empty(),
        "admin route keywords that are not reserved realm names: {accepted:#?}"
    );
}

/// The realm-scoped keywords of R-8.
const REALM_SCOPED: &[&str] = &[
    "users",
    "groups",
    "organizations",
    "applications",
    "sessions",
    "audit",
    "rbac",
    "permissions",
];

/// Scenario "Regression — realm-less sessions filter links": the template
/// source is scanned, so a branch that does not render today counts too.
#[test]
fn r8_no_admin_template_emits_a_realm_less_link() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/ui");
    let mut files = Vec::new();
    files_under(&root, "html", &mut files);
    assert!(!files.is_empty(), "no templates under {}", root.display());

    let mut found = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("read template");
        for (number, line) in source.lines().enumerate() {
            for keyword in REALM_SCOPED {
                let url = format!("/ui/admin/{keyword}");
                for (at, _) in line.match_indices(&url) {
                    let next = line[at + url.len()..].chars().next();
                    if matches!(next, None | Some('/' | '?' | '"' | '\'' | '#' | ' ')) {
                        found.push(format!(
                            "{}:{}: {}",
                            file.strip_prefix(&root).unwrap_or(file).display(),
                            number + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "admin templates emit realm-less URLs: {found:#?}"
    );
}
