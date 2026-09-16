//! Guard: `hearth.maximal.yaml` advertises itself as the maximal example, so
//! every security-relevant key an operator can write MUST actually appear in it
//! (audit 2026-08-28 task 25.24).
//!
//! ## Why this exists
//!
//! Task 20.13 constructed nine abuse guards that had no production constructor
//! and task 20.14 made three WebAuthn realm policies settable; between them they
//! added 38 leaf keys under `security:` and six `webauthn_*` keys. None of them
//! reached `hearth.maximal.yaml`, whose `security:` block still carried four
//! keys out of the 81 the liveness registry knows about. An operator reading the
//! "100% feature-coverage" example therefore could not discover the controls at
//! all — the same class of defect as a key that parses and is read by nothing,
//! seen from the other side.
//!
//! ## What is checked
//!
//! [`SECURITY_KEYS`](../src/config/security_keys.rs) is `pub(crate)`, so this
//! integration test re-derives the key set from the registry's **source text**,
//! exactly as the registry's own test re-derives the field set from `types.rs`.
//! Each dotted path must then appear as a live (uncommented) leaf of
//! `hearth.maximal.yaml`. A commented-out key does not count: an operator cannot
//! see the value a commented key would take, and the parser never sees it either.
//!
//! Shape correctness is *not* re-checked here — `tests/docs_config_snippets.rs`
//! already pushes the whole file through the real parser, including
//! `deny_unknown_fields`. This test asserts coverage; that one asserts validity.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The example config this test holds to its own "maximal" claim.
const MAXIMAL: &str = "hearth.maximal.yaml";

/// The registry whose key set is the bar.
const REGISTRY: &str = "src/config/security_keys.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()))
}

/// Extracts every `security.*` path literal from the `SECURITY_KEYS` table.
///
/// The consumer argument of each entry is a `src/...` path, so only the first
/// string of a row can match the `"security.` prefix.
fn registry_key_paths(source: &str) -> Vec<String> {
    let start = source
        .find("const SECURITY_KEYS")
        .expect("security_keys.rs must declare SECURITY_KEYS");
    let block = &source[start..];
    let end = block
        .find("\n];")
        .expect("the SECURITY_KEYS table must be terminated by `];`");
    let mut out = Vec::new();
    let mut rest = &block[..end];
    while let Some(open) = rest.find("\"security.") {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    out
}

/// Flattens a YAML document into dotted leaf paths.
///
/// A sequence or scalar terminates a path; only mappings recurse. That matches
/// the registry's notion of a "leaf key": `security.reserved_slugs` is a leaf
/// whose value happens to be a list.
fn flatten(value: &serde_norway::Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        serde_norway::Value::Mapping(map) if !map.is_empty() => {
            for (key, child) in map {
                let Some(name) = key.as_str() else { continue };
                let path = if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}.{name}")
                };
                flatten(child, &path, out);
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.insert(prefix.to_string());
            }
        }
    }
}

/// Every live leaf path in `hearth.maximal.yaml`.
fn maximal_leaf_paths() -> BTreeSet<String> {
    let text = read(MAXIMAL);
    let doc: serde_norway::Value =
        serde_norway::from_str(&text).expect("hearth.maximal.yaml must be valid YAML");
    let mut out = BTreeSet::new();
    flatten(&doc, "", &mut out);
    out
}

/// True when some realm sets `realms.<name>.<suffix>`.
fn any_realm_sets(leaves: &BTreeSet<String>, suffix: &str) -> bool {
    leaves
        .iter()
        .any(|p| p.starts_with("realms.") && p.ends_with(suffix))
}

#[test]
fn maximal_example_sets_every_registered_security_key() {
    let registered = registry_key_paths(&read(REGISTRY));
    assert!(
        registered.len() >= 60,
        "the registry extractor found only {} keys — it is probably broken, which \
         would make this guard vacuous",
        registered.len()
    );

    let leaves = maximal_leaf_paths();
    let missing: Vec<&String> = registered.iter().filter(|k| !leaves.contains(*k)).collect();

    assert!(
        missing.is_empty(),
        "{} of {} registered `security.*` keys are absent from {MAXIMAL}, which \
         advertises itself as the maximal example. An operator cannot discover a \
         control that the \"100% feature-coverage\" config never mentions.\n\n{}",
        missing.len(),
        registered.len(),
        missing
            .iter()
            .map(|k| format!("  - {k}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn maximal_example_sets_the_webauthn_policies_task_20_14_made_settable() {
    let leaves = maximal_leaf_paths();
    let suffixes = [
        "webauthn_required",
        "webauthn_resident_key",
        "webauthn_user_verification",
    ];

    let mut missing = Vec::new();
    for suffix in suffixes {
        let global = format!("auth.{suffix}");
        if !leaves.contains(&global) {
            missing.push(global);
        }
        if !any_realm_sets(&leaves, &format!(".auth.{suffix}")) {
            missing.push(format!("realms.<name>.auth.{suffix}"));
        }
    }

    assert!(
        missing.is_empty(),
        "task 20.14 made these WebAuthn policies settable from YAML; {MAXIMAL} must \
         show both the global default and the per-realm override:\n{}",
        missing.join("\n")
    );
}

#[test]
fn maximal_example_sets_the_per_realm_cidr_policy() {
    let leaves = maximal_leaf_paths();
    for suffix in [".security.cidr_policy.allow", ".security.cidr_policy.deny"] {
        assert!(
            any_realm_sets(&leaves, suffix),
            "no realm in {MAXIMAL} sets `realms.<name>{suffix}` — the A-9 tenant CIDR \
             guard built by task 20.13 has no worked example"
        );
    }
}

/// Non-vacuity: the flattener must actually resolve nested paths, and must not
/// report a path the file does not contain.
#[test]
fn leaf_flattener_reports_real_paths_only() {
    let leaves = maximal_leaf_paths();
    assert!(
        leaves.len() >= 200,
        "only {} leaves found in {MAXIMAL}; the flattener is not descending",
        leaves.len()
    );
    assert!(
        leaves.contains("server.bind_address"),
        "a known top-level leaf must be found"
    );
    assert!(
        leaves.contains("security.rate_limiting.login_per_ip.max_attempts"),
        "a known four-deep leaf must be found"
    );
    assert!(
        !leaves.contains("security.this_key_does_not_exist"),
        "the flattener must not invent paths"
    );
}

/// Non-vacuity: the registry extractor must read the real table, not an empty
/// slice, and must not pick up the consumer column.
#[test]
fn registry_extractor_reads_the_real_table() {
    let keys = registry_key_paths(&read(REGISTRY));
    assert!(
        keys.iter().all(|k| k.starts_with("security.")),
        "the extractor picked up a non-`security.` literal: {keys:?}"
    );
    assert!(
        keys.iter().any(|k| k == "security.jwks_rps_limit"),
        "a known registry entry must be extracted"
    );
    let unique: BTreeSet<&String> = keys.iter().collect();
    assert_eq!(
        unique.len(),
        keys.len(),
        "the registry must not list a path twice"
    );
}
