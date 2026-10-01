//! Guards the crate's *default* Cargo feature set.
//!
//! `dev-endpoints` compiles in `POST /admin/bootstrap`, the `/dev/seed-*`
//! family and the hard-coded dev system-admin password. It must never be a
//! default feature: a plain `cargo build --release` or `cargo install hearth`
//! is a production build, and an opt-out default puts that code in every
//! binary whose builder did not know to pass `--no-default-features`.
//! Everything that needs the dev surface opts in with
//! `--features dev-endpoints` instead.

/// Returns the items listed on the `default = [...]` line of `[features]`.
fn default_features(manifest: &str) -> Vec<String> {
    let mut in_features = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        if let Some(rest) = line.strip_prefix("default") {
            let rest = rest.trim_start();
            let Some(list) = rest.strip_prefix('=') else {
                continue;
            };
            let list = list.trim();
            let inner = list
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or_else(|| panic!("`default` must be a one-line array, got: {list}"));
            return inner
                .split(',')
                .map(|item| item.trim().trim_matches('"').to_string())
                .filter(|item| !item.is_empty())
                .collect();
        }
    }
    panic!("Cargo.toml has no `default = [...]` entry under [features]");
}

#[test]
fn default_feature_set_parser_reads_the_list() {
    let manifest = "[package]\nname = \"x\"\n\n[features]\ndefault = [\"a\", \"b\"]\nb = []\n";
    assert_eq!(default_features(manifest), vec!["a", "b"]);
    let empty = "[features]\ndefault = []\n";
    assert_eq!(default_features(empty), [] as [std::string::String; 0]);
}

#[test]
fn dev_endpoints_is_not_a_default_feature() {
    let manifest = include_str!("../Cargo.toml");
    let defaults = default_features(manifest);
    assert!(
        !defaults.iter().any(|f| f == "dev-endpoints"),
        "`dev-endpoints` must be opt-in (`--features dev-endpoints`), not a default \
         feature — a plain `cargo build --release` would ship /admin/bootstrap and the \
         hard-coded dev admin password. default = {defaults:?}"
    );
}

#[test]
fn dev_endpoints_feature_still_exists() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest
            .lines()
            .any(|l| l.trim_start().starts_with("dev-endpoints = [")),
        "the `dev-endpoints` feature must remain declared so dev tooling can opt in"
    );
}
