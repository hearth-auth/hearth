//! Configuration keys of features removed from Hearth.
//!
//! Every config struct uses `deny_unknown_fields`, so a deleted field already
//! stops startup — but with serde's generic "unknown field" message. An
//! operator who upgrades with `sms:` still in `hearth.yaml` must learn that
//! SMS OTP is gone, not that a field is misspelled. This module names the
//! removed feature instead (scope-trim-trusted-core, design decision 2).
//!
//! The check runs on the post-substitution YAML text, before the typed parse,
//! in both [`super::Config::from_yaml_str`] and
//! [`super::Config::from_yaml_str_unchecked`] (the `--dev` path).

use super::error::ConfigError;

/// The release that removed every key in [`REMOVED_KEYS`].
///
/// A constant, not `CARGO_PKG_VERSION`: `build.rs` overrides that with the
/// running version, which is not the version that removed the key.
pub const REMOVED_IN: &str = "3.0.0";

/// One configuration key that belonged to a removed feature.
#[derive(Debug, Clone, Copy)]
pub struct RemovedKey {
    /// Dotted key path. `*` matches any one segment: a realm or client name,
    /// or a sequence element.
    pub path: &'static str,
    /// Human-readable name of the removed feature.
    pub feature: &'static str,
    /// What to use instead, when there is a replacement.
    pub replacement: Option<&'static str>,
}

/// Keys of features removed in [`REMOVED_IN`]. Each removal adds its own keys.
pub const REMOVED_KEYS: &[RemovedKey] = &[];

/// Returns the error for the first removed key present in `yaml`.
///
/// `yaml` is the post-substitution config text. Invalid YAML returns `None`;
/// the caller's own parse reports the real error.
pub(crate) fn removed_key_issue(yaml: &str, table: &[RemovedKey]) -> Option<ConfigError> {
    if table.is_empty() {
        return None;
    }
    let root: serde_norway::Value = serde_norway::from_str(yaml).ok()?;
    table.iter().find_map(|removed| {
        let segments: Vec<&str> = removed.path.split('.').collect();
        find_path(&root, &segments, String::new()).map(|key| ConfigError::RemovedKey {
            key,
            feature: removed.feature,
            removed_in: REMOVED_IN,
            replacement: removed.replacement,
        })
    })
}

/// Returns the concrete dotted path of the first match of `segments` under
/// `value`, where `*` matches any mapping key or sequence index.
fn find_path(value: &serde_norway::Value, segments: &[&str], prefix: String) -> Option<String> {
    let Some((head, rest)) = segments.split_first() else {
        return Some(prefix);
    };
    let join = |name: &str| {
        if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        }
    };
    match value {
        serde_norway::Value::Mapping(map) => map.iter().find_map(|(k, v)| {
            let name = k.as_str()?;
            (*head == "*" || *head == name)
                .then(|| find_path(v, rest, join(name)))
                .flatten()
        }),
        serde_norway::Value::Sequence(items) if *head == "*" => items
            .iter()
            .enumerate()
            .find_map(|(i, v)| find_path(v, rest, join(&i.to_string()))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[RemovedKey] = &[
        RemovedKey {
            path: "sms",
            feature: "SMS OTP",
            replacement: Some("use passkeys or TOTP"),
        },
        RemovedKey {
            path: "server.grpc_port",
            feature: "the public gRPC API",
            replacement: None,
        },
        RemovedKey {
            path: "realms.*.saml_service_providers",
            feature: "the SAML IdP side",
            replacement: None,
        },
        RemovedKey {
            path: "realms.*.clients.*.profile",
            feature: "the FAPI 2.0 profile",
            replacement: None,
        },
    ];

    fn issue(yaml: &str) -> String {
        let err = removed_key_issue(yaml, FIXTURE).expect("a removed key must be reported");
        assert!(
            matches!(err, ConfigError::RemovedKey { .. }),
            "expected RemovedKey, got {err:?}"
        );
        err.to_string()
    }

    #[test]
    fn top_level_key_names_key_feature_version_and_replacement() {
        let msg = issue("sms:\n  transport: twilio\n");
        assert!(msg.contains("'sms'"), "got: {msg}");
        assert!(msg.contains("SMS OTP"), "got: {msg}");
        assert!(msg.contains("3.0.0"), "got: {msg}");
        assert!(msg.contains("use passkeys or TOTP"), "got: {msg}");
    }

    #[test]
    fn key_with_null_value_is_still_reported() {
        let msg = issue("sms:\n");
        assert!(msg.contains("'sms'"), "got: {msg}");
    }

    #[test]
    fn nested_key_is_reported_by_full_path() {
        let msg = issue("server:\n  port: 8420\n  grpc_port: 9090\n");
        assert!(msg.contains("'server.grpc_port'"), "got: {msg}");
        assert!(msg.contains("gRPC"), "got: {msg}");
    }

    #[test]
    fn wildcard_segment_reports_the_concrete_name() {
        let msg = issue("realms:\n  acme:\n    saml_service_providers: []\n");
        assert!(
            msg.contains("'realms.acme.saml_service_providers'"),
            "got: {msg}"
        );
    }

    #[test]
    fn wildcard_matches_sequence_elements() {
        let yaml = "realms:\n  acme:\n    clients:\n      - id: web\n      - id: bank\n        profile: fapi2\n";
        let msg = issue(yaml);
        assert!(
            msg.contains("'realms.acme.clients.1.profile'"),
            "got: {msg}"
        );
    }

    #[test]
    fn kept_keys_are_not_reported() {
        let yaml = "server:\n  port: 8420\nrealms:\n  acme:\n    clients:\n      - id: web\n";
        assert!(removed_key_issue(yaml, FIXTURE).is_none());
    }

    #[test]
    fn prefix_of_a_removed_path_is_not_reported() {
        // `server` itself is kept; only `server.grpc_port` is removed.
        assert!(removed_key_issue("server:\n  port: 8420\n", FIXTURE).is_none());
        // A sibling with a shared name prefix is not the removed key.
        assert!(removed_key_issue("server:\n  grpc_port_note: x\n", FIXTURE).is_none());
    }

    #[test]
    fn invalid_yaml_is_left_to_the_typed_parse() {
        assert!(removed_key_issue("server: [unclosed", FIXTURE).is_none());
    }

    #[test]
    fn production_table_paths_are_well_formed() {
        for key in REMOVED_KEYS {
            assert!(!key.path.is_empty(), "empty path in REMOVED_KEYS");
            assert!(
                key.path.split('.').all(|s| !s.is_empty()),
                "malformed path {:?}",
                key.path
            );
            assert!(!key.feature.is_empty(), "no feature for {:?}", key.path);
        }
    }
}
