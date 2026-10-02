//! scope-trim-trusted-core, group 5: the public gRPC API is removed.
//!
//! A-43 (gRPC reflection production-disable) is now met by removal: there is
//! no gRPC listener to reflect, and `security.grpc.reflection_enabled` can no
//! longer switch reflection back on — the key stops startup.
//!
//! Its config keys must stop startup with an error that names the removed
//! feature, on the checked loader and on the `--dev` loader alike. The Raft
//! peer transport is internal and stays; the cluster suites cover it.

use hearth::config::{Config, ConfigError};

const CASES: &[(&str, &str)] = &[
    (
        "server:\n  port: 8420\n  grpc_port: 9090\n",
        "server.grpc_port",
    ),
    (
        "server:\n  port: 8420\n  grpc_bind_address: 127.0.0.1\n",
        "server.grpc_bind_address",
    ),
    (
        "server:\n  port: 8420\n  grpc_allow_plaintext: true\n",
        "server.grpc_allow_plaintext",
    ),
    (
        "security:\n  grpc:\n    reflection_enabled: true\n",
        "security.grpc",
    ),
];

fn assert_names_removed_grpc(err: &ConfigError, key: &str) {
    assert!(
        matches!(err, ConfigError::RemovedKey { .. }),
        "{key}: expected RemovedKey, got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains(&format!("'{key}'")), "{key}: {msg}");
    assert!(msg.contains("gRPC"), "{key}: {msg}");
    assert!(msg.contains("3.0.0"), "{key}: {msg}");
    assert!(
        msg.contains("/admin"),
        "{key}: the message points at the REST API: {msg}"
    );
}

#[test]
fn grpc_keys_stop_the_checked_loader() {
    for (yaml, key) in CASES {
        let err = Config::from_yaml_str(yaml).expect_err("removed key must fail");
        assert_names_removed_grpc(&err, key);
    }
}

#[test]
fn grpc_keys_stop_the_dev_loader() {
    for (yaml, key) in CASES {
        let err = Config::from_yaml_str_unchecked(yaml).expect_err("removed key must fail");
        assert_names_removed_grpc(&err, key);
    }
}
