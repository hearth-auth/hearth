//! scope-trim-trusted-core, group 10: the abuse extras are removed — IP
//! reputation (P-2), bot signals (P-3), email reputation (P-5) and the A-17
//! login tarpit.
//!
//! A-17 is now met by removal: an operator who tries to switch the tarpit
//! back on is refused at startup, not silently ignored. The guards that stay
//! — the per-IP and per-account limiters, the CAPTCHA challenge (A-16), the
//! outbound volume shield (A-4) and the cross-realm cap (A-50) — keep their
//! own suites.

use hearth::config::{Config, ConfigError};

const REMOVED: &[(&str, &str)] = &[
    (
        "security:\n  tarpit:\n    threshold: 5\n",
        "security.tarpit",
    ),
    (
        "security:\n  ip_reputation:\n    enabled: true\n",
        "security.ip_reputation",
    ),
    (
        "security:\n  providers:\n    bot_signal:\n      enabled: true\n",
        "security.providers",
    ),
    (
        "security:\n  providers:\n    email_reputation:\n      enabled: true\n",
        "security.providers",
    ),
];

fn assert_names_removed(err: &ConfigError, key: &str) {
    assert!(
        matches!(err, ConfigError::RemovedKey { .. }),
        "{key}: expected RemovedKey, got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains(&format!("'{key}'")), "{key}: {msg}");
    assert!(msg.contains("3.0.0"), "{key}: {msg}");
}

/// A-17 adversarial: enabling the removed tarpit, or any removed reputation
/// or bot-signal provider, stops the checked loader.
#[test]
fn a17_removed_abuse_keys_stop_the_checked_loader() {
    for (yaml, key) in REMOVED {
        let err = Config::from_yaml_str(yaml).expect_err("removed key must fail");
        assert_names_removed(&err, key);
    }
}

/// The `--dev` loader refuses the same keys.
#[test]
fn a17_removed_abuse_keys_stop_the_dev_loader() {
    for (yaml, key) in REMOVED {
        let err = Config::from_yaml_str_unchecked(yaml).expect_err("removed key must fail");
        assert_names_removed(&err, key);
    }
}

/// Control: the kept guards still parse.
#[test]
fn kept_abuse_guards_still_parse() {
    let yaml = "security:\n  outbound_volume_shield:\n    enabled: true\n  \
                cross_realm_aggregation_cap:\n    enabled: true\n  \
                distributed_attack_detector:\n    window: 300s\n";
    Config::from_yaml_str_unchecked(yaml).expect("kept guards parse");
}
