//! Start-up liveness registry for security-relevant configuration keys.
//!
//! Audit 2026-08-28 §1A item 5, §9 item 2 (task 20.17).
//!
//! # The class of defect this closes
//!
//! `security.http2.max_concurrent_streams` parses, validates, lands in
//! [`SecurityYaml`](super::types::SecurityYaml) — and is then never read: the
//! HTTP/2 rapid-reset caps come from compiled-in constants in
//! `protocol::http`. An operator who tightens that knob after a CVE advisory
//! gets a clean boot, a clean `hearth config validate`, and no change in
//! behaviour. `storage.fsync` had the same shape, and so did
//! `security.reserved_slugs` when the `security:` block was omitted. A field
//! reaching the domain struct is *not* evidence that anything consumes it.
//!
//! # The mechanism
//!
//! [`SECURITY_KEYS`] names every leaf key an operator can write under
//! `security:` and, for each, the module that actually reads it. Two checks
//! hang off that table:
//!
//! 1. **Start-up, fail closed** — [`liveness_issues`] walks the leaf keys the
//!    operator actually wrote in their YAML. A key that is not in the registry,
//!    or is registered with [`Consumer::None`], is a hard configuration error.
//!    Defaults are never flagged: only a key the operator explicitly set can
//!    fail, so a dead key with a compiled-in default degrades to a refusal only
//!    for the operator who believed it did something.
//! 2. **Test time, forced registration** — `registry_covers_every_security_leaf`
//!    (in this module's test block) re-derives the leaf key set from
//!    `types.rs` and asserts it equals the registry. Adding a field without
//!    naming its consumer fails the build.
//!
//! Secret-bearing keys additionally carry [`Sensitivity::Secret`], which makes
//! an empty value a hard error rather than a credential that matches the empty
//! string (§4.13#4 — see [`super::validate`]).

use super::types::ValidationIssue;

/// Whether a key carries credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sensitivity {
    /// An ordinary tunable. Empty / zero values are the key's own business.
    Value,
    /// Credential material. An empty value MUST NOT be accepted: an empty
    /// expected secret compares equal to an absent one supplied by a caller.
    Secret,
}

/// Where a configuration key is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Consumer {
    /// The module path that reads the resolved value. Free text — the point is
    /// that a human had to name one, and the accompanying test checks the file
    /// exists and mentions the field.
    At(&'static str),
    /// **Nothing reads this key.** Setting it is refused at start-up until a
    /// consumer is wired or the key is removed.
    None,
}

/// One registered configuration key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SecurityKey {
    /// Dotted path from the config root, e.g. `security.jwks_rps_limit`.
    pub path: &'static str,
    /// The module that reads it, or [`Consumer::None`] for a dead key.
    pub consumer: Consumer,
    /// Whether an empty value is a credential hazard.
    pub sensitivity: Sensitivity,
}

const fn key(path: &'static str, consumer: &'static str) -> SecurityKey {
    SecurityKey {
        path,
        consumer: Consumer::At(consumer),
        sensitivity: Sensitivity::Value,
    }
}

const fn secret(path: &'static str, consumer: &'static str) -> SecurityKey {
    SecurityKey {
        path,
        consumer: Consumer::At(consumer),
        sensitivity: Sensitivity::Secret,
    }
}

/// Marks a key that parses but has no consumer yet.
///
/// The registry currently holds none: task 22.12 wired the last two
/// (`security.http2.*`). It is kept because the next key to be added may land
/// before its consumer does, and because the unwired arm of
/// [`liveness_issues_against`] is tested through it.
#[cfg_attr(not(test), allow(dead_code))]
const fn unwired(path: &'static str) -> SecurityKey {
    SecurityKey {
        path,
        consumer: Consumer::None,
        sensitivity: Sensitivity::Value,
    }
}

/// Every leaf key reachable under `security:` in `hearth.yaml`.
///
/// Keep sorted by path. A new field in `SecurityYaml` (or any struct it
/// contains) MUST be added here with the module that consumes it, or
/// `registry_covers_every_security_leaf` fails.
pub(crate) const SECURITY_KEYS: &[SecurityKey] = &[
    key(
        "security.allowed_hosts",
        "src/protocol/http/state.rs (host allowlist middleware)",
    ),
    key(
        "security.allowed_return_to_origins",
        "src/abuse/redirect.rs",
    ),
    key(
        "security.backup.export_rate_limit",
        "src/protocol/admin_auth.rs (ExportRateLimiter)",
    ),
    secret(
        "security.backup.verify_key",
        "src/main.rs (backup manifest verification)",
    ),
    key("security.captcha.provider", "src/abuse/captcha/mod.rs"),
    key(
        "security.captcha.turnstile.site_key",
        "src/abuse/captcha/mod.rs",
    ),
    secret(
        "security.captcha.turnstile.secret_key",
        "src/abuse/captcha/mod.rs",
    ),
    key(
        "security.captcha.turnstile.verify_url",
        "src/abuse/captcha/mod.rs",
    ),
    key(
        "security.dev_csp_form_action_origins",
        "src/protocol/web/security.rs",
    ),
    secret(
        "security.dpop_nonce_secret",
        "src/main.rs (DPoP nonce HMAC key)",
    ),
    key(
        "security.grpc.reflection_enabled",
        "src/protocol/grpc/server.rs",
    ),
    // Wired by 22.12: `main.rs` installs these through
    // `protocol::http::limits::init_server_limits`, and BOTH accept loops
    // (`serve_router_on` and `serve_tls_router`) read them. They were
    // compiled-in constants applied on the TLS loop only.
    key(
        "security.http2.max_concurrent_streams",
        "src/protocol/http/limits.rs (both accept loops)",
    ),
    key(
        "security.http2.max_pending_reset_streams",
        "src/protocol/http/limits.rs (both accept loops)",
    ),
    key(
        "security.ip_reputation.action",
        "src/abuse/ip_reputation/mod.rs",
    ),
    key(
        "security.ip_reputation.enabled",
        "src/abuse/ip_reputation/mod.rs",
    ),
    key(
        "security.ip_reputation.maxmind_db_path",
        "src/abuse/ip_reputation/maxmind.rs",
    ),
    key(
        "security.ip_reputation.spamhaus.drop_url",
        "src/abuse/ip_reputation/spamhaus.rs",
    ),
    key(
        "security.ip_reputation.spamhaus.dropv6_url",
        "src/abuse/ip_reputation/spamhaus.rs",
    ),
    key(
        "security.ip_reputation.spamhaus.refresh_interval_secs",
        "src/abuse/ip_reputation/spamhaus.rs",
    ),
    key(
        "security.jwks_rps_limit",
        "src/protocol/admin_auth.rs (JwksRateLimiter)",
    ),
    secret(
        "security.key_encryption_key",
        "src/identity/key_encryption.rs",
    ),
    key(
        "security.load_test_unthrottled",
        "src/main.rs (loopback-gated)",
    ),
    key(
        "security.password.kdf.admin_max_in_flight",
        "src/config/validate.rs::resolve_admin_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.admin_max_queue_wait_ms",
        "src/config/validate.rs::resolve_admin_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.max_in_flight",
        "src/config/validate.rs::resolve_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.max_queue_wait_ms",
        "src/config/validate.rs::resolve_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    key(
        "security.password.kdf.retry_after_seconds",
        "src/config/validate.rs::resolve_kdf_gate -> src/identity/kdf_gate.rs",
    ),
    secret(
        "security.password.pepper.key_hex",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    secret(
        "security.password.pepper.previous_key_hex",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    key(
        "security.password.pepper.previous_version",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    key(
        "security.password.pepper.version",
        "src/config/validate.rs::resolve_pepper -> src/identity/credentials.rs",
    ),
    key(
        "security.rate_limiting.admin_per_minute",
        "src/protocol/admin_auth.rs (AdminRateLimiter)",
    ),
    key(
        "security.rate_limiting.login_per_account.lockout_seconds",
        "src/main.rs (account lockout policy)",
    ),
    key(
        "security.rate_limiting.login_per_account.max_failures",
        "src/main.rs (account lockout policy)",
    ),
    key(
        "security.rate_limiting.login_per_ip.max_attempts",
        "src/main.rs (per-IP login limiter)",
    ),
    key(
        "security.rate_limiting.login_per_ip.window_seconds",
        "src/main.rs (per-IP login limiter)",
    ),
    key(
        "security.rate_limiting.token_per_minute",
        "src/protocol/admin_auth.rs (TokenRateLimiter)",
    ),
    key("security.request_shaper.ip_rps", "src/abuse/shaper.rs"),
    key("security.request_shaper.realm_rps", "src/abuse/shaper.rs"),
    key(
        "security.reserved_slugs",
        "src/identity/engine/mod.rs (slug reservation)",
    ),
    key(
        "security.slug_cooldown_days",
        "src/identity/keys.rs (slug reservation key TTL)",
    ),
    key("security.tls.crl_paths", "src/protocol/tls.rs"),
    key("security.tls.min_version", "src/protocol/tls.rs"),
];

/// Secret-bearing keys outside the `security:` tree.
///
/// These are not part of the `security:` liveness walk but obey the same
/// empty-value rule: an empty expected credential compares equal to a caller
/// who supplied nothing (§4.13#4). Wildcards use `*` for one path segment and
/// `[]` for "every element of a sequence".
pub(crate) const SECRET_KEYS_OUTSIDE_SECURITY: &[&str] = &[
    "metrics.bearer_token",
    "email.smtp.password",
    "email.sendgrid.api_key",
    "email.mailgun.api_key",
    "email.postmark.server_token",
    "email.mailtrap.api_token",
    "sms.twilio.auth_token",
    "sms.sns.secret_access_key",
    "realms.*.scim.bearer_token",
    // `applications` and `federation.providers` are YAML *maps* keyed by client
    // id, so their leaf paths are `realms.<realm>.applications.<id>.<field>`.
    // A `[]` pattern here never matched, which is how an empty client secret
    // reached the config unflagged.
    "realms.*.applications.*.client_secret",
    "realms.*.oauth_clients.*.client_secret",
    "realms.*.federation.providers.*.client_secret",
    "realms.*.federation.providers[].client_secret",
];

/// Every registered `security.*` path, for external assertions.
pub(crate) fn registered_paths() -> impl Iterator<Item = &'static str> {
    SECURITY_KEYS.iter().map(|k| k.path)
}

fn lookup_in<'a>(registry: &'a [SecurityKey], path: &str) -> Option<&'a SecurityKey> {
    registry.iter().find(|k| k.path == path)
}

/// Collects every leaf path present in `value`, prefixed by `prefix`.
///
/// A sequence contributes its own path once (it is a leaf as far as the
/// registry is concerned — `allowed_hosts`, `crl_paths`), and is not walked
/// element-by-element.
fn collect_leaves(prefix: &str, value: &serde_norway::Value, out: &mut Vec<(String, String)>) {
    match value {
        serde_norway::Value::Mapping(map) => {
            for (k, v) in map {
                let Some(name) = k.as_str() else { continue };
                let path = if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}.{name}")
                };
                match v {
                    serde_norway::Value::Mapping(_) => collect_leaves(&path, v, out),
                    other => out.push((path, scalar_text(other))),
                }
            }
        }
        other => out.push((prefix.to_string(), scalar_text(other))),
    }
}

/// Renders a scalar for the empty-value check. Non-scalars render as a
/// non-empty placeholder so only genuinely empty strings trip the rule.
fn scalar_text(value: &serde_norway::Value) -> String {
    match value {
        serde_norway::Value::String(s) => s.clone(),
        serde_norway::Value::Null => String::new(),
        other => format!("{other:?}"),
    }
}

/// Reports every `security.*` key the operator set that no consumer reads.
///
/// `yaml` is the **post-substitution** config text (see
/// [`super::env::substitute_env_vars`]). Returns one issue per offending key so
/// `validate_all` can surface them all at once; [`assert_wired`] turns the
/// first into a hard error for the start-up path.
pub(crate) fn liveness_issues(yaml: &str) -> Vec<ValidationIssue> {
    liveness_issues_against(SECURITY_KEYS, yaml)
}

/// [`liveness_issues`] against an explicit registry.
///
/// Production always passes [`SECURITY_KEYS`]. The seam exists so the unwired
/// arm stays testable: every real key currently has a consumer, so a test that
/// used a real key as its example would silently stop exercising the arm the
/// moment that key was wired. That is exactly what happened when task 22.12
/// wired `security.http2.*`.
fn liveness_issues_against(registry: &[SecurityKey], yaml: &str) -> Vec<ValidationIssue> {
    let Ok(root) = serde_norway::from_str::<serde_norway::Value>(yaml) else {
        // A YAML parse failure is reported by the caller's own parse; there is
        // nothing to walk here.
        return Vec::new();
    };
    let serde_norway::Value::Mapping(top) = &root else {
        return Vec::new();
    };
    let Some(security) = top
        .iter()
        .find(|(k, _)| k.as_str() == Some("security"))
        .map(|(_, v)| v)
    else {
        return Vec::new();
    };
    if !matches!(security, serde_norway::Value::Mapping(_)) {
        return Vec::new();
    }

    let mut leaves = Vec::new();
    collect_leaves("security", security, &mut leaves);

    let mut issues = Vec::new();
    for (path, _) in &leaves {
        match lookup_in(registry, path) {
            None => issues.push(ValidationIssue {
                field: path.clone(),
                reason: "is not a registered security key. Every key under `security:` must \
                         name the module that consumes it in \
                         `src/config/security_keys.rs::SECURITY_KEYS`; a key nobody reads is \
                         a control the operator believes is on and is not."
                    .to_string(),
            }),
            Some(k) if k.consumer == Consumer::None => issues.push(ValidationIssue {
                field: path.clone(),
                reason: "is parsed but no code reads it, so setting it has no effect. Remove \
                         the key from your config; it is tracked in \
                         `src/config/security_keys.rs` and will start working once a consumer \
                         is wired."
                    .to_string(),
            }),
            Some(_) => {}
        }
    }
    issues
}

/// Reports every registered secret key that is present but empty.
///
/// An empty expected credential is worse than an absent one: the `/metrics`
/// guard and `client_secret_basic` both compare the caller's supplied value
/// against it, and a caller who supplies nothing compares equal (§4.13#4).
pub(crate) fn empty_secret_issues(yaml: &str) -> Vec<ValidationIssue> {
    let Ok(root) = serde_norway::from_str::<serde_norway::Value>(yaml) else {
        return Vec::new();
    };
    let mut leaves = Vec::new();
    collect_leaves("", &root, &mut leaves);

    let mut issues = Vec::new();
    for (path, text) in &leaves {
        if !text.is_empty() {
            continue;
        }
        let is_secret = lookup_in(SECURITY_KEYS, path)
            .is_some_and(|k| k.sensitivity == Sensitivity::Secret)
            || SECRET_KEYS_OUTSIDE_SECURITY
                .iter()
                .any(|pat| matches_pattern(pat, path));
        if is_secret {
            issues.push(ValidationIssue {
                field: path.clone(),
                reason: "must not be the empty string. An empty expected secret compares equal \
                         to a caller that supplied none, so the credential check passes for \
                         everyone. Remove the key to disable the check, or set a real value."
                    .to_string(),
            });
        }
    }
    issues
}

/// Matches a dotted path against a registry pattern.
///
/// `*` matches exactly one path segment. A `[]` suffix on a segment means the
/// value is a sequence, whose elements the walker flattens into
/// `<segment>` — sequences are leaves here, so `[]` patterns are matched
/// against the sequence path itself plus the trailing field name.
fn matches_pattern(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('.').collect();
    let seg: Vec<&str> = path.split('.').collect();
    if pat.len() != seg.len() {
        return false;
    }
    pat.iter()
        .zip(seg.iter())
        .all(|(p, s)| *p == "*" || p.trim_end_matches("[]") == *s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The registry is only a control if it is forced to match the struct.
    ///
    /// Re-derives the leaf key set from `src/config/types.rs` and compares it
    /// to [`SECURITY_KEYS`]. Adding a field to `SecurityYaml` (or any struct it
    /// contains) without naming a consumer fails here, which is the whole
    /// point: a new security key cannot merge unregistered.
    #[test]
    fn registry_covers_every_security_leaf() {
        let source = include_str!("types.rs");
        let derived = derive_security_leaves(source);
        let registered: BTreeSet<&str> = registered_paths().collect();
        let derived_refs: BTreeSet<&str> = derived.iter().map(String::as_str).collect();

        let missing: Vec<&&str> = derived_refs.difference(&registered).collect();
        assert!(
            missing.is_empty(),
            "these `security:` keys exist in types.rs but are not registered in \
             SECURITY_KEYS — add each one with the module that consumes it: {missing:?}"
        );

        let stale: Vec<&&str> = registered.difference(&derived_refs).collect();
        assert!(
            stale.is_empty(),
            "these registry entries no longer match a field in types.rs (renamed or \
             removed?): {stale:?}"
        );
    }

    /// Every registered consumer must name a file that still exists, and at
    /// least one of the named files must still mention the field, so a key
    /// cannot keep a stale consumer after the code that read it is deleted.
    #[test]
    fn every_registered_consumer_still_exists() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for k in SECURITY_KEYS {
            let Consumer::At(consumer) = k.consumer else {
                continue;
            };
            let field = k.path.rsplit('.').next().unwrap_or(k.path);
            let mut named_any = false;
            let mut mentions_field = false;
            // The consumer string may name several hops ("a -> b") and may
            // carry a parenthesised note; check every `src/...rs` token in it.
            for token in consumer.split_whitespace() {
                let file = token.trim_matches(|c: char| !c.is_ascii_graphic());
                let file = file.split("::").next().unwrap_or(file);
                let is_rust_source = std::path::Path::new(file)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
                if !file.starts_with("src/") || !is_rust_source {
                    continue;
                }
                named_any = true;
                let path = repo_root.join(file);
                assert!(
                    path.exists(),
                    "{}: registered consumer {file} does not exist",
                    k.path
                );
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("{}: reading {file}: {e}", k.path));
                if body.contains(field) {
                    mentions_field = true;
                }
            }
            assert!(
                named_any,
                "{}: the consumer entry names no `src/**.rs` file",
                k.path
            );
            assert!(
                mentions_field,
                "{}: none of the registered consumer files mention `{field}` any more — the \
                 key may have lost its consumer",
                k.path
            );
        }
    }

    /// A key nobody reads is refused when the operator sets it explicitly, and
    /// ignored when it is only a compiled-in default.
    #[test]
    fn unwired_key_is_refused_only_when_explicitly_set() {
        // A synthetic registry, not a real key. Every real key has a consumer
        // today, so pinning this arm to one would make the test evaporate the
        // moment that key was wired.
        let registry = &[
            unwired("security.jwks_rps_limit"),
            key("security.slug_cooldown_days", "src/identity/reconcile.rs"),
        ];

        let set = "security:\n  jwks_rps_limit: 60\n";
        let issues = liveness_issues_against(registry, set);
        assert_eq!(
            issues.len(),
            1,
            "expected exactly one issue, got {issues:?}"
        );
        assert_eq!(issues[0].field, "security.jwks_rps_limit");
        assert!(
            issues[0].reason.contains("no code reads it"),
            "the operator must be told the key is dead, not merely unknown: {issues:?}"
        );

        let other = "security:\n  slug_cooldown_days: 30\n";
        assert!(
            liveness_issues_against(registry, other).is_empty(),
            "a registered, wired key must not be flagged"
        );

        // And nothing at all is flagged when the operator sets no security key.
        assert!(
            liveness_issues_against(registry, "storage:\n  data_dir: \"/tmp/x\"\n").is_empty(),
            "a compiled-in default must never be flagged"
        );
    }

    /// The real registry has no dead keys. If this fails, a key was added
    /// without a consumer — wire it, or mark it `unwired` deliberately.
    #[test]
    fn the_shipped_registry_has_no_unwired_keys() {
        let dead: Vec<_> = SECURITY_KEYS
            .iter()
            .filter(|k| k.consumer == Consumer::None)
            .map(|k| k.path)
            .collect();
        assert!(
            dead.is_empty(),
            "these security keys parse but nothing reads them: {dead:?}"
        );
    }

    #[test]
    fn unknown_security_key_is_refused() {
        // `deny_unknown_fields` catches this at parse time too; the registry is
        // the belt to that suspenders, and covers keys added to the struct but
        // never registered.
        let issues = liveness_issues("security:\n  totally_made_up: true\n");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].reason.contains("not a registered security key"));
    }

    #[test]
    fn empty_secret_is_reported_and_empty_tunable_is_not() {
        let issues = empty_secret_issues("metrics:\n  bearer_token: \"\"\n");
        assert_eq!(issues.len(), 1, "got {issues:?}");
        assert_eq!(issues[0].field, "metrics.bearer_token");

        assert!(
            empty_secret_issues("server:\n  bind_address: \"\"\n").is_empty(),
            "a non-secret empty value is not this check's business"
        );
    }

    #[test]
    fn wildcard_patterns_match_a_realm_scoped_secret() {
        assert!(matches_pattern(
            "realms.*.scim.bearer_token",
            "realms.acme.scim.bearer_token"
        ));
        assert!(!matches_pattern(
            "realms.*.scim.bearer_token",
            "realms.acme.scim.other"
        ));
    }

    /// Parses `types.rs` and yields every dotted leaf path under `security:`.
    ///
    /// Deliberately a source parse rather than a `serde` reflection: the whole
    /// point is to notice a field that was *added to the struct*, which no
    /// runtime value can tell us about.
    fn derive_security_leaves(source: &str) -> Vec<String> {
        let lines: Vec<&str> = source.lines().collect();
        let mut structs: std::collections::HashMap<String, Vec<(String, String)>> =
            std::collections::HashMap::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("pub struct ") else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let mut fields = Vec::new();
            for body in &lines[i + 1..] {
                if body.starts_with('}') {
                    break;
                }
                let b = body.trim();
                let Some(decl) = b.strip_prefix("pub ") else {
                    continue;
                };
                let Some(stripped) = decl.strip_suffix(',') else {
                    continue;
                };
                let Some((field, ty)) = stripped.split_once(": ") else {
                    continue;
                };
                if field.contains(' ') {
                    continue;
                }
                fields.push((field.to_string(), ty.to_string()));
            }
            structs.insert(name, fields);
        }

        fn walk(
            structs: &std::collections::HashMap<String, Vec<(String, String)>>,
            ty: &str,
            prefix: &str,
            out: &mut Vec<String>,
            depth: usize,
        ) {
            if depth > 6 {
                return;
            }
            let Some(fields) = structs.get(ty) else {
                return;
            };
            for (field, field_ty) in fields {
                let inner = field_ty
                    .strip_prefix("Option<")
                    .and_then(|s| s.strip_suffix('>'))
                    .unwrap_or(field_ty);
                let base: String = inner
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                let path = format!("{prefix}.{field}");
                if structs.contains_key(&base) {
                    walk(structs, &base, &path, out, depth + 1);
                } else {
                    out.push(path);
                }
            }
        }

        let mut out = Vec::new();
        walk(&structs, "SecurityYaml", "security", &mut out, 0);
        out
    }
}
