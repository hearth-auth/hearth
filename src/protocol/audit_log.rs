//! The protocol layer's single sink for audit writes.
//!
//! # Why this module exists
//!
//! [`AuditEngine::append`] returns a `Result`, and 40 protocol-layer call
//! sites threw it away with a discarding `let` binding. A storage error, a
//! full disk, or a broken HMAC chain therefore produced **no log line at
//! all** — the mutation succeeded, the audit record did not, and nothing
//! anywhere said so (audit 2026-08-28 §4.14#8; the report said 38, the real
//! count when the fix landed was 40).
//!
//! [`AuditFailurePolicy`] exists precisely to grade that loss, and the
//! identity layer honours it in `EmbeddedIdentityEngine::record_audit`. The
//! protocol layer bypassed it entirely.
//!
//! [`record`] is the one way the protocol layer appends an audit event
//! best-effort. It logs every failure at a severity taken from the action's
//! own [`AuditFailurePolicy`]. A structural test in this module refuses the
//! old discarding shape anywhere under `src/protocol/`, so a future call site
//! cannot silently reintroduce the defect.
//!
//! A handler that must *fail the request* when the audit write fails keeps
//! calling [`AuditEngine::append`] directly and handles the `Result` — this
//! helper is for the best-effort majority.

use crate::audit::{AuditAction, AuditEngine, AuditFailurePolicy, CreateAuditEvent};

/// Severity [`record`] logs a lost audit event at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LossSeverity {
    /// The action's own policy is [`AuditFailurePolicy::FailOperation`] —
    /// a destructive or security-sensitive mutation happened with no trail.
    Error,
    /// The action's own policy is [`AuditFailurePolicy::LogOnly`].
    Warn,
}

/// Maps an action's [`AuditFailurePolicy`] to the severity a lost event is
/// logged at.
///
/// Split out from [`record`] so the grading is testable without standing up a
/// whole [`AuditEngine`] double.
pub(crate) fn loss_severity(action: &AuditAction) -> LossSeverity {
    match action.failure_policy() {
        AuditFailurePolicy::FailOperation => LossSeverity::Error,
        AuditFailurePolicy::LogOnly => LossSeverity::Warn,
    }
}

/// Appends `event` best-effort, logging — never discarding — a failure.
///
/// The event's action, resource and realm are recorded so an operator can tell
/// *which* trail has a hole in it. No metadata is logged: it routinely carries
/// user-supplied values.
pub(crate) fn record(audit: &dyn AuditEngine, event: &CreateAuditEvent) {
    let Err(e) = audit.append(event) else {
        return;
    };
    match loss_severity(&event.action) {
        LossSeverity::Error => tracing::error!(
            realm_id = %event.realm_id,
            action = %event.action,
            resource_type = %event.resource_type,
            resource_id = %event.resource_id,
            error = %e,
            "audit append failed for a security-sensitive action; the operation \
             completed but no audit record exists for it"
        ),
        LossSeverity::Warn => tracing::warn!(
            realm_id = %event.realm_id,
            action = %event.action,
            resource_type = %event.resource_type,
            resource_id = %event.resource_id,
            error = %e,
            "audit append failed; the operation completed but no audit record \
             exists for it"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn loss_severity_follows_the_actions_own_failure_policy() {
        // Guards the premise: if every action shared one policy the severity
        // split would be decoration.
        assert_eq!(
            loss_severity(&AuditAction::UserDeleted),
            LossSeverity::Error,
            "a destructive action's lost trail must log at error"
        );
        assert_eq!(loss_severity(&AuditAction::UserUpdated), LossSeverity::Warn);
    }

    /// Collects every hand-written `.rs` file under `dir`.
    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `generated/` is build-script output, not hand-written code.
                if path.file_name().is_some_and(|n| n == "generated") {
                    continue;
                }
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// 19.3 — no protocol-layer audit write may discard its `Result`.
    ///
    /// Structural rather than behavioural on purpose: the defect is a *shape*
    /// repeated across 40 call sites, and a behavioural test would only cover
    /// the handlers someone remembered to write a test for. This keeps every
    /// future call site honest.
    #[test]
    fn no_protocol_audit_write_discards_its_result() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol");
        let mut files = Vec::new();
        rust_sources(&root, &mut files);
        assert!(
            files.len() > 20,
            "the scan found only {} files under {} — the walk is broken, not the code",
            files.len(),
            root.display()
        );

        // `let` + `_` + `=`, split so this file does not match its own rule.
        let discard = concat!("let ", "_ = ");
        let mut offenders = Vec::new();
        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with(discard) && trimmed.contains("audit.append(") {
                    offenders.push(format!("{}:{}", file.display(), i + 1));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "{} protocol-layer audit write(s) discard their Result with no log line. \
             Route them through `crate::protocol::audit_log::record` instead:\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}
