//! Task 24.1 (audit 2026-08-28 §9 item 1) — the class "operations that report
//! success while not having succeeded", made structural.
//!
//! The audit named six instances: a restore that destroys a realm and exits 0,
//! a CLI family emitting zero bytes, a config editor answering `{"ok":true}`
//! after a partial apply, a release pipeline signing a failing build, a SAML
//! consumer auditing a login that never happened, and two admin actions
//! reporting "Reset email sent". Each was fixed one at a time. Fixing six named
//! instances does nothing about the seventh, so this file is the guard.
//!
//! Two rules, both structural on purpose. The defect is a *shape*, and a
//! behavioural test only ever covers the call site somebody remembered.
//!
//! ## Rule 1 — a mandatory audit write may not be discarded
//!
//! `AuditAction::failure_policy` splits every action into `LogOnly` and
//! `FailOperation`. `record_audit` already honours that split: on
//! `FailOperation` it logs at `error` and returns `Err`. So
//! `let _ = self.record_audit(...)` with a `FailOperation` action throws away
//! the one thing the policy exists to do — abort the operation — and the caller
//! then answers `Ok`. The destructive change is durable, its mandatory audit
//! record is gone, and the client was told it all worked.
//!
//! This is the identity-layer mirror of task 19.3, which fixed the same shape
//! for the 40 protocol-layer `audit.append` sites and guards it in
//! `src/protocol/audit_log.rs`.
//!
//! ## Rule 2 — a kill-switch may not be discarded
//!
//! `revoke_session` is what actually enforces a logout, a user disable, a
//! session-limit eviction and a refresh-token theft cascade. A discarded
//! `revoke_session` leaves the session live while every caller above reports
//! the control as applied.
//!
//! ## The escape hatch, and why it needs a reason
//!
//! Some discards are correct: the enclosing function returns `()` and cannot
//! abort, or it is already returning `Err` so the operation *has* failed. Those
//! sites must say so with a `// DISCARD-OK: <reason>` comment on the line
//! above. The comment is the point — it turns an invisible discard into a
//! decision somebody wrote down and a reviewer can disagree with.

use std::path::{Path, PathBuf};

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

/// Every `.rs` file under `src/`, with a sanity floor so a broken walk fails
/// loudly instead of passing vacuously.
fn all_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    assert!(
        files.len() > 50,
        "the scan found only {} files under {} — the walk is broken, not the code",
        files.len(),
        root.display()
    );
    files.sort();
    files
}

/// Reads the `FailOperation` arm of `AuditAction::failure_policy` and returns
/// the action names in it.
///
/// Derived from the source of truth rather than hard-coded, so moving an action
/// into `FailOperation` automatically widens this guard. A hard-coded copy
/// would go stale silently, which is the same class of defect the guard exists
/// to catch.
fn fail_operation_actions() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/audit/types.rs");
    let text = std::fs::read_to_string(&path).expect("read src/audit/types.rs");

    let mut names = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.contains("---- FailOperation") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(rest) = line.trim_start().strip_prefix("| Self::") {
            names.push(rest.split(['=', ' ', ',']).next().unwrap_or("").to_string());
        } else if let Some(rest) = line.trim_start().strip_prefix("Self::") {
            names.push(rest.split(['=', ' ', ',']).next().unwrap_or("").to_string());
        }
        if line.contains("=> FailOperation") {
            break;
        }
    }

    names.retain(|n| !n.is_empty());
    assert!(
        names.len() > 20,
        "parsed only {} FailOperation actions out of src/audit/types.rs — the \
         parse is broken, and this guard would pass vacuously. Names: {names:?}",
        names.len()
    );
    assert!(
        names.iter().any(|n| n == "SessionRevoked"),
        "the FailOperation parse lost `SessionRevoked`, which is the anchor \
         this guard was written against. Parsed: {names:?}"
    );
    names
}

/// True when the comment block immediately above `index` carries a written
/// justification.
///
/// Walks the whole contiguous `//` block, not just the nearest line: a reason
/// worth writing rarely fits on one line, and requiring the marker to land on
/// the last line would push authors into terser reasons.
fn justified(lines: &[&str], index: usize) -> bool {
    let mut i = index;
    while i > 0 {
        i -= 1;
        let trimmed = lines[i].trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with("//") {
            return false;
        }
        if trimmed.contains("DISCARD-OK:") {
            return true;
        }
    }
    false
}

/// `let` + `_` + `=`, split so this file does not match its own rules.
fn discard_prefix() -> &'static str {
    concat!("let ", "_ = ")
}

/// Rule 1 — no discarded audit write may carry a `FailOperation` action.
#[test]
fn no_mandatory_audit_write_is_discarded_without_a_written_reason() {
    let fail_ops = fail_operation_actions();
    let discard = discard_prefix();
    let mut offenders = Vec::new();

    for file in all_sources() {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !trimmed.starts_with(discard) {
                continue;
            }
            // The discarded call must be the audit write itself. Rust puts the
            // opening paren on the first line even when the arguments wrap, so
            // requiring it here is precise: without it, an unrelated discard
            // sitting above a *propagated* audit write reads as an offender.
            if !trimmed.contains("record_audit(") && !trimmed.contains("audit.append(") {
                continue;
            }
            // The arguments may wrap, so look ahead a bounded window for the
            // action.
            let window_end = (i + 8).min(lines.len());
            let window = lines[i..window_end].join("\n");
            let Some(action) = window
                .split("AuditAction::")
                .nth(1)
                .map(|rest| rest.split([',', ' ', '\n', ')']).next().unwrap_or(""))
            else {
                continue;
            };
            if fail_ops.iter().any(|n| n == action) && !justified(&lines, i) {
                offenders.push(format!(
                    "{}:{} — AuditAction::{action}",
                    file.display(),
                    i + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{} discarded audit write(s) carry a FailOperation action. The \
         operation stays committed, its mandatory audit record is lost, and \
         the caller answers Ok. Propagate the Result with `?`, or, if the \
         enclosing function genuinely cannot abort, write the reason on the \
         line above as `// DISCARD-OK: <reason>`:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// Rule 2 — no discarded `revoke_session` without a written reason.
#[test]
fn no_session_revocation_is_discarded_without_a_written_reason() {
    let discard = discard_prefix();
    let mut offenders = Vec::new();

    for file in all_sources() {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !trimmed.starts_with(discard) {
                continue;
            }
            if !trimmed.contains("revoke_session(") {
                continue;
            }
            if !justified(&lines, i) {
                offenders.push(format!("{}:{}", file.display(), i + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "{} discarded session revocation(s). `revoke_session` is what enforces \
         a logout, a user disable, a session-limit eviction and a theft \
         cascade; discarding it leaves the session live while the caller \
         reports the control as applied. Propagate the Result, or write the \
         reason on the line above as `// DISCARD-OK: <reason>`:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}
