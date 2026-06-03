//! Integration tests for P-5 EmailReputation (disposable-domain list + role-address detection).
//!
//! D-4 taxonomy:
//! - **Unit**: verdict correctness for disposable domains, role addresses,
//!   MX stub, and malformed inputs.
//! - **Adversarial**: case-variation attempts, lookalike domains, operator
//!   extra-domain injection.
//!
//! Closes: HEA-1204 §P-5 (EmailReputation trait + reference adapter).

use hearth::abuse::email_reputation::{
    BuiltinEmailReputation, EmailReputation, EmailReputationConfig, EmailReputationVerdict,
    NoopEmailReputation,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn p() -> BuiltinEmailReputation {
    BuiltinEmailReputation::default_config()
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op provider
// ─────────────────────────────────────────────────────────────────────────────

/// Noop provider always returns a clean verdict even for known disposable addresses.
#[test]
fn p5_noop_always_clean() {
    let v = NoopEmailReputation.check("throwaway@mailinator.com");
    assert!(v.is_clean(), "noop must return a clean verdict; got {v:?}");
}

/// Noop clean verdict is the default (all flags false).
#[test]
fn p5_noop_verdict_all_false() {
    let v = NoopEmailReputation.check("noreply@guerrillamail.com");
    assert_eq!(v, EmailReputationVerdict::default());
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: clean / legitimate domains
// ─────────────────────────────────────────────────────────────────────────────

/// Standard gmail.com address is clean.
#[test]
fn p5_unit_gmail_is_clean() {
    let v = p().check("alice@gmail.com");
    assert!(!v.is_disposable);
    assert!(v.is_clean());
}

/// Outlook.com address is clean.
#[test]
fn p5_unit_outlook_is_clean() {
    let v = p().check("bob@outlook.com");
    assert!(!v.is_disposable);
    assert!(v.is_clean());
}

/// A typical company domain is clean.
#[test]
fn p5_unit_company_domain_is_clean() {
    let v = p().check("alice@example.com");
    assert!(v.is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: disposable-domain detection
// ─────────────────────────────────────────────────────────────────────────────

/// mailinator.com is flagged as disposable.
#[test]
fn p5_unit_mailinator_disposable() {
    let v = p().check("random123@mailinator.com");
    assert!(
        v.is_disposable,
        "mailinator.com must be disposable; got {v:?}"
    );
}

/// guerrillamail.com is flagged.
#[test]
fn p5_unit_guerrillamail_disposable() {
    let v = p().check("abc@guerrillamail.com");
    assert!(v.is_disposable);
}

/// 10minutemail.com is flagged.
#[test]
fn p5_unit_10minutemail_disposable() {
    let v = p().check("xyz@10minutemail.com");
    assert!(v.is_disposable);
}

/// yopmail.com is flagged.
#[test]
fn p5_unit_yopmail_disposable() {
    let v = p().check("test@yopmail.com");
    assert!(v.is_disposable);
}

/// maildrop.cc is flagged.
#[test]
fn p5_unit_maildrop_disposable() {
    let v = p().check("user@maildrop.cc");
    assert!(v.is_disposable);
}

/// trashmail.com is flagged.
#[test]
fn p5_unit_trashmail_disposable() {
    let v = p().check("user@trashmail.com");
    assert!(v.is_disposable);
}

/// sharklasers.com (guerrillamail alias) is flagged.
#[test]
fn p5_unit_sharklasers_disposable() {
    let v = p().check("user@sharklasers.com");
    assert!(v.is_disposable);
}

/// temp-mail.org is flagged.
#[test]
fn p5_unit_temp_mail_org_disposable() {
    let v = p().check("user@temp-mail.org");
    assert!(v.is_disposable);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: role-address detection
// ─────────────────────────────────────────────────────────────────────────────

/// noreply@ is flagged as a role address.
#[test]
fn p5_unit_noreply_role() {
    let v = p().check("noreply@example.com");
    assert!(
        v.is_role_address,
        "noreply@ must be a role address; got {v:?}"
    );
}

/// no-reply@ (hyphenated) is flagged.
#[test]
fn p5_unit_no_reply_hyphen_role() {
    let v = p().check("no-reply@example.com");
    assert!(v.is_role_address);
}

/// admin@ is flagged.
#[test]
fn p5_unit_admin_role() {
    let v = p().check("admin@example.com");
    assert!(v.is_role_address);
}

/// postmaster@ is flagged (RFC 2142).
#[test]
fn p5_unit_postmaster_role() {
    let v = p().check("postmaster@example.com");
    assert!(v.is_role_address);
}

/// abuse@ is flagged (RFC 2142 abuse reporting address).
#[test]
fn p5_unit_abuse_role() {
    let v = p().check("abuse@example.com");
    assert!(v.is_role_address);
}

/// security@ is flagged.
#[test]
fn p5_unit_security_role() {
    let v = p().check("security@example.com");
    assert!(v.is_role_address);
}

/// A regular first-name local part is not flagged as a role address.
#[test]
fn p5_unit_first_name_not_role() {
    let v = p().check("alice@example.com");
    assert!(!v.is_role_address);
}

/// A first+last-name combo is not flagged.
#[test]
fn p5_unit_firstname_lastname_not_role() {
    let v = p().check("alice.smith@example.com");
    assert!(!v.is_role_address);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: both flags set simultaneously
// ─────────────────────────────────────────────────────────────────────────────

/// A disposable domain + role local part sets both flags → not clean.
#[test]
fn p5_unit_disposable_and_role_both_flagged() {
    let v = p().check("noreply@mailinator.com");
    assert!(v.is_disposable);
    assert!(v.is_role_address);
    assert!(!v.is_clean());
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: DNS MX check stub
// ─────────────────────────────────────────────────────────────────────────────

/// The stub MX check always returns false (assume domain is valid).
/// This ensures no registrations are blocked due to the absent DNS resolver.
#[test]
fn p5_unit_mx_stub_always_false_clean_domain() {
    let v = p().check("user@example.com");
    assert!(
        !v.domain_has_no_mx,
        "stub MX check must return false for any domain; got {v:?}"
    );
}

/// Even a clearly fake TLD has domain_has_no_mx = false (stub is unconditional).
#[test]
fn p5_unit_mx_stub_always_false_fake_domain() {
    let v = p().check("user@definitely-does-not-exist.invalid");
    assert!(!v.domain_has_no_mx, "stub must always be false; got {v:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit: malformed / edge-case inputs
// ─────────────────────────────────────────────────────────────────────────────

/// Email with no @ returns a clean verdict (format validation is the caller's job).
#[test]
fn p5_unit_no_at_sign_clean() {
    let v = p().check("notanemail");
    assert!(v.is_clean());
}

/// Email that is just "@" does not panic and returns clean.
#[test]
fn p5_unit_only_at_sign_no_panic() {
    let v = p().check("@");
    assert!(v.is_clean());
}

/// Empty string does not panic.
#[test]
fn p5_unit_empty_string_no_panic() {
    let v = p().check("");
    assert!(v.is_clean());
}

/// Multiple @ signs: rfind finds the last one (standard email parsing).
#[test]
fn p5_unit_multiple_at_signs() {
    // "a@b" as the local part, "example.com" as domain.
    let v = p().check("a@b@example.com");
    assert!(!v.is_disposable, "example.com is not disposable");
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: case variations
// ─────────────────────────────────────────────────────────────────────────────

/// Uppercase domain is still detected as disposable.
#[test]
fn p5_adversarial_uppercase_domain_detected() {
    let v = p().check("user@MAILINATOR.COM");
    assert!(
        v.is_disposable,
        "uppercase domain must still match; got {v:?}"
    );
}

/// Mixed-case domain is detected.
#[test]
fn p5_adversarial_mixed_case_domain_detected() {
    let v = p().check("user@Mailinator.Com");
    assert!(v.is_disposable);
}

/// Uppercase role local part is still detected.
#[test]
fn p5_adversarial_uppercase_role_detected() {
    let v = p().check("NOREPLY@example.com");
    assert!(v.is_role_address);
}

/// Mixed-case role local part is detected.
#[test]
fn p5_adversarial_mixed_case_role_detected() {
    let v = p().check("NoReply@example.com");
    assert!(v.is_role_address);
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial: near-miss lookalike domains (should NOT be flagged)
// ─────────────────────────────────────────────────────────────────────────────

/// "mymailinator.com" (not in the list) is NOT flagged — exact match only.
#[test]
fn p5_adversarial_superset_domain_not_flagged() {
    let v = p().check("user@mymailinator.com");
    assert!(
        !v.is_disposable,
        "mymailinator.com is not in the blocklist; got {v:?}"
    );
}

/// A subdomain of a disposable domain is NOT flagged by default (exact match).
///
/// Operators who want subdomain coverage should add entries explicitly.
#[test]
fn p5_adversarial_subdomain_of_disposable_not_flagged() {
    let v = p().check("user@mail.mailinator.com");
    assert!(
        !v.is_disposable,
        "subdomain check is caller-opt-in; exact match only; got {v:?}"
    );
}

/// "adminuser" local part is NOT a role address (only exact matches).
#[test]
fn p5_adversarial_admin_prefix_not_role() {
    let v = p().check("adminuser@example.com");
    assert!(
        !v.is_role_address,
        "adminuser is not a role address; got {v:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator-supplied extra domains
// ─────────────────────────────────────────────────────────────────────────────

/// Operator can add a custom disposable domain at startup.
#[test]
fn p5_extra_domain_blocked() {
    let p = BuiltinEmailReputation::new(EmailReputationConfig {
        extra_disposable_domains: vec!["my-internal-throwaway.test".to_owned()],
    });
    let v = p.check("user@my-internal-throwaway.test");
    assert!(v.is_disposable);
}

/// Operator's custom domain does not block a different domain.
#[test]
fn p5_extra_domain_only_blocks_matching() {
    let p = BuiltinEmailReputation::new(EmailReputationConfig {
        extra_disposable_domains: vec!["my-internal-throwaway.test".to_owned()],
    });
    let v = p.check("user@other-domain.test");
    assert!(!v.is_disposable);
}

/// Operator-supplied domain is normalised to lowercase.
#[test]
fn p5_extra_domain_normalised_lowercase() {
    let p = BuiltinEmailReputation::new(EmailReputationConfig {
        extra_disposable_domains: vec!["MyCustom-Throwaway.EXAMPLE".to_owned()],
    });
    let v = p.check("user@mycustom-throwaway.example");
    assert!(v.is_disposable);
}

/// The built-in list is still active when extras are supplied.
#[test]
fn p5_builtin_list_remains_active_with_extras() {
    let p = BuiltinEmailReputation::new(EmailReputationConfig {
        extra_disposable_domains: vec!["extra-domain.test".to_owned()],
    });
    // Built-in entry should still work.
    let v = p.check("user@mailinator.com");
    assert!(v.is_disposable);
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict helper
// ─────────────────────────────────────────────────────────────────────────────

/// is_clean() returns true only when all flags are false.
#[test]
fn p5_is_clean_all_flags_false() {
    let clean = EmailReputationVerdict::default();
    assert!(clean.is_clean());
}

/// is_clean() returns false when is_disposable is set.
#[test]
fn p5_is_clean_false_when_disposable() {
    let v = EmailReputationVerdict {
        is_disposable: true,
        ..Default::default()
    };
    assert!(!v.is_clean());
}

/// is_clean() returns false when is_role_address is set.
#[test]
fn p5_is_clean_false_when_role() {
    let v = EmailReputationVerdict {
        is_role_address: true,
        ..Default::default()
    };
    assert!(!v.is_clean());
}
