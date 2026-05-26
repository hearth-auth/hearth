//! Integration tests verifying that the gRPC service boundary sanitizes errors.
//!
//! Covers `HEA-822` (GAP-2): raw `Display` strings from the identity, storage,
//! and audit layers must never reach gRPC callers. Each test class exercises a
//! distinct error category (NotFound, InvalidArgument, Internal) and asserts
//! both the correct `tonic::Code` and that no internal detail leaks into the
//! message.

mod common;

use hearth::audit::AuditError;
use hearth::identity::IdentityError;
use hearth::protocol::grpc::convert::{audit_error_to_status, identity_to_status, rbac_to_status};
use hearth::rbac::RbacError;
use hearth::storage::StorageError;
use tonic::Code;

// ---------------------------------------------------------------------------
// NotFound error class
// ---------------------------------------------------------------------------

#[test]
fn not_found_maps_to_correct_code() {
    let status = identity_to_status(IdentityError::UserNotFound);
    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.message(), "user not found");
}

#[test]
fn realm_not_found_maps_to_not_found() {
    let status = identity_to_status(IdentityError::RealmNotFound);
    assert_eq!(status.code(), Code::NotFound);
    assert_eq!(status.message(), "realm not found");
}

// ---------------------------------------------------------------------------
// InvalidArgument error class
// ---------------------------------------------------------------------------

#[test]
fn invalid_input_maps_to_invalid_argument() {
    let status = identity_to_status(IdentityError::InvalidInput {
        reason: "field 'email' is required".to_string(),
    });
    assert_eq!(status.code(), Code::InvalidArgument);
    // The reason here is user-facing validation feedback — safe to surface.
    assert!(
        status.message().contains("invalid input"),
        "expected 'invalid input' prefix, got: {}",
        status.message()
    );
}

#[test]
fn rbac_invalid_permission_maps_to_invalid_argument() {
    let status = rbac_to_status(RbacError::InvalidPermission {
        reason: "bad::perm".to_string(),
    });
    assert_eq!(status.code(), Code::InvalidArgument);
}

// ---------------------------------------------------------------------------
// Internal error class — the critical sanitization check
// ---------------------------------------------------------------------------

#[test]
fn identity_storage_error_does_not_leak_internals() {
    let storage_err = StorageError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "WAL file: /var/lib/hearth/secret/data.wal permission denied",
    ));
    let identity_err = IdentityError::Storage(Box::new(storage_err));
    let status = identity_to_status(identity_err);

    assert_eq!(
        status.code(),
        Code::Internal,
        "storage errors must be Code::Internal"
    );
    assert_eq!(
        status.message(),
        "internal error",
        "storage error message must not leak raw details; got: {}",
        status.message()
    );
    // Specifically verify the file path from the I/O error did not leak.
    assert!(
        !status.message().contains("WAL"),
        "file path leaked into gRPC status: {}",
        status.message()
    );
    assert!(
        !status.message().contains("secret"),
        "path component leaked into gRPC status: {}",
        status.message()
    );
}

#[test]
fn identity_serialization_error_does_not_leak_internals() {
    let status = identity_to_status(IdentityError::Serialization {
        reason: "unexpected byte 0xff at position 42 in internal serde codec".to_string(),
    });

    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), "internal error");
    assert!(
        !status.message().contains("serde"),
        "serializer detail leaked: {}",
        status.message()
    );
}

#[test]
fn rbac_storage_error_does_not_leak_internals() {
    let io_err = std::io::Error::other("checksum mismatch at offset 0xdeadbeef in rbac.sst");
    let storage_err = StorageError::Io(io_err);
    let status = rbac_to_status(RbacError::Storage(Box::new(storage_err)));

    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), "internal error");
    assert!(
        !status.message().contains("checksum"),
        "storage detail leaked: {}",
        status.message()
    );
}

#[test]
fn audit_storage_error_does_not_leak_internals() {
    let io_err = std::io::Error::other("disk full writing audit log: /var/lib/hearth/audit.wal");
    let storage_err = StorageError::Io(io_err);
    let audit_err = AuditError::Storage(Box::new(storage_err));
    let status = audit_error_to_status(audit_err);

    assert_eq!(
        status.code(),
        Code::Internal,
        "audit storage must be Code::Internal"
    );
    // Message must contain "internal error [<uuid>]" — not the raw I/O string.
    assert!(
        status.message().starts_with("internal error ["),
        "expected opaque error ID, got: {}",
        status.message()
    );
    assert!(
        !status.message().contains("disk"),
        "I/O detail leaked: {}",
        status.message()
    );
    assert!(
        !status.message().contains("hearth"),
        "file path leaked: {}",
        status.message()
    );
}

#[test]
fn audit_serialization_error_does_not_leak_internals() {
    let audit_err = AuditError::Serialization {
        reason: "unexpected key 'secret_field' in audit record JSON".to_string(),
    };
    let status = audit_error_to_status(audit_err);

    assert_eq!(status.code(), Code::Internal);
    assert!(
        status.message().starts_with("internal error ["),
        "expected opaque error ID, got: {}",
        status.message()
    );
    assert!(
        !status.message().contains("secret_field"),
        "field name leaked: {}",
        status.message()
    );
}

#[test]
fn audit_integrity_violation_is_surfaced_safely() {
    let audit_err = AuditError::IntegrityViolation {
        reason: "hash mismatch at event id abc123".to_string(),
    };
    let status = audit_error_to_status(audit_err);

    // IntegrityViolation is surfaced as DataLoss (meaningful to the caller)
    // but without exposing the internal event ID.
    assert_eq!(status.code(), Code::DataLoss);
    assert_eq!(status.message(), "audit chain integrity violation");
    assert!(
        !status.message().contains("abc123"),
        "internal event ID leaked: {}",
        status.message()
    );
}

#[test]
fn identity_signing_error_does_not_leak_internals() {
    let status = identity_to_status(IdentityError::SigningError {
        reason: "key ring corrupted: ed25519 secret key has wrong length 24 != 32".to_string(),
    });

    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), "internal error");
    assert!(
        !status.message().contains("ed25519"),
        "crypto detail leaked: {}",
        status.message()
    );
}
