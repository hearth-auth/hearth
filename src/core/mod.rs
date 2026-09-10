//! Core types and traits shared across all Hearth layers.
//!
//! Contains only types and traits — no logic, no state, no I/O.

mod error;
pub mod pagination;
pub mod secrets;
mod time;
mod types;

pub use error::CoreError;
pub use pagination::{
    Page, PageRequest, PagedResult, DEFAULT_COUNT_CAP, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT,
};
pub use secrets::{
    ct_eq_secret, ct_eq_secret_opt, ct_eq_secret_str, random_secret_bytes, random_secret_hex,
    random_secret_uuid, SECRET_BYTES,
};
pub use time::{Clock, FakeClock, SystemClock, Timestamp};
pub use types::{
    AgentCredentialId, AgentId, AuditEventId, ClientId, IdpId, ImportOutcome, InvitationId,
    OrganizationId, RealmId, ResourceServerId, SessionId, Uri, UriError, UserId, WebhookDeliveryId,
    WebhookId,
};
