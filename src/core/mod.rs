//! Core types and traits shared across all Hearth layers.
//!
//! Contains only types and traits — no logic, no state, no I/O.

mod error;
pub mod pagination;
mod time;
mod types;

pub use error::CoreError;
pub use pagination::{
    Page, PageRequest, PagedResult, DEFAULT_COUNT_CAP, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT,
};
pub use time::{Clock, FakeClock, SystemClock, Timestamp};
pub use types::{
    AgentCredentialId, AgentId, AuditEventId, ClientId, IdpId, InvitationId, OrganizationId,
    RealmId, ResourceServerId, SessionId, Uri, UriError, UserId, WebhookDeliveryId, WebhookId,
};
