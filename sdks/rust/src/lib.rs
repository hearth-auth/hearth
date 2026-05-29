//! Hearth identity platform Rust SDK.
//!
//! Provides [`HearthClient`] (auth flows, RBAC predicates, WebAuthn, mode-aware authz)
//! and [`AdminClient`] (user/realm CRUD).
//!
//! ## Feature flags
//!
//! | Feature | What it adds |
//! |---------|--------------|
//! | `tower-middleware` | [`middleware::RequirePermissionLayer`] — Tower layer for mode-aware permission enforcement |

mod admin;
mod claims;
mod client;
mod error;
mod types;

#[cfg(feature = "tower-middleware")]
pub mod middleware;

pub use admin::AdminClient;
pub use claims::Claims;
pub use client::HearthClient;
pub use error::HearthError;
pub use types::*;
