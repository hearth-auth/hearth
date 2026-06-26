//! Hearth identity platform Rust SDK.
//!
//! Provides [`HearthClient`] (auth flows, RBAC predicates, JWKS-backed EdDSA verification)
//! and [`AdminClient`] (user/realm/role/group/org CRUD).
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use hearth_sdk::{HearthClientBuilder, pkce::generate_pkce_pair};
//!
//! let client = HearthClientBuilder::new("https://auth.example.com/realms/my-realm")
//!     .client_id("my-app")
//!     .client_secret("s3cr3t")
//!     .build();
//!
//! // PKCE authorization code flow
//! let pkce = generate_pkce_pair();
//! // ... redirect user to authorization URL with pkce.challenge ...
//! // After callback:
//! let tokens = client.exchange_code(code, client_id, secret, redirect_uri,
//!                                   Some(&pkce.verifier)).await?;
//!
//! // Verify a token (full Ed25519/EdDSA signature check)
//! let claims = client.verify_token(&tokens.access_token).await?;
//! println!("user: {}", claims.subject());
//!
//! // Machine-to-machine
//! let m2m = client.client_credentials(client_id, secret, Some("read:users")).await?;
//! ```
//!
//! ## Feature flags
//!
//! | Feature | What it adds |
//! |---------|--------------|
//! | `tower-middleware` | [`middleware::RequirePermissionLayer`] — Tower layer for mode-aware permission enforcement |
//! | `actix-middleware` | [`actix::HearthActixMiddleware`] + [`actix::RequirePermission`] extractor — Actix-web 4 middleware |

mod admin;
mod claims;
mod client;
mod error;
mod types;

pub mod jwks_cache;
pub mod pkce;

#[cfg(feature = "tower-middleware")]
pub mod middleware;

#[cfg(feature = "actix-middleware")]
pub mod actix;

pub use admin::AdminClient;
pub use claims::Claims;
pub use client::{HearthClient, HearthClientBuilder, HearthClientConfig};
pub use error::HearthError;
pub use jwks_cache::JwksCache;
pub use pkce::generate_pkce_pair;
pub use types::*;
