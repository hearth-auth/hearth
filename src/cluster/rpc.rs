//! Generated gRPC types for the cluster peer transport.
//!
//! The proto source lives at `proto/hearth/cluster/v1/raft.proto`. Unlike
//! the API protos, `build.rs` does not compile it: the generated file under
//! `src/cluster/generated/` is committed. Regenerate it after editing the
//! proto with `tonic_prost_build::configure().build_server(true)
//! .build_client(true)` (the workspace's pinned `tonic-prost-build`), which
//! reproduces the committed file byte for byte.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::needless_lifetimes,
    clippy::return_self_not_must_use,
    clippy::too_many_lines,
    clippy::manual_let_else,
    clippy::match_single_binding,
    clippy::elidable_lifetime_names,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::default_trait_access,
    mismatched_lifetime_syntaxes
)]

include!("generated/hearth.cluster.v1.rs");
