# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Hearth has not yet cut a versioned release; all shipped work appears under `[Unreleased]`.

## [Unreleased]

### Security

- **gRPC cross-realm BFLA (HEA-799)** — all five realm-management gRPC handlers
  (`list_realms`, `get_realm`, `create_realm`, `update_realm`, `delete_realm`) previously
  discarded the authenticated realm (`_auth`) and operated on any caller-supplied realm ID.
  An admin of realm A could read, modify, or destroy realm B with a valid realm-A token.
  Fixed: each handler now enforces that regular realm admins may only operate on their own
  realm; only system-realm admins may act cross-realm or create new realms. Regression tests
  added in `tests/grpc_cross_realm_bfla.rs` (HEA-799).
