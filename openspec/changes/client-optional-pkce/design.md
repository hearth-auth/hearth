## Context

Hearth refuses an authorization request without `code_challenge` in four places: the engine authorization (`authorize`), the pushed authorization request (PAR) path, and the two checks of the browser authorize page. The code exchange checks the `code_verifier` only when the stored code has a challenge.

## Goals / Non-Goals

**Goals:**
- An admin can let one confidential client send authorization requests without PKCE (owner decision on #780).
- A public client always needs PKCE, whatever its record says.
- A client that sends PKCE gets the same checks as before.

**Non-Goals:**
- A global or per-realm opt-out.
- The RFC 9700 §2.1.1 `nonce` condition: Hearth cannot make sure that a client checks the nonce, so the owner chose an explicit per-client setting.
- An admin UI control. The admin API and `hearth.yaml` set it; the UI can follow.

## Decisions

1. **One effective rule.** PKCE is required when `client.require_pkce()` is `true` OR the client is public (`OAuthClient::is_public`). The gates use this one method, so a client that loses its secret later needs PKCE again, also if its record still says `false`.
   - Pro: no gate can forget the public-client rule.
   - Con: a record can say `false` and have no effect; the admin API refuses that combination on each write, so it only happens on a record that an import or a reconcile wrote with a later credential change.
2. **Refuse `require_pkce: false` for a public client** at create, update, reconcile and import. The engine error and the config validation error name the field. The admin API answers `400` with the generic `invalid input` body, as for every other engine validation error, so no engine reason goes out on the wire.
3. **Downgrade protection at the exchange.** A code without a stored challenge and a request with a `code_verifier` is `invalid_grant`. Without the setting, every code has a challenge, so this changes nothing for other clients.
4. **Default `true` with a serde default.** Client records are JSON (`get_client_inner`), so a record without the field reads as `true`. No store format bump.
5. **Dynamic client registration cannot set it.** RFC 7591 has no such metadata, and an open registration endpoint must not lower the PKCE rule.
6. **YAML is authoritative.** Reconcile re-applies `require_pkce` on every load, so the admin API refuses a runtime change of a YAML-declared application with `409`, like `dpop_bound_access_tokens`.
   - Pro: an operator does not see a value that the next restart reverts.
   - Con: for a YAML-declared client, the only way to change it is `hearth.yaml`.

## Risks / Trade-offs

- [An admin turns PKCE off for a client that does not check `nonce` or `state`] → The authorization code can then be injected (RFC 9700 §4.5). The docs say to use it only for a client that cannot send PKCE, such as the conformance suite's static clients.
- [The setting spreads to production clients] → Default on, one client at a time, and the admin API response shows the value.
