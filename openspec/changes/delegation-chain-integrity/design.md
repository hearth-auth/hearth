## Context

Token exchange (RFC 8693) builds an `act` chain, one link per hop. Each exchange stores a
`StoredDelegationGrant` so the user can list and revoke it. AATs carry their own chain in
`aat_parent` and `aat_chain`, and Hearth is their only signer.

This change makes three rules hold:

1. The act-chain depth ceiling is one configured number, read by token validation and by token
   exchange.
2. Revoking a delegation also revokes every token exchanged onward from it.
3. AAT validation checks each link of the chain against a record that Hearth wrote when it minted
   the link.

## Goals / Non-Goals

**Goals:**
- `security.max_act_chain_depth`: default `3`, range `1`–`32`, used everywhere a depth ceiling
  applies.
- A revoke walk that reaches every onward exchange, with no window in which a concurrent exchange
  escapes it.
- AAT validation that does not depend only on the claims inside the presented token.

**Non-Goals:**
- Cascading other revocations (RFC 7009 `/revoke`, logout) to onward exchanges. Section 2 below
  closes the window for those too, but it does not walk the stored tree for them.
- Changing what `max_delegation_depth` means. It stays "the deepest chain this agent may take part
  in", as the exchange code applies it today.
- Changing the hot path. `validate_token` gains no allocation and no storage read.

## Decisions

### 1. One configured ceiling

- `SecurityYaml.max_act_chain_depth: u8`, default `3`. `Config::validate` refuses a value outside
  `1`–`32` and names the key. The key is registered in `src/config/security_keys.rs`.
- `IdentityConfig.max_act_chain_depth: u8`, default `3`. `main.rs` copies the YAML value into both
  `IdentityConfig` arms (`--dev` and production).
- The constant `abuse::MAX_ACT_CHAIN_DEPTH` is deleted. Every reader uses the config value.
- **Why 32:** a deeper chain does not weaken a check, but each link adds an `act` object to the
  token. Past about 32 links a delegated token can pass common 8 KB request-header limits. So 32 is
  a size bound, not a policy. RFC 8693 sets no number.
- **Counting:** `ActClaim::depth_up_to(limit) -> usize` walks the chain in a loop and stops at
  link `limit + 1`, so it returns at most `limit + 1`. It does not allocate and does not recurse,
  so it is safe in `validate_token`. `ActClaim::depth` is deleted, so no caller can count a long
  chain without a bound.
- **Agent depth:** create and update refuse a `max_delegation_depth` outside `1`–ceiling. At
  exchange time the actor's ceiling is `min(agent.max_delegation_depth, ceiling)`, and a non-agent
  actor gets the ceiling. So a stored value above a later, lower ceiling is capped, not trusted.

### 2. Onward revocation

- `StoredDelegationGrant` gains `parent_token_jti: Option<String>`: the `jti` of the subject token
  of the exchange. It is `None` only when the subject token had no `jti`.
- A new index row `dgrant:parent:{parent_jti}:{delegation_id}` points from the parent token to the
  child grant. Its value is the child token's `exp` as 8 bytes LE, so the cleanup sweep can drop it
  once the child expires.
- **Store, then re-check (exchange side):** after the token is signed, the exchange stores the
  grant and the index row, then reads the revoked-`jti` row of `parent_token_jti`. If the parent is
  revoked, the exchange revokes the new grant and fails with `invalid_grant`. A failed grant write
  now fails the exchange. Before, the error was dropped, and the token was returned with no grant
  that could revoke it.
- **Revoke, then walk (revoke side):** revoking a grant writes its `token_jti` to the revoked-`jti`
  blocklist first, then scans `dgrant:parent:{token_jti}:` and revokes each child the same way.
  The walk uses a work list, not recursion. Each child is visited once, because a child that is
  already revoked is skipped.
- **Why no window:** each side writes its own row before it reads the other side's row. If the
  revoke scan runs before the child's index row exists, the exchange's re-check then runs after the
  parent's blocklist row exists, and it sees it. Both writes and reads go through the same storage
  engine (Raft-routed in cluster mode), so one of the two always sees the other.
- Each cascaded child records `AgentTokenRevoked` with `"via": "cascade"` and the parent's
  `delegation_id`.
- `validate_token`, `introspect` and `decide` already read the revoked-`jti` blocklist and its
  cache. The walk writes the same rows through `encode_revoked_jti` and
  `insert_revoked_jti_cache`, so no read path changes.

### 3. AAT records

- `issue_aat` and `derive_aat` store an `AatRecord` at `aat:rec:{jti}` before they return the
  token: `sub`, `aud`, `exp`, `tools`, `scope`, `parent` and `chain`. A failed write fails the call.
- `parse_and_validate_aat`, after the signature, expiry, audience and agent checks:
  1. **Structure:** `aat_chain` is not empty, has no repeated `jti`, ends with the token's own
     `jti`, and is at most `MAX_AAT_CHAIN_DEPTH + 1` long. `aat_parent` is `None` for a chain of
     one, else it is the link before the last.
  2. **Records:** each `jti` in the chain has a record. The token's own record must equal the
     presented claims (`sub`, `aud`, `exp`, `tools`, `scope`, `parent`, `chain`). Each record's
     `parent` must be the link before it.
  3. **Narrowing:** for each link after the root, its tools pass `validate_tools_subset` against the
     previous link's record, and its scopes are a subset of the previous link's scopes.
  4. **Revocation:** unchanged. Every `jti` in the chain is checked against `aat:rev:`.
- The records are read in the same loop as the revocation rows. The chain is at most 6 links, and
  AAT validation is not on the hot path.
- The cleanup sweep deletes an `aat:rec:` row once its `exp` has passed.

## Risks / Trade-offs

- **AATs minted before this change have no record, so they fail validation.** An AAT lives at most
  1 hour, and Hearth has no production users. Callers derive or issue a new one.
- **A backup does not carry `aat:rec:` rows.** After a restore, AATs minted on the source fail on
  the target, for the same reason. This fails closed, and the rows live 1 hour at most.
- **The `dgrant:` rows are not swept today.** The new `dgrant:parent:` index is swept by `exp`. The
  older `dgrant:id:` and `dgrant:user:` rows keep their present lifetime; that is unchanged here.
- **The revoke walk fans out with the tree.** A delegation exchanged onward many times does many
  writes in one revoke. This is the cost of the rule, and each child is written once.
