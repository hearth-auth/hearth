//! One-shot, server-side reveal of a freshly generated client secret.
//!
//! The console mints a client secret when it creates a confidential
//! application or regenerates one. Storage keeps only its hash, so the secret
//! must be shown to the operator once — and answering the POST itself with it
//! meant a browser reload re-submitted the form (the CSRF token is per
//! session), creating a duplicate application or rotating the secret again.
//!
//! The POST instead stashes the secret here and redirects (post/redirect/get)
//! to the application's page, whose GET takes it back out. The secret never
//! travels in a URL, a redirect or a log. An entry is:
//!
//! * **bound to the session** that created it — another session, even another
//!   admin, cannot take it;
//! * **single-use** — the first GET removes it, so a reload shows the page
//!   without it;
//! * **short-lived** — it expires after [`REVEAL_TTL`], and the store holds at
//!   most [`MAX_PENDING`] entries.
//!
//! The store is in-process: behind a load balancer without session affinity
//! the redirected GET can land on another node and show no secret, in which
//! case the operator regenerates it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::core::{ClientId, SessionId};

/// How long a pending reveal waits for its GET.
pub const REVEAL_TTL: Duration = Duration::from_secs(300);

/// Most reveals pending at once, across all sessions.
pub const MAX_PENDING: usize = 1024;

/// A secret waiting to be shown.
struct Pending {
    secret: Zeroizing<String>,
    expires_at: Instant,
}

/// Pending one-shot secret reveals, keyed by `(session, client)`.
///
/// Deliberately not `Debug`: it holds plaintext secrets.
#[derive(Default)]
pub struct SecretReveals {
    pending: Mutex<HashMap<(SessionId, ClientId), Pending>>,
}

impl SecretReveals {
    /// Stashes `secret` for `session` to see once on `client`'s page,
    /// replacing any reveal already pending for the pair.
    pub fn stash(&self, session: &SessionId, client: &ClientId, secret: Zeroizing<String>) {
        self.stash_at(session, client, secret, Instant::now());
    }

    /// Takes the secret pending for `session` on `client`'s page, if any.
    /// A second call answers `None`.
    #[must_use]
    pub fn take(&self, session: &SessionId, client: &ClientId) -> Option<Zeroizing<String>> {
        self.take_at(session, client, Instant::now())
    }

    fn stash_at(
        &self,
        session: &SessionId,
        client: &ClientId,
        secret: Zeroizing<String>,
        now: Instant,
    ) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|_, p| p.expires_at > now);
        if pending.len() >= MAX_PENDING {
            // Drop the entry closest to expiry: its operator has had the
            // longest to follow the redirect.
            if let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, p)| p.expires_at)
                .map(|(k, _)| k.clone())
            {
                pending.remove(&oldest);
            }
        }
        pending.insert(
            (session.clone(), client.clone()),
            Pending {
                secret,
                expires_at: now + REVEAL_TTL,
            },
        );
    }

    fn take_at(
        &self,
        session: &SessionId,
        client: &ClientId,
        now: Instant,
    ) -> Option<Zeroizing<String>> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = pending.remove(&(session.clone(), client.clone()))?;
        (entry.expires_at > now).then_some(entry.secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn a_reveal_is_single_use_and_bound_to_its_session() {
        let store = SecretReveals::default();
        let (mine, theirs) = (SessionId::generate(), SessionId::generate());
        let client = ClientId::generate();
        store.stash(&mine, &client, secret("s3cret"));

        assert!(
            store.take(&theirs, &client).is_none(),
            "another session cannot take it"
        );
        assert!(
            store.take(&mine, &ClientId::generate()).is_none(),
            "nor another client's page"
        );
        assert_eq!(
            store.take(&mine, &client).as_deref().map(String::as_str),
            Some("s3cret")
        );
        assert!(store.take(&mine, &client).is_none(), "shown once");
    }

    #[test]
    fn a_reveal_expires() {
        let store = SecretReveals::default();
        let (session, client) = (SessionId::generate(), ClientId::generate());
        let t0 = Instant::now();
        store.stash_at(&session, &client, secret("s3cret"), t0);
        assert!(store
            .take_at(&session, &client, t0 + REVEAL_TTL + Duration::from_secs(1))
            .is_none());
    }

    #[test]
    fn the_store_is_bounded() {
        let store = SecretReveals::default();
        let t0 = Instant::now();
        for i in 0..(MAX_PENDING + 10) {
            store.stash_at(
                &SessionId::generate(),
                &ClientId::generate(),
                secret("x"),
                t0 + Duration::from_millis(u64::try_from(i).unwrap_or(u64::MAX)),
            );
        }
        let len = store
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert!(len <= MAX_PENDING, "{len} pending reveals");
    }
}
