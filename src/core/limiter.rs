//! Building blocks every in-process rate limiter shares.
//!
//! * [`rate_limit_key`] — the one mapping from a client address to the key a
//!   per-IP limiter counts it under. IPv6 peers are counted per `/64`: a
//!   single host is routinely handed a whole `/64`, so a per-address budget is
//!   2^64 budgets for one attacker (GA sweep 3, E-3).
//! * [`ExpiringMap`] — a bounded map whose entries carry an expiry. Every
//!   limiter's per-key state lives in one of these, so no limiter's memory
//!   grows with the number of distinct keys an anonymous caller can invent
//!   (GA sweep 3, E-2).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Returns the key a per-IP rate limiter counts `ip` under.
///
/// * IPv4 — the address itself.
/// * IPv4-mapped IPv6 (`::ffff:a.b.c.d`) — the IPv4 address, so a dual-stack
///   listener counts a client the same whichever family it arrives on.
/// * IPv6 — the address with its low 64 bits cleared: the `/64` the host was
///   assigned. The connection cap (`PerIpLimiter`) buckets the same way.
#[must_use]
pub fn rate_limit_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        v4 @ IpAddr::V4(_) => v4,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// [`rate_limit_key`] for a limiter whose key is a string.
///
/// A string that parses as an address is replaced by its rate-limit key's
/// canonical text form. Anything else is returned unchanged, so a caller that
/// passes a non-address discriminator keeps its own bucket.
#[must_use]
pub fn rate_limit_key_str(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(addr) => rate_limit_key(addr).to_string(),
        Err(_) => ip.to_owned(),
    }
}

/// A point in time an [`ExpiringMap`] can order entries by.
///
/// Implemented for [`Instant`] and for `i64` microseconds (the limiters whose
/// callers pass `now_micros` so tests can drive time).
pub trait LimiterClock: Copy + Ord {
    /// `self` advanced by `by`, saturating instead of overflowing.
    #[must_use]
    fn plus(self, by: Duration) -> Self;
}

impl LimiterClock for Instant {
    fn plus(self, by: Duration) -> Self {
        self.checked_add(by).unwrap_or(self)
    }
}

impl LimiterClock for i64 {
    fn plus(self, by: Duration) -> Self {
        self.saturating_add(i64::try_from(by.as_micros()).unwrap_or(i64::MAX))
    }
}

/// Size at which an insert first sweeps idle entries, independent of the
/// periodic interval.
pub const SWEEP_FLOOR: usize = 1_024;

/// One entry: the caller's value and the time after which dropping it changes
/// no decision.
struct Slot<V, T> {
    value: V,
    expires_at: T,
}

/// A bounded map from a limiter key to that key's state.
///
/// Each entry carries an `expires_at` supplied by the caller on every write:
/// the time after which the entry carries no information, i.e. a fresh entry
/// would make exactly the decisions the old one would. Dropping an expired
/// entry is therefore invisible.
///
/// Expired entries are dropped
///
/// * on a periodic sweep, run by the first write at least `sweep_interval`
///   after the previous one;
/// * when an insert finds the map at its sweep threshold, which starts at
///   [`SWEEP_FLOOR`] and doubles with the live population so the work stays
///   amortised O(1) per insert.
///
/// The map never holds more than `capacity` entries. When an insert of a new
/// key finds it full of live entries, it evicts the eighth of them that expire
/// soonest — the entries carrying the least remaining information. That
/// eviction *is* visible (the evicted keys start afresh) and is the price of a
/// hard memory bound under a flood of distinct keys.
///
/// Not synchronised: limiters wrap it in their own `Mutex`.
pub struct ExpiringMap<K, V, T = Instant> {
    entries: HashMap<K, Slot<V, T>>,
    capacity: usize,
    sweep_interval: Duration,
    next_sweep: Option<T>,
    sweep_at_len: usize,
}

impl<K, V, T> fmt::Debug for ExpiringMap<K, V, T> {
    // Keys are client addresses and account ids: report the shape, not them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpiringMap")
            .field("len", &self.entries.len())
            .field("capacity", &self.capacity)
            .field("sweep_interval", &self.sweep_interval)
            .finish_non_exhaustive()
    }
}

impl<K: Eq + Hash, V, T: LimiterClock> ExpiringMap<K, V, T> {
    /// Creates an empty map holding at most `capacity` entries (at least one)
    /// and sweeping expired entries every `sweep_interval`.
    #[must_use]
    pub fn new(capacity: usize, sweep_interval: Duration) -> Self {
        let capacity = capacity.max(1);
        Self {
            entries: HashMap::new(),
            capacity,
            sweep_interval,
            next_sweep: None,
            sweep_at_len: SWEEP_FLOOR.min(capacity),
        }
    }

    /// Number of entries held, expired or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the map holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The value stored for `key`, if any.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries.get(key).map(|slot| &slot.value)
    }

    /// Removes `key`, returning its value.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries.remove(key).map(|slot| slot.value)
    }

    /// Updates the entry for `key`, inserting `init()` first when absent.
    ///
    /// `update` mutates the value and returns the caller's result together
    /// with the entry's new expiry. `now` drives the periodic sweep and the
    /// insert-time maintenance described on the type.
    pub fn upsert<R>(
        &mut self,
        key: K,
        now: T,
        init: impl FnOnce() -> V,
        update: impl FnOnce(&mut V) -> (R, T),
    ) -> R {
        match self.next_sweep {
            Some(due) if now < due => {}
            _ => {
                self.sweep(now);
            }
        }
        if !self.entries.contains_key(&key) {
            self.make_room(now);
        }
        let slot = self.entries.entry(key).or_insert_with(|| Slot {
            value: init(),
            expires_at: now,
        });
        let (result, expires_at) = update(&mut slot.value);
        slot.expires_at = expires_at;
        result
    }

    /// Drops every entry that expired before `now`; returns how many.
    ///
    /// Also schedules the next periodic sweep and re-arms the size threshold
    /// at twice the surviving population (never below [`SWEEP_FLOOR`], never
    /// above the capacity).
    pub fn sweep(&mut self, now: T) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, slot| slot.expires_at >= now);
        let after = self.entries.len();
        self.next_sweep = Some(now.plus(self.sweep_interval));
        self.sweep_at_len = after.saturating_mul(2).max(SWEEP_FLOOR).min(self.capacity);
        before - after
    }

    /// Ensures an insert of one new key keeps the map within its bounds.
    fn make_room(&mut self, now: T) {
        if self.entries.len() < self.sweep_at_len {
            return;
        }
        self.sweep(now);
        if self.entries.len() >= self.capacity {
            self.evict_soonest((self.capacity / 8).max(1));
        }
    }

    /// Evicts exactly `count` entries (or all of them, if fewer), choosing
    /// those that expire soonest. O(n); runs at most once per `count` inserts.
    fn evict_soonest(&mut self, count: usize) {
        let len = self.entries.len();
        if count >= len {
            self.entries.clear();
            return;
        }
        let mut expiries: Vec<T> = self.entries.values().map(|slot| slot.expires_at).collect();
        let (_, &mut cutoff, _) = expiries.select_nth_unstable(count - 1);
        // Everything strictly before the cutoff goes; ties at the cutoff go
        // only until `count` entries are gone.
        let strictly_before = expiries[..count].iter().filter(|&&e| e < cutoff).count();
        let mut ties_to_evict = count - strictly_before;
        self.entries.retain(|_, slot| {
            if slot.expires_at < cutoff {
                false
            } else if slot.expires_at == cutoff && ties_to_evict > 0 {
                ties_to_evict -= 1;
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: i64 = 1_000_000;

    fn map(capacity: usize, sweep_secs: u64) -> ExpiringMap<u32, u32, i64> {
        ExpiringMap::new(capacity, Duration::from_secs(sweep_secs))
    }

    /// Inserts `key` at `now` with an expiry of `expires_at`.
    fn put(m: &mut ExpiringMap<u32, u32, i64>, key: u32, now: i64, expires_at: i64) {
        m.upsert(
            key,
            now,
            || 0,
            |v| {
                *v += 1;
                ((), expires_at)
            },
        );
    }

    // ── rate_limit_key ───────────────────────────────────────────────────────

    #[test]
    fn ipv4_is_its_own_rate_limit_key() {
        let ip: IpAddr = "203.0.113.9".parse().expect("ip literal");
        assert_eq!(rate_limit_key(ip), ip);
    }

    #[test]
    fn two_ipv6_addresses_in_one_slash64_share_a_key() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().expect("ip literal");
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff"
            .parse()
            .expect("ip literal");
        let expected: IpAddr = "2001:db8:1:2::".parse().expect("ip literal");
        assert_eq!(rate_limit_key(a), expected);
        assert_eq!(rate_limit_key(b), expected);
    }

    #[test]
    fn ipv6_addresses_in_different_slash64s_do_not_share_a_key() {
        let a: IpAddr = "2001:db8:1:2::1".parse().expect("ip literal");
        let b: IpAddr = "2001:db8:1:3::1".parse().expect("ip literal");
        assert_ne!(rate_limit_key(a), rate_limit_key(b));
    }

    #[test]
    fn ipv4_mapped_ipv6_is_keyed_as_its_ipv4_address() {
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().expect("ip literal");
        let v4: IpAddr = "203.0.113.9".parse().expect("ip literal");
        assert_eq!(rate_limit_key(mapped), v4);
    }

    #[test]
    fn string_keys_map_addresses_and_keep_everything_else() {
        assert_eq!(rate_limit_key_str("2001:db8::1"), "2001:db8::");
        assert_eq!(rate_limit_key_str("2001:db8::2"), "2001:db8::");
        assert_eq!(rate_limit_key_str("203.0.113.9"), "203.0.113.9");
        assert_eq!(rate_limit_key_str("not-an-ip"), "not-an-ip");
    }

    // ── ExpiringMap ──────────────────────────────────────────────────────────

    /// The periodic sweep drops every expired entry, so after N distinct keys
    /// and their expiry the map shrinks back to what is live.
    #[test]
    fn periodic_sweep_drops_expired_entries() {
        let mut m = map(10_000, 10);
        for k in 0..500 {
            put(&mut m, k, 0, SEC);
        }
        assert_eq!(m.len(), 500);
        // The first write after the interval sweeps.
        put(&mut m, 9_999, 11 * SEC, 12 * SEC);
        assert_eq!(m.len(), 1, "only the entry written after expiry is live");
    }

    /// Crossing the size threshold sweeps without waiting for the interval.
    #[test]
    fn crossing_the_sweep_threshold_drops_expired_entries_early() {
        let mut m = map(1_000_000, 3_600);
        let floor = u32::try_from(SWEEP_FLOOR).expect("floor fits u32");
        for k in 0..floor {
            put(&mut m, k, 0, SEC);
        }
        for k in floor..2 * floor {
            put(&mut m, k, 2 * SEC, 3 * SEC);
        }
        assert_eq!(
            m.len(),
            SWEEP_FLOOR,
            "the first batch expired at 1 s and must be gone by the second"
        );
    }

    /// The capacity is a hard bound even when every entry is live.
    #[test]
    fn hard_cap_holds_when_every_entry_is_live() {
        let mut m = map(100, 3_600);
        for k in 0..10_000 {
            put(&mut m, k, 0, 1_000 * SEC);
            assert!(m.len() <= 100, "len {} exceeds the cap at key {k}", m.len());
        }
    }

    /// At the cap the soonest-expiring entries go first; long-lived state
    /// (a challenge window, say) outlives short-lived junk.
    #[test]
    fn cap_eviction_takes_the_soonest_expiring_entries() {
        let mut m = map(8, 3_600);
        for k in 0..8 {
            let expiry = if k == 3 {
                1_000 * SEC
            } else {
                100 * SEC + i64::from(k)
            };
            put(&mut m, k, 0, expiry);
        }
        put(&mut m, 8, 0, 200 * SEC);
        assert_eq!(m.len(), 8);
        assert!(m.get(&0).is_none(), "key 0 expires soonest and is evicted");
        assert!(m.get(&3).is_some(), "the long-lived entry survives");
        for k in 9..20 {
            put(&mut m, k, 0, 200 * SEC);
        }
        assert!(
            m.get(&3).is_some(),
            "the long-lived entry outlives the churn"
        );
    }

    /// An entry expiring exactly now still carries information and is kept;
    /// sweep reports how many it dropped.
    #[test]
    fn sweep_keeps_entries_that_have_not_expired() {
        let mut m = map(100, 3_600);
        put(&mut m, 1, 0, SEC);
        put(&mut m, 2, 0, 5 * SEC);
        assert_eq!(m.sweep(SEC), 0, "an entry expiring at `now` is kept");
        assert_eq!(m.sweep(SEC + 1), 1);
        assert!(m.get(&1).is_none());
        assert_eq!(m.get(&2), Some(&1));
    }

    /// The expiry an update returns replaces the old one.
    #[test]
    fn an_update_extends_the_expiry() {
        let mut m = map(100, 3_600);
        put(&mut m, 1, 0, SEC);
        put(&mut m, 1, SEC / 2, 10 * SEC);
        assert_eq!(m.sweep(5 * SEC), 0, "the refreshed entry is still live");
        assert_eq!(m.get(&1), Some(&2));
        assert_eq!(m.remove(&1), Some(2));
        assert!(m.is_empty());
    }
}
