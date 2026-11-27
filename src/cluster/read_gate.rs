//! The read gate: whether this cluster node may serve a read now
//! (`cluster-consistency` R2, V2).
//!
//! A node serves a read only while it is **in contact**: a follower accepted
//! an `AppendEntries` from the current leader within
//! `cluster.read_lag_threshold_ms`, or a leader had a quorum acknowledgement
//! within it. The lag hold closes the gate whatever the contact: applied
//! entries lag received ones beyond the threshold.
//!
//! While `serve` starts, the start-up bit skips the contact check (not the
//! holds): start-up reads build caches and serve no client, so a node that
//! cannot reach a quorum still starts, and then answers `503`. See
//! [`ReadGate::begin_start_up`].
//!
//! The whole state is one [`AtomicU64`], so the read side is one `Acquire`
//! load and two compares: no allocation, no lock, no yield. Every writer runs
//! off the hot path (the peer server, the lag monitor).
//!
//! Word layout:
//!
//! | Bits | Meaning |
//! |---|---|
//! | 62 | Lag hold: applied entries lag received ones beyond the threshold. |
//! | 61 | Start-up: the contact check is skipped. |
//! | 0–60 | Deadline, in milliseconds since the gate was made. |
//!
//! The deadline uses a monotonic clock, so a wall-clock step cannot extend it
//! (C1).
//!
//! On a leader the gate also records when a quorum last acknowledged it.
//! Each `AppendEntries` it sends carries the age of that acknowledgement, and
//! a follower counts the request as contact only while the age is below the
//! leader lease less 1 s: a deposed leader cut off with a follower would
//! otherwise keep it serving the deposed leader's frozen state.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Bit set while the apply-lag check fails.
const LAG_HOLD: u64 = 1 << 62;
/// Bit set while `serve` starts: the contact check is skipped.
const START_UP: u64 = 1 << 61;
/// The deadline bits.
const DEADLINE: u64 = START_UP - 1;
/// `quorum_ack_ms` value: no quorum acknowledgement on record.
const NO_ACK: u64 = u64::MAX;

/// Why the gate refuses a read now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Applied entries lag received ones beyond the threshold.
    ReplicationLag,
    /// No contact with the leader (or, on a leader, with a quorum) within
    /// the threshold.
    NotInContact,
}

/// Whether this node may serve a read now. See the module docs.
#[derive(Debug)]
pub(crate) struct ReadGate {
    word: AtomicU64,
    /// How long one contact keeps the gate open.
    threshold_ms: u64,
    /// The zero of the deadline clock.
    origin: Instant,
    /// When a quorum last acknowledged this node as leader, in deadline-clock
    /// milliseconds, or [`NO_ACK`]. Off the hot path.
    quorum_ack_ms: AtomicU64,
}

impl ReadGate {
    /// A closed gate: no contact yet, no hold.
    pub(crate) fn new(threshold_ms: u64) -> Self {
        Self {
            word: AtomicU64::new(0),
            threshold_ms,
            origin: Instant::now(),
            quorum_ack_ms: AtomicU64::new(NO_ACK),
        }
    }

    /// Milliseconds since the gate was made, on the monotonic clock.
    pub(crate) fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis())
            .unwrap_or(DEADLINE)
            .min(DEADLINE)
    }

    /// Records that a quorum acknowledged this node as leader at `at_ms`.
    /// Never moves the record back.
    pub(crate) fn record_quorum_ack_at(&self, at_ms: u64) {
        let at_ms = at_ms.min(DEADLINE);
        // Rust 1.99 renamed `fetch_update` to `try_update`; the MSRV (1.88)
        // has only the old name.
        #[allow(deprecated)]
        let _ = self
            .quorum_ack_ms
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current == NO_ACK || at_ms > current).then_some(at_ms)
            });
    }

    /// Forgets the quorum acknowledgement: this node is not the leader. A
    /// node that leads again starts with none, so its first heartbeats of a
    /// new term carry no age from an old one.
    pub(crate) fn clear_quorum_ack(&self) {
        self.quorum_ack_ms.store(NO_ACK, Ordering::Release);
    }

    /// Milliseconds since a quorum last acknowledged this node as leader, or
    /// `None` with none on record. Sent with every `AppendEntries`.
    pub(crate) fn quorum_ack_age_ms(&self) -> Option<u64> {
        self.quorum_ack_age_at(self.now_ms())
    }

    /// [`Self::quorum_ack_age_ms`] at `now_ms`.
    pub(crate) fn quorum_ack_age_at(&self, now_ms: u64) -> Option<u64> {
        let at = self.quorum_ack_ms.load(Ordering::Acquire);
        (at != NO_ACK).then(|| now_ms.saturating_sub(at))
    }

    /// Whether a read may be served now. The hot-path check.
    pub(crate) fn allows(&self) -> bool {
        self.allows_at(self.now_ms())
    }

    /// Whether a read may be served at `now_ms`.
    pub(crate) fn allows_at(&self, now_ms: u64) -> bool {
        let word = self.word.load(Ordering::Acquire);
        word & LAG_HOLD == 0 && (word & START_UP != 0 || now_ms < word & DEADLINE)
    }

    /// Why a read at `now_ms` is refused, or `None` when it is allowed.
    /// Off the hot path: called only to describe a refusal.
    pub(crate) fn refusal_at(&self, now_ms: u64) -> Option<Refusal> {
        let word = self.word.load(Ordering::Acquire);
        if word & LAG_HOLD != 0 {
            Some(Refusal::ReplicationLag)
        } else if word & START_UP == 0 && now_ms >= word & DEADLINE {
            Some(Refusal::NotInContact)
        } else {
            None
        }
    }

    /// Records a contact at `at_ms`: the gate stays open until
    /// `at_ms + threshold`. Never moves the deadline back.
    pub(crate) fn record_contact_at(&self, at_ms: u64) {
        let deadline_ms = at_ms.saturating_add(self.threshold_ms).min(DEADLINE);
        // The closure returns `None` only when the deadline is already
        // later, which leaves the word as it is. Rust 1.99 renamed
        // `fetch_update` to `try_update`; the MSRV (1.88) has only the old
        // name.
        #[allow(deprecated)]
        let _ = self
            .word
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                (deadline_ms > word & DEADLINE).then_some((word & !DEADLINE) | deadline_ms)
            });
    }

    /// Closes the gate at once: forgets the last contact. The next contact
    /// opens it again. Test-only until the snapshot install fence (task 3.1)
    /// calls it.
    #[cfg(test)]
    pub(crate) fn close(&self) {
        self.word.fetch_and(!DEADLINE, Ordering::AcqRel);
    }

    /// Sets or clears the lag hold. The deadline is kept: when the lag
    /// clears, a node still in contact serves reads again at once.
    pub(crate) fn set_lag_hold(&self, held: bool) {
        if held {
            self.word.fetch_or(LAG_HOLD, Ordering::AcqRel);
        } else {
            self.word.fetch_and(!LAG_HOLD, Ordering::AcqRel);
        }
    }

    /// Sets the start-up bit: reads skip the contact check until
    /// [`Self::end_start_up`]. The lag hold still applies.
    pub(crate) fn begin_start_up(&self) {
        self.word.fetch_or(START_UP, Ordering::AcqRel);
    }

    /// Clears the start-up bit: from now on a read needs contact.
    pub(crate) fn end_start_up(&self) {
        self.word.fetch_and(!START_UP, Ordering::AcqRel);
    }
}

/// How a node's own Raft metrics show its contact as a leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaderContact {
    /// This node does not lead. Its contact comes from `AppendEntries`.
    NotLeader,
    /// This node is the only voter: it is its own quorum, always in contact.
    SoleVoter,
    /// A quorum acknowledged this leader `ms` milliseconds before the
    /// metrics were reported, within the threshold.
    AckedAgo { ms: u64 },
    /// No quorum acknowledged this leader within the threshold.
    OutOfContact,
}

/// The [`LeaderContact`] of node `id` from its Raft metrics.
pub(crate) fn leader_contact(
    id: u64,
    current_leader: Option<u64>,
    millis_since_quorum_ack: Option<u64>,
    voters: usize,
    threshold_ms: u64,
) -> LeaderContact {
    if current_leader != Some(id) {
        return LeaderContact::NotLeader;
    }
    if voters <= 1 {
        return LeaderContact::SoleVoter;
    }
    match millis_since_quorum_ack {
        Some(ms) if ms < threshold_ms => LeaderContact::AckedAgo { ms },
        _ => LeaderContact::OutOfContact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 500;

    #[test]
    fn a_new_gate_is_closed() {
        let gate = ReadGate::new(T);
        assert!(!gate.allows_at(0));
        assert_eq!(gate.refusal_at(0), Some(Refusal::NotInContact));
    }

    #[test]
    fn a_contact_opens_the_gate_until_its_deadline() {
        let gate = ReadGate::new(T);
        gate.record_contact_at(1_000);
        assert!(gate.allows_at(1_000));
        assert_eq!(gate.refusal_at(1_000), None);
        assert!(
            gate.allows_at(1_000 + T - 1),
            "open just before the deadline"
        );
        assert!(!gate.allows_at(1_000 + T), "closed at the deadline");
        assert!(!gate.allows_at(1_000 + T + 1), "closed after the deadline");
        assert_eq!(gate.refusal_at(1_000 + T), Some(Refusal::NotInContact));
    }

    #[test]
    fn an_older_contact_never_moves_the_deadline_back() {
        let gate = ReadGate::new(T);
        gate.record_contact_at(2_000);
        gate.record_contact_at(1_000);
        assert!(gate.allows_at(2_000 + T - 1));
    }

    #[test]
    fn closing_refuses_at_once_until_the_next_contact() {
        let gate = ReadGate::new(T);
        gate.record_contact_at(1_000);
        gate.close();
        assert!(
            !gate.allows_at(1_001),
            "closed at once, before the deadline"
        );
        assert_eq!(gate.refusal_at(1_001), Some(Refusal::NotInContact));
        gate.record_contact_at(1_002);
        assert!(gate.allows_at(1_003), "a later contact opens it");
    }

    #[test]
    fn the_live_clock_starts_closed_and_opens_on_a_contact() {
        let gate = ReadGate::new(T);
        assert!(!gate.allows());
        gate.record_contact_at(gate.now_ms());
        assert!(gate.allows());
    }

    #[test]
    fn start_up_skips_the_contact_check_until_it_ends() {
        let gate = ReadGate::new(T);
        gate.begin_start_up();
        assert!(gate.allows_at(1_000), "no contact needed at start-up");
        assert_eq!(gate.refusal_at(1_000), None);
        gate.record_contact_at(1_000);
        gate.end_start_up();
        assert!(gate.allows_at(1_000 + T - 1), "the contact was kept");
        assert!(!gate.allows_at(1_000 + T), "contact is needed again");
    }

    #[test]
    fn the_lag_hold_closes_the_gate_and_keeps_the_contact() {
        let gate = ReadGate::new(T);
        gate.record_contact_at(1_000);
        gate.set_lag_hold(true);
        assert!(
            !gate.allows_at(1_001),
            "closed at once, before the deadline"
        );
        assert_eq!(gate.refusal_at(1_001), Some(Refusal::ReplicationLag));
        gate.record_contact_at(1_100);
        assert!(!gate.allows_at(1_101), "a contact does not lift the hold");
        gate.set_lag_hold(false);
        assert!(gate.allows_at(1_101), "the node is still in contact");
        assert!(!gate.allows_at(1_100 + T));
    }

    #[test]
    fn start_up_does_not_skip_the_lag_hold() {
        let gate = ReadGate::new(T);
        gate.begin_start_up();
        gate.set_lag_hold(true);
        assert_eq!(gate.refusal_at(0), Some(Refusal::ReplicationLag));
        gate.set_lag_hold(false);
        assert!(gate.allows_at(0), "still starting up");
    }

    #[test]
    fn closing_keeps_the_lag_hold() {
        let gate = ReadGate::new(T);
        gate.set_lag_hold(true);
        gate.close();
        gate.record_contact_at(1_000);
        assert_eq!(gate.refusal_at(1_001), Some(Refusal::ReplicationLag));
    }

    #[test]
    fn a_leader_acked_within_the_threshold_is_in_contact() {
        assert_eq!(
            leader_contact(1, Some(1), Some(T - 1), 3, T),
            LeaderContact::AckedAgo { ms: T - 1 }
        );
    }

    #[test]
    fn a_leader_not_acked_within_the_threshold_is_out_of_contact() {
        assert_eq!(
            leader_contact(1, Some(1), Some(T), 3, T),
            LeaderContact::OutOfContact
        );
        assert_eq!(
            leader_contact(1, Some(1), Some(10 * T), 3, T),
            LeaderContact::OutOfContact
        );
        assert_eq!(
            leader_contact(1, Some(1), None, 3, T),
            LeaderContact::OutOfContact,
            "a leader no quorum ever acknowledged"
        );
    }

    #[test]
    fn a_sole_voter_is_never_out_of_contact() {
        assert_eq!(
            leader_contact(1, Some(1), None, 1, T),
            LeaderContact::SoleVoter
        );
        assert_eq!(
            leader_contact(1, Some(1), Some(10 * T), 1, T),
            LeaderContact::SoleVoter
        );
    }

    #[test]
    fn a_follower_gets_no_contact_from_its_own_metrics() {
        assert_eq!(
            leader_contact(2, Some(1), Some(0), 3, T),
            LeaderContact::NotLeader
        );
        assert_eq!(
            leader_contact(2, None, None, 3, T),
            LeaderContact::NotLeader
        );
    }

    #[test]
    fn a_new_gate_has_no_quorum_ack() {
        assert_eq!(ReadGate::new(T).quorum_ack_age_ms(), None);
    }

    #[test]
    fn the_quorum_ack_age_counts_from_the_latest_ack() {
        let gate = ReadGate::new(T);
        gate.record_quorum_ack_at(700);
        gate.record_quorum_ack_at(100);
        assert_eq!(
            gate.quorum_ack_age_at(1_000),
            Some(300),
            "the older ack is ignored"
        );
        gate.clear_quorum_ack();
        assert_eq!(gate.quorum_ack_age_at(1_000), None);
    }

    #[test]
    fn closing_keeps_the_start_up_bit() {
        let gate = ReadGate::new(T);
        gate.begin_start_up();
        gate.close();
        assert!(gate.allows_at(1_000), "still starting up");
        gate.end_start_up();
        assert!(!gate.allows_at(1_000));
    }
}
