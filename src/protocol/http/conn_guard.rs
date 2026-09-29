//! Per-connection guards shared by every Hearth listener.
//!
//! GA audit 2026-09-28 B6: one unauthenticated client held every connection
//! slot by opening sockets and never finishing a request. Two pieces here close
//! the part of that the admission gate in [`super::limits`] cannot:
//!
//! 1. [`PerIpLimiter`] caps how many connections one client address may hold
//!    at once, so a single host cannot take every slot.
//! 2. [`FirstBytesDeadline`] closes a connection that does not send its first
//!    bytes in time. hyper's `header_read_timeout` covers HTTP/1 header blocks,
//!    but the automatic HTTP/1-vs-HTTP/2 detection in front of it — and the
//!    HTTP/2 preface read on the gRPC listener — wait for those first bytes
//!    with no deadline of their own.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use crate::core::TrustedProxies;

/// The HTTP/2 client connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Caps concurrent connections per client address.
///
/// IPv4 peers are counted per address. IPv6 peers are counted per `/64`: a
/// single host is routinely handed a whole `/64`, so a per-address count would
/// be no cap at all. IPv4-mapped IPv6 peers count as their IPv4 address.
pub(crate) struct PerIpLimiter {
    /// Maximum connections per bucket; `0` disables the cap.
    max: usize,
    /// Peers never counted — the operator's `server.trusted_proxies`,
    /// addresses and CIDR ranges alike.
    exempt: TrustedProxies,
    /// Live connection count per bucket. Entries are removed at zero so the
    /// map is bounded by the number of distinct peers currently connected.
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl PerIpLimiter {
    /// Builds a limiter allowing `max` connections per client (`0` = no cap),
    /// with `exempt` peers never counted.
    pub(crate) fn new(max: u32, exempt: TrustedProxies) -> Arc<Self> {
        Arc::new(Self {
            max: usize::try_from(max).unwrap_or(usize::MAX),
            exempt,
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// Admits one connection from `peer`, or returns `None` when that client
    /// already holds its allowance. The returned guard releases the slot when
    /// dropped, so it must live as long as the connection.
    pub(crate) fn try_acquire(self: &Arc<Self>, peer: IpAddr) -> Option<PerIpGuard> {
        let peer = peer.to_canonical();
        if self.max == 0 || self.exempt.contains(peer) {
            return Some(PerIpGuard {
                owner: None,
                bucket: peer,
            });
        }
        let bucket = bucket_of(peer);
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(bucket).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(PerIpGuard {
            owner: Some(Arc::clone(self)),
            bucket,
        })
    }

    /// Live connections counted against `peer`'s bucket (test support).
    #[cfg(test)]
    fn count(&self, peer: IpAddr) -> usize {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        counts
            .get(&bucket_of(peer.to_canonical()))
            .copied()
            .unwrap_or(0)
    }
}

/// The bucket a peer's connections are counted in.
fn bucket_of(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V4(_) => peer,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// One admitted connection's slot in a [`PerIpLimiter`]; released on drop.
pub(crate) struct PerIpGuard {
    /// `None` for an uncounted (exempt or uncapped) connection.
    owner: Option<Arc<PerIpLimiter>>,
    bucket: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        let mut counts = owner.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.bucket) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.bucket);
            }
        }
    }
}

/// Wraps a connection so it fails with [`io::ErrorKind::TimedOut`] if the
/// client has not sent enough to identify its protocol within `budget`.
///
/// The deadline disarms as soon as the bytes read so far stop matching the
/// HTTP/2 preface (the connection is HTTP/1, whose header block hyper's own
/// `header_read_timeout` bounds) or once the full preface has arrived (the
/// connection is HTTP/2, whose liveness the keep-alive pings bound). After
/// that the wrapper is a plain pass-through.
pub(crate) struct FirstBytesDeadline<IO> {
    io: IO,
    deadline: Option<Pin<Box<Sleep>>>,
    /// Bytes of [`H2_PREFACE`] matched so far.
    matched: usize,
}

impl<IO> FirstBytesDeadline<IO> {
    /// Arms a `budget` deadline on `io`.
    pub(crate) fn new(io: IO, budget: Duration) -> Self {
        Self {
            io,
            deadline: Some(Box::pin(tokio::time::sleep(budget))),
            matched: 0,
        }
    }

    /// Feeds newly read bytes to the protocol sniff and disarms the deadline
    /// once the protocol is known (or the peer closed).
    fn observe(&mut self, bytes: &[u8]) {
        if self.deadline.is_none() {
            return;
        }
        if bytes.is_empty() {
            // EOF: nothing left to wait for.
            self.deadline = None;
            return;
        }
        for &byte in bytes {
            if H2_PREFACE.get(self.matched) != Some(&byte) {
                // Not HTTP/2: hyper's HTTP/1 header timeout takes over.
                self.deadline = None;
                return;
            }
            self.matched += 1;
            if self.matched == H2_PREFACE.len() {
                self.deadline = None;
                return;
            }
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for FirstBytesDeadline<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.observe(&buf.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if let Some(deadline) = this.deadline.as_mut() {
                    if deadline.as_mut().poll(cx).is_ready() {
                        this.deadline = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "client sent no request within operational.header_read_timeout_secs",
                        )));
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for FirstBytesDeadline<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn the_cap_refuses_past_the_allowance_and_a_drop_readmits() {
        let limiter = PerIpLimiter::new(2, TrustedProxies::default());
        let a = limiter.try_acquire(v4(1)).expect("first");
        let _b = limiter.try_acquire(v4(1)).expect("second");
        assert!(
            limiter.try_acquire(v4(1)).is_none(),
            "the third connection from one address must be refused"
        );
        assert!(
            limiter.try_acquire(v4(2)).is_some(),
            "another address has its own allowance"
        );
        drop(a);
        assert!(
            limiter.try_acquire(v4(1)).is_some(),
            "releasing a connection must readmit"
        );
    }

    #[test]
    fn released_buckets_are_removed_so_the_map_does_not_grow() {
        let limiter = PerIpLimiter::new(4, TrustedProxies::default());
        let guard = limiter.try_acquire(v4(9)).expect("admit");
        assert_eq!(limiter.count(v4(9)), 1);
        drop(guard);
        assert_eq!(limiter.count(v4(9)), 0);
        let counts = limiter.counts.lock().expect("lock");
        assert!(counts.is_empty(), "a zero count must not stay in the map");
    }

    #[test]
    fn ipv6_peers_share_one_allowance_per_slash_64() {
        let limiter = PerIpLimiter::new(1, TrustedProxies::default());
        let first: IpAddr = "2001:db8:1:2::1".parse().expect("ip");
        let same_64: IpAddr = "2001:db8:1:2:ffff::9".parse().expect("ip");
        let other_64: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        let _held = limiter.try_acquire(first).expect("first");
        assert!(
            limiter.try_acquire(same_64).is_none(),
            "a second address in the same /64 is the same client"
        );
        assert!(limiter.try_acquire(other_64).is_some());
    }

    #[test]
    fn mapped_ipv4_counts_as_the_ipv4_address() {
        let limiter = PerIpLimiter::new(1, TrustedProxies::default());
        let _held = limiter.try_acquire(v4(7)).expect("first");
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().expect("ip");
        assert!(limiter.try_acquire(mapped).is_none());
    }

    fn exempt(entries: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(entries).expect("valid trusted_proxies")
    }

    /// Every peer inside a trusted CIDR is exempt; one outside it is capped.
    /// Ingress-controller pods are rescheduled onto new addresses inside the
    /// range, and each carries every client behind it.
    #[test]
    fn peers_inside_a_trusted_cidr_are_exempt_and_peers_outside_are_capped() {
        let limiter = PerIpLimiter::new(1, exempt(&["192.0.2.0/28"]));
        let _a = limiter.try_acquire(v4(1)).expect("in range");
        let _b = limiter.try_acquire(v4(1)).expect("in range, again");
        let _c = limiter
            .try_acquire(v4(15))
            .expect("last address in the /28");
        let _d = limiter.try_acquire(v4(15)).expect("last address, again");
        assert_eq!(limiter.count(v4(1)), 0, "exempt peers are never counted");

        let _e = limiter
            .try_acquire(v4(16))
            .expect("first connection outside");
        assert!(
            limiter.try_acquire(v4(16)).is_none(),
            "one past the /28 is an ordinary client and is capped"
        );

        let mapped: IpAddr = "::ffff:192.0.2.3".parse().expect("ip");
        let _f = limiter.try_acquire(mapped).expect("mapped, in range");
        let _g = limiter
            .try_acquire(mapped)
            .expect("mapped, in range, again");
    }

    #[test]
    fn peers_inside_a_trusted_ipv6_cidr_are_exempt() {
        let limiter = PerIpLimiter::new(1, exempt(&["2001:db8:42::/48"]));
        let inside: IpAddr = "2001:db8:42:7::1".parse().expect("ip");
        let _a = limiter.try_acquire(inside).expect("in range");
        let _b = limiter.try_acquire(inside).expect("in range, again");
        let outside: IpAddr = "2001:db8:43::1".parse().expect("ip");
        let _c = limiter.try_acquire(outside).expect("first outside");
        assert!(limiter.try_acquire(outside).is_none());
    }

    #[test]
    fn exempt_peers_and_a_zero_cap_are_never_counted() {
        let limiter = PerIpLimiter::new(1, exempt(&["192.0.2.5"]));
        let _a = limiter.try_acquire(v4(5)).expect("exempt");
        let _b = limiter.try_acquire(v4(5)).expect("exempt again");
        assert_eq!(limiter.count(v4(5)), 0);

        let uncapped = PerIpLimiter::new(0, TrustedProxies::default());
        let _c = uncapped.try_acquire(v4(6)).expect("uncapped");
        let _d = uncapped.try_acquire(v4(6)).expect("uncapped again");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out() {
        let (client, server) = tokio::io::duplex(64);
        let mut guarded = FirstBytesDeadline::new(server, Duration::from_secs(5));
        let mut buf = [0_u8; 8];
        let err = guarded
            .read(&mut buf)
            .await
            .expect_err("a peer that sends nothing must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_http2_preface_times_out() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = FirstBytesDeadline::new(server, Duration::from_secs(5));
        client.write_all(&H2_PREFACE[..10]).await.expect("write");
        let mut buf = [0_u8; 64];
        let n = guarded.read(&mut buf).await.expect("first bytes");
        assert_eq!(n, 10);
        let err = guarded
            .read(&mut buf)
            .await
            .expect_err("the rest of the preface never came");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn http1_bytes_disarm_the_deadline() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = FirstBytesDeadline::new(server, Duration::from_secs(5));
        client
            .write_all(b"GET / HTTP/1.1\r\n")
            .await
            .expect("write");
        let mut buf = [0_u8; 64];
        let n = guarded.read(&mut buf).await.expect("first bytes");
        assert!(n > 0, "the request line must be read");
        // Past the deadline, a pending read is hyper's business, not ours.
        let pending = tokio::time::timeout(Duration::from_secs(60), guarded.read(&mut buf)).await;
        assert!(
            pending.is_err(),
            "once the protocol is known the wrapper must not time the connection out"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_complete_http2_preface_disarms_the_deadline() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut guarded = FirstBytesDeadline::new(server, Duration::from_secs(5));
        client.write_all(H2_PREFACE).await.expect("write");
        let mut buf = [0_u8; 64];
        let mut got = 0;
        while got < H2_PREFACE.len() {
            got += guarded.read(&mut buf).await.expect("preface");
        }
        let pending = tokio::time::timeout(Duration::from_secs(60), guarded.read(&mut buf)).await;
        assert!(
            pending.is_err(),
            "an HTTP/2 connection is not timed out here"
        );
    }
}
