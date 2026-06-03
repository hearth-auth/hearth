use super::types::{AbuseDecision, AbuseRequest};
use super::AbusePolicy;

/// No-op [`AbusePolicy`] that unconditionally allows all requests.
///
/// Used as the default policy until a concrete detection implementation is
/// wired up. Zero heap allocations, zero syscalls — trivially within the
/// ≤ 5 µs p99 hot-path budget.
pub struct NoopAbusePolicy;

impl AbusePolicy for NoopAbusePolicy {
    fn check(&self, _req: &AbuseRequest<'_>) -> AbuseDecision {
        AbuseDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::abuse::types::AbuseRequest;
    use crate::core::RealmId;

    fn dummy_realm() -> RealmId {
        RealmId::new(uuid::Uuid::nil())
    }

    #[test]
    fn noop_always_allows() {
        let policy = NoopAbusePolicy;
        let realm = dummy_realm();
        let req = AbuseRequest {
            realm_id: &realm,
            client_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            endpoint: "token",
        };
        assert_eq!(policy.check(&req), AbuseDecision::Allow);
    }

    #[test]
    fn noop_allows_any_endpoint() {
        let policy = NoopAbusePolicy;
        let realm = dummy_realm();
        for endpoint in ["token", "authorize", "introspect", "revoke", "users"] {
            let req = AbuseRequest {
                realm_id: &realm,
                client_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                endpoint,
            };
            assert_eq!(policy.check(&req), AbuseDecision::Allow, "failed for {endpoint}");
        }
    }
}
