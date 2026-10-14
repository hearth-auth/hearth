//! The subject a token names in its `sub` claim.
//!
//! Entity IDs show as bare UUIDs. A token's `sub` must also tell a user from
//! an OAuth client or an agent without a lookup, because the three share no
//! namespace. So a client and an agent keep a kind prefix in `sub`, and a user
//! does not (OpenSpec `rbac-token-claims`, "Entity IDs are bare UUIDs").

use std::fmt;

use uuid::Uuid;

use super::types::{AgentId, ClientId, UserId};

/// The subject of a token Hearth issues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenSubject {
    /// A user: `sub` is the bare UUID, the user's `id` in every API.
    User(UserId),
    /// An OAuth client acting for itself: `sub` is `client_<uuid>`.
    Client(ClientId),
    /// An agent: `sub` is `agt_<uuid>`.
    Agent(AgentId),
}

/// The `sub` prefix of a client subject.
const CLIENT_PREFIX: &str = "client_";
/// The `sub` prefix of an agent subject.
const AGENT_PREFIX: &str = "agt_";
/// The `sub` prefix of a user subject in tokens issued before 4.0.
const LEGACY_USER_PREFIX: &str = "user_";

impl TokenSubject {
    /// Reads a `sub` claim: `client_<uuid>` is a client, `agt_<uuid>` an
    /// agent, and a bare UUID or the legacy `user_<uuid>` a user. Any other
    /// text is `None`. It does not allocate (`validate_token` calls it).
    pub fn parse(sub: &str) -> Option<Self> {
        let canonical = |text: &str| {
            let uuid = Uuid::try_parse(text).ok()?;
            // Only the form Hearth writes: lowercase and hyphenated.
            let mut buf = Uuid::encode_buffer();
            (uuid.hyphenated().encode_lower(&mut buf) == text).then_some(uuid)
        };
        if let Some(rest) = sub.strip_prefix(CLIENT_PREFIX) {
            return canonical(rest).map(|u| Self::Client(ClientId::new(u)));
        }
        if let Some(rest) = sub.strip_prefix(AGENT_PREFIX) {
            return canonical(rest).map(|u| Self::Agent(AgentId::new(u)));
        }
        let user = sub.strip_prefix(LEGACY_USER_PREFIX).unwrap_or(sub);
        canonical(user).map(|u| Self::User(UserId::new(u)))
    }
}

impl fmt::Display for TokenSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(id) => write!(f, "{id}"),
            Self::Client(id) => write!(f, "{CLIENT_PREFIX}{id}"),
            Self::Agent(id) => write!(f, "{AGENT_PREFIX}{id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_subject_is_the_bare_uuid() {
        let uuid = Uuid::new_v4();
        let sub = TokenSubject::User(UserId::new(uuid)).to_string();
        assert_eq!(sub, uuid.to_string());
    }

    #[test]
    fn a_client_and_an_agent_keep_their_kind_prefix() {
        let uuid = Uuid::new_v4();
        assert_eq!(
            TokenSubject::Client(ClientId::new(uuid)).to_string(),
            format!("client_{uuid}")
        );
        assert_eq!(
            TokenSubject::Agent(AgentId::new(uuid)).to_string(),
            format!("agt_{uuid}")
        );
    }

    #[test]
    fn parse_reads_back_every_subject_it_writes() {
        let uuid = Uuid::new_v4();
        for subject in [
            TokenSubject::User(UserId::new(uuid)),
            TokenSubject::Client(ClientId::new(uuid)),
            TokenSubject::Agent(AgentId::new(uuid)),
        ] {
            assert_eq!(TokenSubject::parse(&subject.to_string()), Some(subject));
        }
    }

    /// Tokens issued before 4.0 carry `user_<uuid>`; they stay valid until
    /// they expire.
    #[test]
    fn parse_reads_a_legacy_user_subject() {
        let uuid = Uuid::new_v4();
        assert_eq!(
            TokenSubject::parse(&format!("user_{uuid}")),
            Some(TokenSubject::User(UserId::new(uuid)))
        );
    }

    #[test]
    fn parse_refuses_anything_else() {
        let uuid = Uuid::new_v4();
        for sub in [
            String::new(),
            "none".to_string(),
            "client_".to_string(),
            format!("session_{uuid}"),
            format!("org_{uuid}"),
            format!("agent:agt_{uuid}"),
            format!("client_user_{uuid}"),
            format!(" {uuid}"),
        ] {
            assert_eq!(TokenSubject::parse(&sub), None, "{sub:?}");
        }
    }
}
