//! P-5 EmailReputation — pluggable email-reputation trait + built-in adapter.
//!
//! # Design
//!
//! `EmailReputation` is the trait that every pluggable email-reputation backend
//! must implement.  The built-in [`BuiltinEmailReputation`] ships with Hearth
//! and covers two signal classes:
//!
//! 1. **Disposable-domain detection** — checks the email domain against a
//!    bundled list of well-known disposable / temporary-email providers.
//! 2. **Role-address detection** — flags addresses like `noreply@`, `admin@`,
//!    `postmaster@` that are unlikely to belong to a real user.
//!
//! ## DNS MX validation (stub)
//!
//! The plan calls for "DNS MX validity" checking but a proper MX lookup
//! requires an async DNS resolver (`hickory-resolver` or equivalent), which
//! is not yet a Hearth dependency.  The reference adapter sets
//! `domain_has_no_mx = false` (assume domain is valid) and documents this
//! clearly.  Add `hickory-resolver` and wire `lookup_mx()` when full MX
//! verification is required (see HEA-1114 §4.2 P-5 notes).
//!
//! # Failure mode: fail-open
//!
//! Per §6.1 of the abuse-prevention plan: `EmailReputation` is **fail-open**.
//! Implementations MUST return a permissive verdict (all flags `false`) on any
//! internal error so that legitimate registrations are never blocked.
//!
//! # Off hot-path
//!
//! Providers are consulted only at registration, invitation acceptance, and
//! similar account-creation flows — never during `validate_token()` or
//! `lookup_session()`.

use std::collections::HashSet;
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Verdict returned by an [`EmailReputation`] check.
///
/// Callers decide policy: individual flags may be informational, advisory, or
/// hard-blocking depending on realm configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmailReputationVerdict {
    /// The email domain appears in the disposable / temporary-email blocklist.
    pub is_disposable: bool,

    /// The domain could not be confirmed to have an MX record.
    ///
    /// `false` (assume valid) in the built-in adapter — see module docs for
    /// the DNS limitation.
    pub domain_has_no_mx: bool,

    /// The local part is a well-known role address (`noreply`, `admin`,
    /// `postmaster`, etc.) that is unlikely to belong to an individual user.
    pub is_role_address: bool,
}

impl EmailReputationVerdict {
    /// `true` when none of the advisory flags are set.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.is_disposable && !self.domain_has_no_mx && !self.is_role_address
    }
}

/// Pluggable email-reputation provider trait (P-5 extension point).
///
/// Implement this trait to integrate Kickbox, ZeroBounce, NeverBounce, or a
/// custom validation service.  The built-in reference adapter
/// [`BuiltinEmailReputation`] ships with Hearth.
///
/// # Contract
///
/// - `check()` MUST be synchronous.  External adapters that require network
///   calls should cache results and refresh asynchronously.
/// - `check()` MUST fail-open: return a permissive verdict (all flags `false`)
///   on any transport or internal error.
/// - `check()` MUST NOT log the email address in plaintext when PII logging
///   is disabled.
/// - `email` is the full address as submitted by the user.  The implementation
///   is responsible for normalisation (lower-casing, plus-aliasing, etc.).
pub trait EmailReputation: Send + Sync {
    /// Evaluates the email address and returns a reputation verdict.
    fn check(&self, email: &str) -> EmailReputationVerdict;
}

// ─────────────────────────────────────────────────────────────────────────────
// No-op provider (fail-open default)
// ─────────────────────────────────────────────────────────────────────────────

/// No-op email-reputation provider.
///
/// Always returns a clean verdict (all flags `false`).  This is the safe
/// default for deployments that have not yet configured a provider; no
/// registration is ever blocked by this implementation.
pub struct NoopEmailReputation;

impl EmailReputation for NoopEmailReputation {
    fn check(&self, _email: &str) -> EmailReputationVerdict {
        EmailReputationVerdict::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in reference adapter
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`BuiltinEmailReputation`].
///
/// Serialised under `security.providers.email_reputation` in `hearth.yaml`.
#[derive(Debug, Clone, Default)]
pub struct EmailReputationConfig {
    /// Additional disposable domains to block beyond the built-in list.
    ///
    /// Domains should be lowercase (e.g. `"my-temp-mail.example"`).
    pub extra_disposable_domains: Vec<String>,
}

/// Built-in email-reputation adapter (P-5 reference implementation).
///
/// Signals applied:
///
/// 1. **Disposable-domain check** — O(1) lookup against a bundled `HashSet`
///    of ~150 well-known disposable / throwaway email providers.  Operator
///    extras are merged at startup via
///    [`EmailReputationConfig::extra_disposable_domains`].
/// 2. **Role-address check** — the local part (before `@`) is compared
///    against a list of well-known role prefixes.
/// 3. **DNS MX check** — stub, always returns `domain_has_no_mx: false`.
///    See module docs for the `hickory-resolver` upgrade path.
///
/// # Domain normalisation
///
/// The domain part is extracted from the first `@` and lowercased before
/// every lookup.  Subdomains are NOT checked against the disposable list
/// (e.g. `user@mail.mailinator.com` is checked as `mail.mailinator.com`,
/// not `mailinator.com`).  Operators who want subdomain matching should add
/// the relevant subdomains to `extra_disposable_domains`.
#[derive(Debug)]
pub struct BuiltinEmailReputation {
    /// Merged disposable-domain set (built-in + operator-supplied).
    disposable_domains: HashSet<String>,
}

impl BuiltinEmailReputation {
    /// Constructs the adapter, merging the built-in list with operator extras.
    #[must_use]
    pub fn new(config: EmailReputationConfig) -> Self {
        let mut set: HashSet<String> = builtin_disposable_domains()
            .iter()
            .map(|&s| s.to_owned())
            .collect();
        for d in config.extra_disposable_domains {
            set.insert(d.to_ascii_lowercase());
        }
        Self {
            disposable_domains: set,
        }
    }

    /// Constructs the adapter with the built-in-only disposable domain list.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(EmailReputationConfig::default())
    }

    fn is_disposable_domain(&self, domain: &str) -> bool {
        self.disposable_domains.contains(domain)
    }
}

impl EmailReputation for BuiltinEmailReputation {
    fn check(&self, email: &str) -> EmailReputationVerdict {
        let Some(at_pos) = email.rfind('@') else {
            // Malformed email — no `@`.  Caller should validate format first;
            // we return a clean verdict and let the schema validator reject it.
            return EmailReputationVerdict::default();
        };

        let local = &email[..at_pos];
        let domain = email[at_pos + 1..].to_ascii_lowercase();

        let is_disposable = self.is_disposable_domain(&domain);

        // DNS MX check stub — always false until hickory-resolver is wired.
        // TODO: implement real MX lookup via hickory-resolver (HEA-1114 §4.2 P-5).
        let domain_has_no_mx = false;

        let is_role_address = is_role_local_part(local);

        EmailReputationVerdict {
            is_disposable,
            domain_has_no_mx,
            is_role_address,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Role-address detection
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known role-address local-part prefixes (RFC 2142 + common additions).
const ROLE_LOCAL_PARTS: &[&str] = &[
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "do_not_reply",
    "postmaster",
    "hostmaster",
    "webmaster",
    "mailer-daemon",
    "abuse",
    "security",
    "admin",
    "administrator",
    "root",
    "support",
    "helpdesk",
    "help",
    "info",
    "contact",
    "sales",
    "marketing",
    "billing",
    "finance",
    "hr",
    "jobs",
    "careers",
    "newsletter",
    "notifications",
    "alerts",
    "bounce",
    "bounces",
    "unsubscribe",
    "feedback",
    "system",
    "daemon",
    "devnull",
    "dev-null",
];

fn is_role_local_part(local: &str) -> bool {
    let lower = local.to_ascii_lowercase();
    ROLE_LOCAL_PARTS.contains(&lower.as_str())
}

// ─────────────────────────────────────────────────────────────────────────────
// Disposable domain list
// ─────────────────────────────────────────────────────────────────────────────

/// Raw disposable / throwaway email domain list.
///
/// Sourced from widely published community lists (disposable-email-domains,
/// ivolo/disposable-email-domains, wesbos/burner-email-providers, etc.).
/// This is a conservative baseline; not exhaustive.  Operators should
/// supplement via [`EmailReputationConfig::extra_disposable_domains`] for
/// region-specific or newly-emerged providers.
const BUILTIN_DISPOSABLE_DOMAIN_LIST: &[&str] = &[
    // ── Major well-known disposable providers ─────────────────────────────
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamail.info",
    "guerrillamail.org",
    "guerrillamail.net",
    "guerrillamail.de",
    "guerrillamail.biz",
    "guerrillamailblock.com",
    "tempmail.com",
    "temp-mail.org",
    "temp-mail.io",
    "10minutemail.com",
    "10minutemail.net",
    "10minutemail.org",
    "throwaway.email",
    "throwam.com",
    "yopmail.com",
    "yopmail.fr",
    "cool.fr.nf",
    "jetable.fr.nf",
    "nospam.ze.tc",
    "nomail.xl.cx",
    "mega.zik.dj",
    "speed.1s.fr",
    "courriel.fr.nf",
    "moncourrier.fr.nf",
    "monemail.fr.nf",
    "monmail.fr.nf",
    "trashmail.at",
    "trashmail.com",
    "trashmail.io",
    "trashmail.me",
    "trashmail.net",
    "trashmail.org",
    "spamgourmet.com",
    "spamgourmet.net",
    "spamgourmet.org",
    "spambox.us",
    "spambox.info",
    "spambox.org",
    "maildrop.cc",
    "dispostable.com",
    "fakeinbox.com",
    "mailnull.com",
    "sharklasers.com",
    "guerrillamail.info",
    "grr.la",
    "guerrillamailblock.com",
    "spam4.me",
    "getairmail.com",
    "mailnesia.com",
    "mailnull.com",
    "mintemail.com",
    "spamgap.com",
    "mailexpire.com",
    "mail-temporaire.fr",
    "mail-temporaire.com",
    "trbvm.com",
    "dodgit.com",
    "ieatspam.eu",
    "ieatspam.info",
    "jetable.com",
    "jetable.net",
    "jetable.org",
    "nomail.xl.cx",
    "ownmail.net",
    "spamevader.com",
    "throwam.com",
    "trash-mail.at",
    "trash-mail.com",
    "trash-mail.io",
    "klzlk.com",
    "dud.la",
    "spamhereplease.com",
    "filzmail.com",
    "deadaddress.com",
    "sogetthis.com",
    "themails.in",
    "mailmetrash.com",
    "spamherelots.com",
    "egosearch.eu",
    "baxomale.ht.cx",
    "beefmilk.com",
    "binkmail.com",
    "bobmail.info",
    "bodhi.lawlita.com",
    "bofthew.com",
    "bootybay.de",
    "brefmail.com",
    "bsquaredlabs.com",
    "buf.yt",
    "bumpymail.com",
    "casualdx.com",
    "cheatmail.de",
    "chinamail.cn",
    "chogmail.com",
    "clicks.net",
    "clock.pt",
    "consumerriot.com",
    "cool.fr.nf",
    "courriel.fr.nf",
    "courrieltemporaire.com",
    "crapmail.org",
    "crapmail.net",
    "cuvox.de",
    "dacoolest.com",
    "dandikmail.com",
    "dayrep.com",
    "deadspam.com",
    "delikkt.de",
    "despam.it",
    "despammed.com",
    "devnullmail.com",
    "dharmatel.net",
    "discardmail.com",
    "discardmail.de",
    "discard.email",
    "disposableinbox.com",
    "disposablemail.at",
    "disposablemail.top",
    "disposablemailbox.com",
    "drdrb.com",
    "drdrb.net",
    "dudmail.com",
    "dumpandfuck.com",
    "dumpmail.de",
    "dumpyemail.com",
    "e4ward.com",
    "easytrashmail.com",
    "einrot.com",
    "email60.com",
    "emailage.cf",
    "emailgo.de",
    "emailias.com",
    "emaillime.com",
    "emailmiser.com",
    "emailproxsy.com",
    "emailsensei.com",
    "emailsingularity.com",
    "emailtemporario.com.br",
    "emailto.de",
    "emailwarden.com",
    "emailx.at.hm",
    "emailxfer.com",
    "emeil.in",
    "emeil.ir",
    "emz.net",
    "esave.one",
    "evopo.com",
    "explodemail.com",
    "express.net.ua",
    "eyepaste.com",
    "fakemailgenerator.com",
    "fastem.com",
    "fauxmail.xyz",
    "fightallspam.com",
    "fivemail.de",
    "fleckens.hu",
    "flyspam.com",
    "frapmail.com",
    "fudgerub.com",
    "fux0ringduh.com",
    "garliclife.com",
    "gehensiemirnichtaufdensack.de",
    "get1mail.com",
    "getonemail.com",
    "ghosttexter.de",
    "girlsundertheinfluence.com",
    "gishpuppy.com",
    "giveh2o.info",
    "gmailnew.com",
    "gnmankn.com",
    "gorillaswithdirtyarmpits.com",
    "gotti.otherinbox.com",
    "gowikibooks.com",
    "gowikicampus.com",
    "gowikicars.com",
    "gowikifilms.com",
    "gowikigames.com",
    "gowikimusic.com",
    "gowikinetwork.com",
    "gowikitravel.com",
    "gowikitv.com",
    "grandmamail.com",
    "grandmasmail.com",
    "gre.hu",
    "greensloth.com",
    "gsrv.co.uk",
    "gustr.com",
    "harakirimail.com",
    "hartbot.de",
    "hat-geld.de",
    "herp.in",
    "hmamail.com",
    "hochsitze.com",
    "hopemail.biz",
    "hotpop.com",
    "hulapla.de",
    "hushmail.com",
    "hulapla.de",
    "ieatspam.eu",
    "ieatspam.info",
    "ihateyoualot.info",
    "iheartspam.org",
    "ikbenspamvrij.nl",
    "imails.info",
    "inoutmail.de",
    "inoutmail.eu",
    "inoutmail.info",
    "inoutmail.net",
    "insorg.org",
    "internet-e-mail.de",
    "internet-mail.de",
    "internetemails.net",
    "internetmailing.net",
    "inwind.it",
    "ioio.eu",
    "junk1.tk",
    "junkmail.ga",
    "junkmail.gq",
    "kasmail.com",
    "kaspop.com",
    "keepmymail.com",
    "killmail.com",
    "killmail.net",
    "kir.ch.tc",
    "klassmaster.com",
    "klassmaster.net",
    "koszmail.pl",
    "kurzepost.de",
    "letthemeatspam.com",
    "lhsdv.com",
    "ligsb.com",
    "lol.ovpn.to",
    "lolfreak.net",
    "lookugly.com",
    "lopl.co.cc",
    "lortemail.dk",
    "losemymail.com",
    "lovemeleaveme.com",
    "lr7.us",
    "lr78.com",
    "lroid.com",
    "lukop.dk",
    "m21.cc",
    "mail-filter.com",
    "mail-temporaire.fr",
    "mail2rss.org",
    "mail333.com",
    "mail4trash.com",
    "mailbidon.com",
    "mailbiz.biz",
    "mailblocks.com",
    "mailbucket.org",
    "mailcat.biz",
    "mailcatch.com",
    "mailde.de",
    "mailde.info",
    "maildo.de",
    "maileimer.de",
    "mailexpire.com",
    "mailfa.tk",
    "mailforspam.com",
    "mailfreeonline.com",
    "mailguard.me",
    "mailhazard.com",
    "mailhazard.us",
    "mailimate.com",
    "mailin8r.com",
    "mailinater.com",
    "mailinator2.com",
    "mailincubator.com",
    "mailismagic.com",
    "mailme.ir",
    "mailme.lv",
    "mailme24.com",
    "mailmetrash.com",
    "mailmoat.com",
    "mailnew.com",
    "mailnull.com",
    "mailpick.biz",
    "mailproxsy.com",
    "mailquack.com",
    "mailrock.biz",
    "mailscrap.com",
    "mailseal.de",
    "mailshell.com",
    "mailsiphon.com",
    "mailslite.com",
    "mailtemp.info",
    "mailtome.de",
    "mailtoyou.top",
    "mailtrash.net",
    "mailtv.net",
    "mailtv.tv",
    "mailwire.com",
    "mailzilla.org",
    "makemetheking.com",
    "manifestgenerator.com",
    "mbx.cc",
    "meltmail.com",
    "mexicanstyle.biz",
    "mierdamail.com",
    "mindless.com",
    "moburl.com",
    "mockmail.com",
    "moncourrier.fr.nf",
    "monemail.fr.nf",
    "monmail.fr.nf",
    "moot.es",
    "morriesworld.ml",
    "mswork.ru",
    "mt2009.com",
    "mt2014.com",
    "mymail-in.net",
    "mymailoasis.com",
    "mypartyclip.de",
    "myphantomemail.com",
    "myspaceinc.com",
    "myspaceinc.net",
    "myspaceinc.org",
    "myspacepimpedup.com",
    "myspamless.com",
    "mytempemail.com",
    "mytempmail.com",
    "naexs.com",
    "netzidiot.de",
    "nevamail.com",
    "newbpotato.tk",
    "nice-looking.com",
    "noclickemail.com",
    "nogmailspam.info",
    "nomorespamemails.com",
    "nonspam.eu",
    "nonspammer.de",
    "noref.in",
    "nospam.ze.tc",
    "nospamfor.us",
    "nospammail.net",
    "nospamthanks.info",
    "notmailinator.com",
    "nowmymail.com",
    "nwldx.com",
    "objectmail.com",
    "obobbo.com",
    "odnorazovoe.ru",
    "oneoffemail.com",
    "oneoffmail.com",
    "onewaymail.com",
    "oopi.org",
    "opayq.com",
    "ordinaryamerican.net",
    "otherinbox.com",
    "ourklips.com",
    "outlawspam.com",
    "ovpn.to",
    "owlpic.com",
    "pancakemail.com",
    "paplease.com",
    "pepbot.com",
    "pfui.ru",
    "pimpedupmyspace.com",
    "pjjkp.com",
    "plexolan.de",
    "poczta.onet.pl",
    "pointypointystick.com",
    "politikerclub.de",
    "polyfaust.com",
    "poofy.org",
    "pookmail.com",
    "postacı.com",
    "privacy.net",
    "proxymail.eu",
    "prtnx.com",
    "prtz.eu",
    "public-inbox.org",
    "putthisinyourspamdatabase.com",
    "putthisinyourspamdatabase.com",
    "qq.com",
    "qisdo.com",
    "qisoa.com",
    "qoika.com",
    "quickinbox.com",
    "quickmail.in",
    "r4nd0m.de",
    "raetp9.com",
    "raiasu.com",
    "rcpt.at",
    "recode.me",
    "regbypass.com",
    "regbypass.comsafe-mail.net",
    "rejectmail.com",
    "repl.ca",
    "reu.oothbehalf.com",
    "rklips.com",
    "rmqkr.net",
    "rn.com",
    "rnailinator.com",
    "roll.in",
    "ronnierage.net",
    "rppkn.com",
    "rtrtr.com",
    "s0ny.net",
    "safe-mail.net",
    "safetymail.info",
    "safetypost.de",
    "sanfinder.com",
    "saynotospams.com",
    "scatmail.com",
    "schafmail.de",
    "schrott-email.de",
    "secretemail.de",
    "secure-mail.biz",
    "selfdestructingmail.com",
    "selfdestructingmail.org",
    "sendspamhere.com",
    "senseless-entertainment.com",
    "services391.com",
    "sharklasers.com",
    "shieldedmail.com",
    "shiftmail.com",
    "shitmail.de",
    "shitmail.me",
    "shitmail.org",
    "shitware.nl",
    "shortmail.net",
    "showslow.de",
    "sibmail.com",
    "sinnlos-mail.de",
    "skeefmail.com",
    "slapsfromlastnight.com",
    "slaskpost.se",
    "slopsbox.com",
    "smellfear.com",
    "smashmail.de",
    "smellfear.com",
    "snkmail.com",
    "sofimail.com",
    "sofort-mail.de",
    "sogetthis.com",
    "sohai.ml",
    "spam.la",
    "spam.su",
    "spamavert.com",
    "spamcowboy.com",
    "spamcowboy.net",
    "spamcowboy.org",
    "spamday.com",
    "spamex.com",
    "spamfree.eu",
    "spamfree24.de",
    "spamfree24.eu",
    "spamfree24.info",
    "spamfree24.net",
    "spamfree24.org",
    "spamgob.com",
    "spamgoes.in",
    "spamgourmet.com",
    "spamgourmet.net",
    "spamgourmet.org",
    "spamherelots.com",
    "spamhereplease.com",
    "spamhole.com",
    "spamify.com",
    "spaminator.de",
    "spamkill.info",
    "spaml.com",
    "spaml.de",
    "spammotel.com",
    "spamobox.com",
    "spamoff.de",
    "spamsalad.in",
    "spamslicer.com",
    "spamspot.com",
    "spamstack.net",
    "spamthis.co.uk",
    "spamthisplease.com",
    "spamtroll.net",
    "spamwc.de",
    "spamwc.net",
    "spamwc.org",
    "speed.1s.fr",
    "sperma.cf",
    "spoofmail.de",
    "squizzy.de",
    "squizzy.eu",
    "squizzy.net",
    "ssoia.com",
    "startkeys.com",
    "stinkefinger.net",
    "stop-my-spam.cf",
    "stop-my-spam.com",
    "stop-my-spam.ga",
    "stop-my-spam.ml",
    "stop-my-spam.tk",
    "stuffmail.de",
    "super-auswahl.de",
    "supergreatmail.com",
    "supermailer.jp",
    "superrito.com",
    "superstachel.de",
    "suremail.info",
    "suter.hu",
    "svk.jp",
    "sweetxxx.de",
    "tafmail.com",
    "tagyourself.com",
    "talkinator.com",
    "techemail.com",
    "temp-mail.de",
    "temp.emeraldwebmail.com",
    "tempail.com",
    "tempalias.com",
    "tempemail.biz",
    "tempemail.co.za",
    "tempemail.com",
    "tempemail.net",
    "tempinbox.co.uk",
    "tempinbox.com",
    "tempmail.de",
    "tempmail.eu",
    "tempmail.it",
    "tempmail.net",
    "tempmail.us",
    "tempomail.fr",
    "temporamail.com",
    "temporarioemail.com.br",
    "temporaryemail.net",
    "temporaryemail.us",
    "temporaryforwarding.com",
    "temporaryinbox.com",
    "temporarymailaddress.com",
    "tempsky.com",
    "tempthe.net",
    "tempymail.com",
    "thanksnospam.info",
    "thecloudindex.com",
    "thisisnotmyrealemail.com",
    "throwam.com",
    "throwawayemailaddress.com",
    "throwjunk.com",
    "tilien.com",
    "tinyurl24.com",
    "tittbit.in",
    "tizi.com",
    "tmail.com",
    "trbvm.com",
    "trbvn.com",
    "trbvo.com",
    "trillianpro.com",
    "tryalert.com",
    "turual.com",
    "twinmail.de",
    "tyldd.com",
    "uggsrock.com",
    "uhhu.ru",
    "umail.net",
    "uroid.com",
    "us.af",
    "venompen.com",
    "verticalscope.com",
    "veryrealemail.com",
    "viditag.com",
    "viralplays.com",
    "vmail.me",
    "volcanomail.com",
    "w3internet.co.uk",
    "watch-harry-potter.com",
    "webemail.me",
    "webm4il.info",
    "weg-werf-email.de",
    "wetrainbayarea.com",
    "wetrainbayarea.org",
    "whyspam.me",
    "wilemail.com",
    "willselfdestruct.com",
    "winemaven.info",
    "wintotlg.com",
    "wronghead.com",
    "wuzup.net",
    "wuzupmail.net",
    "www.e4ward.com",
    "www.gishpuppy.com",
    "www.mailinator.com",
    "wwwnew.eu",
    "xagloo.co",
    "xagloo.com",
    "xemaps.com",
    "xents.com",
    "xmaily.com",
    "xoxy.net",
    "xyzfree.net",
    "yapped.net",
    "yeah.net",
    "yep.it",
    "yogamaven.com",
    "yuurok.com",
    "z1p.biz",
    "za.com",
    "zebins.com",
    "zebins.eu",
    "zehnminuten.de",
    "zehnminutenmail.de",
    "zetmail.com",
    "zippymail.info",
    "zoemail.net",
    "zoemail.org",
    "zomg.info",
];

static BUILTIN_DISPOSABLE_DOMAINS: OnceLock<HashSet<&'static str>> = OnceLock::new();

fn builtin_disposable_domains() -> &'static HashSet<&'static str> {
    BUILTIN_DISPOSABLE_DOMAINS
        .get_or_init(|| BUILTIN_DISPOSABLE_DOMAIN_LIST.iter().copied().collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared static accessor
// ─────────────────────────────────────────────────────────────────────────────

static DEFAULT_PROVIDER: OnceLock<BuiltinEmailReputation> = OnceLock::new();

/// Returns a shared reference to the default built-in email-reputation
/// provider (built-in disposable list + role-address check only).
pub fn default_builtin_provider() -> &'static BuiltinEmailReputation {
    DEFAULT_PROVIDER.get_or_init(BuiltinEmailReputation::default_config)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> BuiltinEmailReputation {
        BuiltinEmailReputation::default_config()
    }

    // ── No-op provider ──────────────────────────────────────────────────────

    /// Noop provider always returns a clean verdict.
    #[test]
    fn noop_always_clean() {
        let p = NoopEmailReputation;
        let v = p.check("throwaway@mailinator.com");
        assert!(v.is_clean());
    }

    // ── Clean domains ───────────────────────────────────────────────────────

    /// Gmail is not disposable.
    #[test]
    fn gmail_is_not_disposable() {
        let v = provider().check("user@gmail.com");
        assert!(!v.is_disposable, "gmail.com should not be disposable");
    }

    /// A company domain is not disposable.
    #[test]
    fn company_domain_not_disposable() {
        let v = provider().check("alice@example.com");
        assert!(!v.is_disposable);
        assert!(v.is_clean());
    }

    // ── Disposable domains ──────────────────────────────────────────────────

    /// mailinator.com is flagged as disposable.
    #[test]
    fn mailinator_is_disposable() {
        let v = provider().check("temp123@mailinator.com");
        assert!(v.is_disposable, "mailinator.com must be flagged");
    }

    /// guerrillamail.com is flagged.
    #[test]
    fn guerrillamail_is_disposable() {
        let v = provider().check("abc@guerrillamail.com");
        assert!(v.is_disposable);
    }

    /// 10minutemail.com is flagged.
    #[test]
    fn ten_minute_mail_is_disposable() {
        let v = provider().check("user@10minutemail.com");
        assert!(v.is_disposable);
    }

    /// yopmail.com is flagged.
    #[test]
    fn yopmail_is_disposable() {
        let v = provider().check("user@yopmail.com");
        assert!(v.is_disposable);
    }

    /// trashmail.com is flagged.
    #[test]
    fn trashmail_is_disposable() {
        let v = provider().check("user@trashmail.com");
        assert!(v.is_disposable);
    }

    /// maildrop.cc is flagged.
    #[test]
    fn maildrop_is_disposable() {
        let v = provider().check("user@maildrop.cc");
        assert!(v.is_disposable);
    }

    // ── Domain lookup is case-insensitive ───────────────────────────────────

    /// Domain check is case-insensitive.
    #[test]
    fn domain_check_case_insensitive() {
        let v = provider().check("user@MAILINATOR.COM");
        assert!(v.is_disposable, "uppercase domain should still match");
    }

    /// Mixed-case domain is handled.
    #[test]
    fn domain_mixed_case() {
        let v = provider().check("user@Mailinator.Com");
        assert!(v.is_disposable);
    }

    // ── Role-address detection ──────────────────────────────────────────────

    /// noreply@ is flagged as a role address.
    #[test]
    fn noreply_is_role_address() {
        let v = provider().check("noreply@example.com");
        assert!(v.is_role_address);
    }

    /// admin@ is flagged as a role address.
    #[test]
    fn admin_is_role_address() {
        let v = provider().check("admin@example.com");
        assert!(v.is_role_address);
    }

    /// postmaster@ is flagged as a role address.
    #[test]
    fn postmaster_is_role_address() {
        let v = provider().check("postmaster@example.com");
        assert!(v.is_role_address);
    }

    /// A regular first-name-based local part is not a role address.
    #[test]
    fn regular_local_not_role() {
        let v = provider().check("alice@example.com");
        assert!(!v.is_role_address);
    }

    /// Role-address detection is case-insensitive.
    #[test]
    fn role_address_case_insensitive() {
        let v = provider().check("NOREPLY@example.com");
        assert!(v.is_role_address);
    }

    // ── Disposable + role ───────────────────────────────────────────────────

    /// A disposable domain + role local part sets both flags.
    #[test]
    fn disposable_and_role_address_both_flagged() {
        let v = provider().check("noreply@mailinator.com");
        assert!(v.is_disposable);
        assert!(v.is_role_address);
        assert!(!v.is_clean());
    }

    // ── Malformed / edge cases ──────────────────────────────────────────────

    /// A malformed email (no @) returns a clean verdict rather than erroring.
    #[test]
    fn malformed_no_at_returns_clean() {
        let v = provider().check("notanemail");
        assert!(v.is_clean());
    }

    /// An email with only @ is handled without panic.
    #[test]
    fn only_at_returns_clean() {
        let v = provider().check("@");
        assert!(v.is_clean());
    }

    // ── DNS MX check (stub) ─────────────────────────────────────────────────

    /// The stub MX check always returns domain_has_no_mx = false (assume valid).
    #[test]
    fn mx_check_stub_always_false() {
        let v = provider().check("user@example.com");
        assert!(
            !v.domain_has_no_mx,
            "stub MX check must not set domain_has_no_mx"
        );
    }

    // ── Operator-supplied extras ────────────────────────────────────────────

    /// Operator can extend the disposable-domain list at startup.
    #[test]
    fn extra_disposable_domain_works() {
        let p = BuiltinEmailReputation::new(EmailReputationConfig {
            extra_disposable_domains: vec!["mycustom-throwaway.example".to_owned()],
        });
        let v = p.check("user@mycustom-throwaway.example");
        assert!(v.is_disposable);
    }

    /// Operator-supplied extra domain is normalised to lowercase.
    #[test]
    fn extra_disposable_domain_normalised() {
        let p = BuiltinEmailReputation::new(EmailReputationConfig {
            extra_disposable_domains: vec!["MyCustom-Throwaway.EXAMPLE".to_owned()],
        });
        let v = p.check("user@mycustom-throwaway.example");
        assert!(v.is_disposable);
    }

    // ── is_clean helper ─────────────────────────────────────────────────────

    #[test]
    fn is_clean_requires_all_flags_false() {
        let clean = EmailReputationVerdict::default();
        assert!(clean.is_clean());

        let not_clean = EmailReputationVerdict {
            is_disposable: true,
            ..Default::default()
        };
        assert!(!not_clean.is_clean());
    }
}
