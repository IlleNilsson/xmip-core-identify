//! User principal names and service principal names, read one way.
//!
//! Many mechanisms name the same two things differently. A person or an
//! account is `jane@partner-x.example` to a directory, `PARTNERX\jane` to an
//! older Windows logon, a client principal to Kerberos, the `upn` claim to an
//! identity provider and an alternative name to a smart-card certificate. A
//! service is `HTTP/xmip.example@EXAMPLE.COM` to Kerberos, a target name to
//! NTLM and an application's identity to an authorization server. The owner,
//! 2026-09-19: identification and authentication by user and service
//! principal name should be supported where it can (ADR-0054).
//!
//! So the two names are types here, in the capability every identify and
//! authenticate technology already depends on (ADR-0044), and a technology
//! that can read one says so under one of two evidence names, [`USER`] and
//! [`SERVICE`], in the one canonical form these types write. A Party is then
//! resolved by a principal name whatever mechanism carried it.
//!
//! Canonical means comparable, not pretty: a domain and a realm fold to lower
//! case because DNS and Kerberos realms in practice compare that way; a user
//! part keeps its case because a directory may care; a host folds to lower
//! case; a service class keeps its case, as Kerberos compares it exactly.

use std::fmt;

/// The evidence name a user principal name is put under, in canonical form.
pub const USER: &str = "principal.user";

/// The evidence name a service principal name is put under, in canonical form.
pub const SERVICE: &str = "principal.service";

/// A user principal name: a user within a domain.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserPrincipalName {
    user: String,
    domain: String,
}

impl UserPrincipalName {
    /// Parse `user@domain`, or the down-level `DOMAIN\user`. The last `@`
    /// divides, because a user part may itself hold one. Nothing else is a
    /// user principal name: a bare `jane` names a user and no domain.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();

        if let Some((domain, user)) = text.split_once('\\') {
            return Self::of(user, domain);
        }

        let (user, domain) = text.rsplit_once('@')?;
        Self::of(user, domain)
    }

    /// A user within a domain, where neither is empty and the domain holds no
    /// character a domain cannot.
    #[must_use]
    pub fn of(user: &str, domain: &str) -> Option<Self> {
        let user = user.trim();
        let domain = domain.trim().trim_end_matches('.');
        let plain = |character: char| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        };

        if user.is_empty() || domain.is_empty() || !domain.chars().all(plain) {
            return None;
        }

        if user.contains(['\\', '/']) {
            return None;
        }

        Some(Self {
            user: user.to_string(),
            domain: domain.to_ascii_lowercase(),
        })
    }

    /// The user part, as written.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The domain, in lower case.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Whether another name is the same account: the domain already
    /// compares folded, and the user part is compared without case, as a
    /// directory compares a logon name.
    #[must_use]
    pub fn is(&self, other: &Self) -> bool {
        self.domain == other.domain && self.user.eq_ignore_ascii_case(&other.user)
    }
}

impl fmt::Display for UserPrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.user, self.domain)
    }
}

/// A service principal name: a service class on a host, optionally at a
/// port, optionally a named instance, optionally within a realm.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServicePrincipalName {
    class: String,
    host: String,
    port: Option<u16>,
    instance: Option<String>,
    realm: Option<String>,
}

impl ServicePrincipalName {
    /// Parse `class/host`, `class/host:port`, `class/host/instance`, each
    /// optionally followed by `@REALM` — the forms Kerberos and Active
    /// Directory write. A name with no `/` is not a service principal name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (name, realm) = match text.rsplit_once('@') {
            Some((name, realm)) if !realm.contains('/') => (name, Some(realm.trim())),
            _ => (text, None),
        };
        let mut parts = name.splitn(3, '/');
        let class = parts.next()?.trim();
        let host = parts.next()?.trim();
        let instance = parts.next().map(str::trim).filter(|part| !part.is_empty());
        let (host, port) = match host.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
            None => (host, None),
        };

        if class.is_empty() || host.is_empty() {
            return None;
        }

        Some(Self {
            class: class.to_string(),
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            port,
            instance: instance.map(str::to_string),
            realm: realm
                .filter(|realm| !realm.is_empty())
                .map(str::to_ascii_lowercase),
        })
    }

    /// The service class: `HTTP`, `host`, `MSSQLSvc`.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    /// The host, in lower case.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, where the name carries one.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The realm, in lower case, where the name carries one.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    /// Whether another name is the same service: class, host, port and
    /// instance alike, and the realm alike where both name one. A name
    /// without a realm is the same service in whichever realm it is found.
    #[must_use]
    pub fn is(&self, other: &Self) -> bool {
        let realm = match (&self.realm, &other.realm) {
            (Some(ours), Some(theirs)) => ours == theirs,
            _ => true,
        };

        realm
            && self.class == other.class
            && self.host == other.host
            && self.port == other.port
            && self.instance == other.instance
    }
}

impl fmt::Display for ServicePrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.class, self.host)?;

        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }

        if let Some(instance) = &self.instance {
            write!(f, "/{instance}")?;
        }

        if let Some(realm) = &self.realm {
            write!(f, "@{realm}")?;
        }

        Ok(())
    }
}

/// Either kind of principal name, for a reader that is handed text and must
/// say which it is. A `/` makes a service; otherwise an `@` or a `\` makes a
/// user; anything else is neither.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalName {
    /// A user within a domain.
    User(UserPrincipalName),
    /// A service on a host.
    Service(ServicePrincipalName),
}

impl PrincipalName {
    /// Read text as whichever principal name it is, if it is one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.contains('/') {
            return ServicePrincipalName::parse(text).map(Self::Service);
        }

        UserPrincipalName::parse(text).map(Self::User)
    }

    /// The evidence name this kind is put under.
    #[must_use]
    pub const fn evidence(&self) -> &'static str {
        match self {
            Self::User(_) => USER,
            Self::Service(_) => SERVICE,
        }
    }
}

impl fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(user) => user.fmt(f),
            Self::Service(service) => service.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_principal_name_reads_the_same_from_either_form() {
        let modern = UserPrincipalName::parse("Jane@Partner-X.Example").expect("a name");
        let older = UserPrincipalName::parse("PARTNER-X.EXAMPLE\\jane").expect("a name");

        assert_eq!(modern.to_string(), "Jane@partner-x.example");
        assert_eq!(modern.user(), "Jane");
        assert_eq!(modern.domain(), "partner-x.example");
        assert!(modern.is(&older), "the same account, written two ways");
        assert_ne!(modern, older, "and still told apart as written");
    }

    #[test]
    fn the_last_at_sign_divides_and_a_bare_user_is_not_a_principal_name() {
        let guest =
            UserPrincipalName::parse("jane@home.example@partner-x.example").expect("a name");

        assert_eq!(guest.user(), "jane@home.example");
        assert_eq!(guest.domain(), "partner-x.example");
        assert!(UserPrincipalName::parse("jane").is_none());
        assert!(UserPrincipalName::parse("jane@").is_none());
        assert!(UserPrincipalName::parse("@partner-x.example").is_none());
        assert!(UserPrincipalName::parse("jane@bad domain").is_none());
    }

    #[test]
    fn a_service_principal_name_keeps_its_class_and_folds_its_host_and_realm() {
        let web =
            ServicePrincipalName::parse("HTTP/Xmip.Example.:8443@EXAMPLE.COM").expect("a name");

        assert_eq!(web.class(), "HTTP");
        assert_eq!(web.host(), "xmip.example");
        assert_eq!(web.port(), Some(8443));
        assert_eq!(web.realm(), Some("example.com"));
        assert_eq!(web.to_string(), "HTTP/xmip.example:8443@example.com");

        let sql = ServicePrincipalName::parse("MSSQLSvc/db01.example/orders").expect("a name");
        assert_eq!(sql.to_string(), "MSSQLSvc/db01.example/orders");
        assert!(ServicePrincipalName::parse("xmip.example").is_none());
        assert!(ServicePrincipalName::parse("HTTP/host:notaport").is_none());
    }

    #[test]
    fn a_service_without_a_realm_is_the_same_service_in_any_realm() {
        let bare = ServicePrincipalName::parse("HTTP/xmip.example").expect("a name");
        let placed = ServicePrincipalName::parse("HTTP/XMIP.example@EXAMPLE.COM").expect("a name");
        let elsewhere = ServicePrincipalName::parse("HTTP/xmip.example@OTHER.COM").expect("a name");
        let other = ServicePrincipalName::parse("http/xmip.example").expect("a name");

        assert!(bare.is(&placed));
        assert!(!placed.is(&elsewhere));
        assert!(!bare.is(&other), "Kerberos compares the class exactly");
    }

    #[test]
    fn text_says_which_kind_it_is_and_where_its_evidence_goes() {
        let user = PrincipalName::parse("jane@partner-x.example").expect("a user");
        let service = PrincipalName::parse("HTTP/xmip.example@EXAMPLE.COM").expect("a service");

        assert_eq!(user.evidence(), USER);
        assert_eq!(service.evidence(), SERVICE);
        assert_eq!(service.to_string(), "HTTP/xmip.example@example.com");
        assert!(PrincipalName::parse("CN=partner-x.example").is_none());
    }
}
