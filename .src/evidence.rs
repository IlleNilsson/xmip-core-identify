//! The names a claim carries across the identity gates: the evidence the
//! first gate writes and a later one reads, and the proofs the first gate
//! attaches for the authenticator of the same mechanism.
//!
//! A name read on one side and written on the other is one name, declared
//! once. Until 2026-09-24 most were declared twice — the identify technology
//! wrote `jwt.token` under one constant and the authenticate technology read
//! it under another, and `authorize/scope` read `scope` under a third — held
//! equal by nothing. A technology that neither shares nor hands on a name
//! keeps it: a name is here because more than one crate says it.
//!
//! Only names that cross the gates inside identity are here. A name a
//! transport writes and a gate reads — the peer's address, the TLS peer
//! certificate's issuer and fingerprint, the first two NTLM legs — is
//! `context::property`'s, even where a gate hands it on under the same name
//! (the owner, 2026-09-24).
//!
//! What each carries, and in what form, is said where it is written. A proof
//! never reaches the record (`Presented::proof`); evidence always does.

// Evidence: on the claim, on the record.

/// A user principal name, in the canonical form `UserPrincipalName` writes
/// (ADR-0054).
pub const PRINCIPAL_USER: &str = "principal.user";
/// A service principal name, in the canonical form `ServicePrincipalName`
/// writes (ADR-0054).
pub const PRINCIPAL_SERVICE: &str = "principal.service";
/// A token's scopes, learned by the second gate: the space-separated list as
/// the token or its authorization server stated it (RFC 6749 section 3.3).
/// `authorize/scope` reads it.
pub const SCOPE: &str = "scope";
/// Where an API key was found: `header:<name>` or `query:<name>`.
pub const API_KEY_SOURCE: &str = "api-key.source";
/// A Kerberos ticket's client as the ticket names it, `cname@crealm`: sealed
/// to the first gate, which says so, and learned by the second.
pub const KERBEROS_CLIENT: &str = "kerberos.client";

// Proofs: for the authenticator of the same mechanism, never on the record.

/// A Basic credential: the base64 after `Basic `.
pub const BASIC_CREDENTIAL: &str = "basic.credential";
/// A bearer token, whole.
pub const BEARER_TOKEN: &str = "bearer.token";
/// A Digest response: the whole parameter list.
pub const DIGEST_RESPONSE: &str = "digest.response";
/// A password presented beside a username.
pub const PASSWORD: &str = "password";
/// An API key, whole.
pub const API_KEY: &str = "api-key";
/// A compact JWT, whole.
pub const JWT_TOKEN: &str = "jwt.token";
/// A compact OIDC ID token, whole.
pub const OIDC_TOKEN: &str = "oidc.token";
/// A SAML assertion, base64.
pub const SAML_ASSERTION: &str = "saml.assertion";
/// A `Negotiate` token carrying a Kerberos AP-REQ, base64.
pub const KERBEROS_AP_REQ: &str = "kerberos.ap-req";
/// An NTLM AUTHENTICATE (type 3) message, base64.
pub const NTLM_AUTHENTICATE: &str = "ntlm.authenticate";
/// The peer's certificate chain, PEM, where no handshake proved it.
pub const CERTIFICATE_CHAIN: &str = "certificate.chain";
/// The transport's word that its handshake proved the peer's chain.
pub const MUTUAL_TLS_HANDSHAKE: &str = "mutual-tls.handshake";
/// The signature an SSH peer made with its key.
pub const SSH_KEY_SIGNATURE: &str = "ssh-key.signature";
/// The session identifier that signature covers.
pub const SSH_KEY_SESSION: &str = "ssh-key.session";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_two_names_are_one() {
        let names = [
            PRINCIPAL_USER,
            PRINCIPAL_SERVICE,
            SCOPE,
            API_KEY_SOURCE,
            KERBEROS_CLIENT,
            BASIC_CREDENTIAL,
            BEARER_TOKEN,
            DIGEST_RESPONSE,
            PASSWORD,
            API_KEY,
            JWT_TOKEN,
            OIDC_TOKEN,
            SAML_ASSERTION,
            KERBEROS_AP_REQ,
            NTLM_AUTHENTICATE,
            CERTIFICATE_CHAIN,
            MUTUAL_TLS_HANDSHAKE,
            SSH_KEY_SIGNATURE,
            SSH_KEY_SESSION,
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());

        // And none is a name a transport or the runtime writes: that one is
        // declared in context, once, and not again here.
        for name in names {
            assert!(!context::property::ALL.contains(&name), "{name}");
        }
    }
}
