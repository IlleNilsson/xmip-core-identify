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
/// The peer certificate's issuer, as the transport wrote it.
pub const TLS_PEER_ISSUER: &str = "tls.peer.issuer";
/// The peer certificate's fingerprint, as the transport wrote it.
pub const TLS_PEER_FINGERPRINT: &str = "tls.peer.fingerprint";

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
/// The NEGOTIATE (type 1) message of the same handshake, base64, where the
/// transport kept it; the transport writes it as a property of this name.
pub const NTLM_NEGOTIATE: &str = "ntlm.negotiate";
/// The CHALLENGE (type 2) message the node answered with, base64, where the
/// transport kept it; the transport writes it as a property of this name.
pub const NTLM_CHALLENGE: &str = "ntlm.challenge";
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
            TLS_PEER_ISSUER,
            TLS_PEER_FINGERPRINT,
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
            NTLM_NEGOTIATE,
            NTLM_CHALLENGE,
            CERTIFICATE_CHAIN,
            MUTUAL_TLS_HANDSHAKE,
            SSH_KEY_SIGNATURE,
            SSH_KEY_SESSION,
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }
}
