//! What the first gate makes of a JSON Web Token: the compact token a
//! property carries, and the principal name its claims name (ADR-0054).
//!
//! The token itself — its three parts, its base64url, its claims set read
//! with every member named once — is `xmip-core-library-jose`'s
//! (`jose::jwt::Token`), which the second gate checks the signature of too.
//! Reading the claims is this gate's work and checking the signature the
//! next one's (ADR-0050); `xmip-core-identify-jwt` and `-oidc` both call
//! what is here, so neither depends on the other (ADR-0044).

use jose::jwt::Token;

use crate::{PrincipalName, ServicePrincipalName, UserPrincipalName};

/// The compact token a property carries: after `scheme` where one is named
/// (`Bearer`, compared without regard to case), the whole value where none
/// is, and nothing where the value is not a compact token. Both
/// technologies that read a token off a header read it this way, and each
/// carried its own copy until 2026-09-22.
#[must_use]
pub fn carried<'a>(raw: &'a str, scheme: Option<&str>) -> Option<&'a str> {
    let token = match scheme {
        Some(scheme) => crate::authorization::under(raw, scheme)?,
        None => raw.trim(),
    };
    jose::jws::is_compact(token).then_some(token)
}

/// The principal name a token carries, where it carries one (ADR-0054): a
/// user's under `upn`, else `preferred_username`; an application's under
/// `azp`, else `appid`, where the token is an application's — `idtyp` is
/// `app`, or it names no user at all. An opaque identifier is not a
/// principal name and yields nothing.
#[must_use]
pub fn principal(token: &Token) -> Option<PrincipalName> {
    let users: Vec<&str> = ["upn", "preferred_username"]
        .iter()
        .filter_map(|claim| token.claim(claim))
        .collect();
    let application = token.claim("idtyp") == Some("app");

    if !application && !users.is_empty() {
        return users
            .iter()
            .find_map(|text| UserPrincipalName::parse(text))
            .map(PrincipalName::User);
    }

    ["azp", "appid"]
        .iter()
        .filter_map(|claim| token.claim(claim))
        .find_map(ServicePrincipalName::parse)
        .map(PrincipalName::Service)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_carried_under_its_scheme_or_bare_and_an_opaque_one_is_not() {
        assert_eq!(carried(" bearer a.b.c ", Some("Bearer")), Some("a.b.c"));
        assert_eq!(carried("a.b.c", None), Some("a.b.c"));
        assert_eq!(carried("Basic a.b.c", Some("Bearer")), None);
        assert_eq!(carried("Bearer opaque", Some("Bearer")), None);
        assert_eq!(carried("Bearer a.b.c", None), None);
    }
}
