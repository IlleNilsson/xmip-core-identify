//! What both gates read of a SAML assertion alike: its base64, and which
//! user principal name it carries.
//!
//! The first gate scans the assertion and the second parses it to verify
//! its signature, and until 2026-09-22 each also decided on its own which
//! name the assertion carried: the first took the `NameID` only where its
//! format may hold a name and the UPN attribute only under its claims URI,
//! the second any `NameID` and any attribute whose name ended in `/upn`. So
//! one assertion could name one principal to the first gate and another to
//! the second. The rule is here, and each gate hands it what it read.

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::{IdentifyError, UserPrincipalName};

/// The proof the base64 assertion rides under, from the first gate to the
/// second.
pub const ASSERTION_PROOF: &str = "saml.assertion";

/// The `Name` of the attribute an identity provider carries a user principal
/// name under.
pub const UPN_ATTRIBUTE: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";

/// The `NameID` formats whose text may be a user principal name; a `NameID`
/// with no format is unspecified (SAML Core 8.3.1).
pub const NAMING_FORMATS: [&str; 3] = [
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
];

/// Standard base64, padded or not: identity providers differ, and the
/// binding does not say.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The bytes a base64 response or assertion carries, whitespace between
/// its lines ignored.
///
/// # Errors
///
/// Where the text is not base64.
pub fn decode(text: &str) -> Result<Vec<u8>, IdentifyError> {
    let compact: String = text.split_whitespace().collect();
    BASE64
        .decode(compact)
        .map_err(|_| IdentifyError::new("the SAML message is not base64"))
}

/// Whether an attribute of this `Name` carries a user principal name: the
/// claims URI, or `upn` alone as some identity providers write it.
#[must_use]
pub fn is_upn_attribute(name: &str) -> bool {
    let name = name.trim();
    name == UPN_ATTRIBUTE || name.eq_ignore_ascii_case("upn")
}

/// The user principal name an assertion carries (ADR-0054): the `NameID`
/// where its `format` may hold one, else the UPN attribute's value.
#[must_use]
pub fn user_principal(
    name_id: &str,
    format: Option<&str>,
    upn_attribute: Option<&str>,
) -> Option<UserPrincipalName> {
    let naming = format.is_none_or(|format| NAMING_FORMATS.contains(&format.trim()));

    naming
        .then(|| UserPrincipalName::parse(name_id.trim()))
        .flatten()
        .or_else(|| upn_attribute.and_then(|text| UserPrincipalName::parse(text.trim())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    #[test]
    fn a_naming_name_id_is_the_principal_and_an_opaque_one_defers_to_the_attribute() {
        let named = user_principal("jane@corp.example", None, None).expect("a name");
        assert_eq!(named.to_string(), "jane@corp.example");

        let opaque = user_principal(
            "jane@corp.example",
            Some(PERSISTENT),
            Some("jane@other.example"),
        )
        .expect("the attribute");
        assert_eq!(opaque.to_string(), "jane@other.example");

        assert_eq!(user_principal("x7f3", Some(PERSISTENT), None), None);
    }

    #[test]
    fn only_the_claims_uri_or_upn_alone_names_the_attribute() {
        assert!(is_upn_attribute(UPN_ATTRIBUTE));
        assert!(is_upn_attribute("UPN"));
        assert!(!is_upn_attribute("urn:evil.example/upn"));
    }

    #[test]
    fn base64_is_read_padded_or_not_across_lines() {
        assert_eq!(decode("YW\nJj").expect("read"), b"abc");
        assert_eq!(decode("YWI=").expect("read"), b"ab");
        assert_eq!(decode("YWI").expect("read"), b"ab");
        assert!(decode("not*base64").is_err());
    }
}
