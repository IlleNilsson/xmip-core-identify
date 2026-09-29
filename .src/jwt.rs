//! The compact form of a JSON Web Token, read and not verified.
//!
//! RFC 7519 carries its header and claims as base64url JSON around two dots.
//! Reading the claims is the first gate's work — `xmip-core-identify-jwt`
//! presents `sub`, `-oidc` presents `sub` and `iss` — and checking the
//! signature is the second gate's, so both halves live up here (ADR-0044)
//! and neither technology depends on the other. The signature bytes are kept
//! for the authenticator; nothing here decides whether they hold.
//!
//! The header and the claims set are read with `serde_json`, as every
//! other JSON reader in the estate is, and a member name that appears twice
//! refuses the token: a reader that took the first and an authenticator
//! that took the last would each trust a different claim.

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::IdentifyError;

/// A token split at its two dots, each part decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compact {
    /// The protected header's members.
    pub header: Map<String, Value>,
    /// The claims set's members.
    pub claims: Map<String, Value>,
    /// The signature, as bytes. Verified by the second gate or not at all.
    pub signature: Vec<u8>,
    /// What was signed: `<header>.<claims>` exactly as it arrived.
    pub signing_input: String,
}

impl Compact {
    /// Split and decode a compact token.
    ///
    /// # Errors
    ///
    /// Where the text is not three base64url parts around two dots, or a part
    /// does not decode, or the header or claims set is not a JSON object
    /// with unique member names.
    pub fn parse(token: &str) -> Result<Self, IdentifyError> {
        let mut parts = token.trim().split('.');
        let (Some(header), Some(claims), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(IdentifyError::new(
                "a JWT has exactly three parts around two dots",
            ));
        };

        Ok(Self {
            header: decode_object(header, "header")?,
            claims: decode_object(claims, "claims")?,
            signature: decode(signature, "signature")?,
            signing_input: format!("{header}.{claims}"),
        })
    }

    /// The `alg` the header names.
    #[must_use]
    pub fn algorithm(&self) -> Option<String> {
        text(&self.header, "alg")
    }

    /// The `kid` the header names, where it names one.
    #[must_use]
    pub fn key_id(&self) -> Option<String> {
        text(&self.header, "kid")
    }

    /// One string claim from the claims set.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<String> {
        text(&self.claims, name)
    }

    /// One numeric claim — `exp`, `nbf`, `iat` — as whole seconds; a
    /// fraction is dropped.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn numeric_claim(&self, name: &str) -> Option<i64> {
        let value = self.claims.get(name)?;
        value
            .as_i64()
            .or_else(|| value.as_f64().map(|seconds| seconds as i64))
    }

    /// The principal name the token carries, where it carries one
    /// (ADR-0054): a user's under `upn`, else `preferred_username`; an
    /// application's under `azp`, else `appid`, where the token is an
    /// application's — `idtyp` is `app`, or it names no user at all. An
    /// opaque identifier is not a principal name and yields nothing. Here
    /// because `jwt` and `oidc` both need it and neither may copy the other
    /// (ADR-0044).
    #[must_use]
    pub fn principal(&self) -> Option<crate::PrincipalName> {
        let users: Vec<String> = ["upn", "preferred_username"]
            .iter()
            .filter_map(|claim| self.claim(claim))
            .collect();
        let application = self.claim("idtyp").as_deref() == Some("app");

        if !application && !users.is_empty() {
            return users
                .iter()
                .find_map(|text| crate::UserPrincipalName::parse(text))
                .map(crate::PrincipalName::User);
        }

        ["azp", "appid"]
            .iter()
            .filter_map(|claim| self.claim(claim))
            .find_map(|text| crate::ServicePrincipalName::parse(&text))
            .map(crate::PrincipalName::Service)
    }

    /// A claim that is a string or an array of strings — `aud`, `scope`,
    /// `roles` — as its strings; nothing where it is absent, or is neither,
    /// or an array holds anything but strings.
    #[must_use]
    pub fn strings_claim(&self, name: &str) -> Vec<String> {
        match self.claims.get(name) {
            Some(Value::String(one)) => vec![one.clone()],
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| value.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

/// A member's value where it is a string.
fn text(members: &Map<String, Value>, name: &str) -> Option<String> {
    members.get(name)?.as_str().map(str::to_string)
}

/// Three parts around two dots and no whitespace: the shape RFC 7515 gives a
/// compact serialization, and the test that tells a JWT from an opaque token.
#[must_use]
pub fn is_compact(token: &str) -> bool {
    token.split('.').count() == 3 && !token.contains(char::is_whitespace) && !token.is_empty()
}

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
    is_compact(token).then_some(token)
}

/// Decode base64url without padding, as RFC 7515 section 2 spells it.
///
/// # Errors
///
/// Where the text is not base64url.
pub fn decode(text: &str, what: &str) -> Result<Vec<u8>, IdentifyError> {
    codec::base64::decode_url(text.trim_end_matches('='))
        .map_err(|_| IdentifyError::new(format!("the JWT {what} is not base64url")))
}

/// The object a header or claims set is, read by `serde_json` and refused
/// where a member name appears twice — once its escapes are undone, so
/// `"sub"` is `sub` — because RFC 7519 section 4 lets a reader take
/// either and an authenticator must not trust the one a reader did not.
struct Members(Map<String, Value>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON object whose member names are unique")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Members, A::Error> {
        let mut members = Map::new();
        while let Some(name) = access.next_key::<String>()? {
            if members.contains_key(&name) {
                return Err(de::Error::custom(format!(
                    "the member {name:?} appears twice"
                )));
            }
            let value = access.next_value::<Value>()?;
            members.insert(name, value);
        }
        Ok(Members(members))
    }
}

fn decode_object(text: &str, what: &str) -> Result<Map<String, Value>, IdentifyError> {
    let bytes = decode(text, what)?;
    serde_json::from_slice::<Members>(&bytes)
        .map(|members| members.0)
        .map_err(|failure| {
            IdentifyError::new(format!("the JWT {what} is not a JSON object: {failure}"))
        })
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

    fn token(header: &str, claims: &str) -> String {
        format!(
            "{}.{}.{}",
            codec::base64::encode_url_unpadded(header.as_bytes()),
            codec::base64::encode_url_unpadded(claims.as_bytes()),
            codec::base64::encode_url_unpadded(b"sig")
        )
    }

    #[test]
    fn a_compact_token_is_split_at_its_two_dots_and_decoded() {
        let text = token(r#"{"alg":"HS256","kid":"k1"}"#, r#"{"sub":"party-x"}"#);
        let compact = Compact::parse(&text).expect("three parts");

        assert_eq!(compact.algorithm().as_deref(), Some("HS256"));
        assert_eq!(compact.key_id().as_deref(), Some("k1"));
        assert_eq!(compact.claim("sub").as_deref(), Some("party-x"));
        assert_eq!(compact.signature, b"sig");
        assert!(text.starts_with(&compact.signing_input));
    }

    #[test]
    fn a_token_without_three_parts_is_refused_by_name() {
        let failure = Compact::parse("only.two").expect_err("two parts");

        assert!(failure.message.contains("three parts"));
    }

    #[test]
    fn a_part_that_is_not_base64url_is_refused_by_name() {
        let header = codec::base64::encode_url_unpadded(br#"{"alg":"none"}"#);
        let failure = Compact::parse(&format!("{header}.b!!.aQ")).expect_err("not base64url");

        assert!(failure.message.contains("claims"));
    }

    #[test]
    fn numeric_and_array_claims_are_read_and_nested_members_are_not() {
        let text = token(
            r#"{"alg":"none"}"#,
            r#"{"exp":1700000000,"aud":["a","b"],"scope":"read","nested":{"sub":"no"}}"#,
        );
        let compact = Compact::parse(&text).expect("three parts");

        assert_eq!(compact.numeric_claim("exp"), Some(1_700_000_000));
        assert_eq!(compact.strings_claim("aud"), vec!["a", "b"]);
        assert_eq!(compact.strings_claim("scope"), vec!["read"]);
        assert_eq!(compact.claim("sub"), None);
    }

    #[test]
    fn an_escaped_string_claim_is_unescaped() {
        let text = token(r#"{"alg":"none"}"#, r#"{"sub":"a\"bA"}"#);
        let compact = Compact::parse(&text).expect("three parts");

        assert_eq!(compact.claim("sub").as_deref(), Some("a\"bA"));
    }

    #[test]
    fn every_json_escape_is_undone_and_a_surrogate_pair_is_one_character() {
        let text = token(r#"{"alg":"none"}"#, r#"{"sub":"\b\f\n\r\t\/\\é😀"}"#);
        let compact = Compact::parse(&text).expect("three parts");

        assert_eq!(
            compact.claim("sub").as_deref(),
            Some("\u{8}\u{c}\n\r\t/\\\u{e9}\u{1f600}")
        );
        let lone = token(r#"{"alg":"none"}"#, r#"{"sub":"\ud83d"}"#);
        assert!(Compact::parse(&lone).is_err(), "a lone surrogate");
    }

    #[test]
    fn a_member_name_is_matched_after_its_escapes_are_undone() {
        let text = token(r#"{"alg":"none"}"#, r#"{"sub":"party-x"}"#);
        let compact = Compact::parse(&text).expect("three parts");

        assert_eq!(compact.algorithm().as_deref(), Some("none"));
        assert_eq!(compact.claim("sub").as_deref(), Some("party-x"));
    }

    #[test]
    fn a_member_named_twice_refuses_the_token_even_behind_an_escape() {
        for claims in [
            r#"{"sub":"party-x","sub":"admin"}"#,
            r#"{"sub":"party-x","sub":"admin"}"#,
        ] {
            let failure = Compact::parse(&token(r#"{"alg":"none"}"#, claims)).expect_err(claims);
            assert!(failure.message.contains("twice"), "{}", failure.message);
        }
        let header = token(r#"{"alg":"none","alg":"HS256"}"#, r#"{"sub":"x"}"#);
        let failure = Compact::parse(&header).expect_err("a header named twice");
        assert!(failure.message.contains("header"), "{}", failure.message);
    }

    #[test]
    fn claims_that_are_not_an_object_or_a_mixed_array_are_not_read() {
        assert!(Compact::parse(&token(r#"{"alg":"none"}"#, "[1]")).is_err());
        assert!(Compact::parse(&token(r#"{"alg":"none"}"#, "{\"sub\":")).is_err());
        let text = token(
            r#"{"alg":"none"}"#,
            r#"{"aud":["a",1],"exp":1700000000.9,"sub":7}"#,
        );
        let compact = Compact::parse(&text).expect("three parts");

        assert!(compact.strings_claim("aud").is_empty());
        assert_eq!(compact.numeric_claim("exp"), Some(1_700_000_000));
        assert_eq!(compact.claim("sub"), None, "a number is not a string");
    }
}
