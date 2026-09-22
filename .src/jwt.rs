//! The compact form of a JSON Web Token, read and not verified.
//!
//! RFC 7519 carries its header and claims as base64url JSON around two dots.
//! Reading the claims is the first gate's work — `xmip-core-identify-jwt`
//! presents `sub`, `-oidc` presents `sub` and `iss` — and checking the
//! signature is the second gate's, so both halves live up here (ADR-0044)
//! and neither technology depends on the other. The signature bytes are kept
//! for the authenticator; nothing here decides whether they hold.
//!
//! The claim reader is deliberately small: it finds one top-level member by
//! name and reads a string, a number or an array of strings. A token whose
//! claims need more than that is not a token this gate reads.

use crate::IdentifyError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A token split at its two dots, each part decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compact {
    /// The protected header, as JSON text.
    pub header: String,
    /// The claims set, as JSON text.
    pub claims: String,
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
    /// does not decode, or the header and claims are not UTF-8.
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
            header: decode_text(header, "header")?,
            claims: decode_text(claims, "claims")?,
            signature: decode(signature, "signature")?,
            signing_input: format!("{header}.{claims}"),
        })
    }

    /// The `alg` the header names.
    #[must_use]
    pub fn algorithm(&self) -> Option<String> {
        string_claim(&self.header, "alg")
    }

    /// The `kid` the header names, where it names one.
    #[must_use]
    pub fn key_id(&self) -> Option<String> {
        string_claim(&self.header, "kid")
    }

    /// One string claim from the claims set.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<String> {
        string_claim(&self.claims, name)
    }

    /// One numeric claim — `exp`, `nbf`, `iat` — as seconds.
    #[must_use]
    pub fn numeric_claim(&self, name: &str) -> Option<i64> {
        number_claim(&self.claims, name)
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

    /// A claim that is a string or an array of strings — `aud`, `scope`
    /// split on spaces, `roles`.
    #[must_use]
    pub fn strings_claim(&self, name: &str) -> Vec<String> {
        strings_claim(&self.claims, name)
    }
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
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| IdentifyError::new(format!("the JWT {what} is not base64url")))
}

fn decode_text(text: &str, what: &str) -> Result<String, IdentifyError> {
    String::from_utf8(decode(text, what)?)
        .map_err(|_| IdentifyError::new(format!("the JWT {what} is not UTF-8 JSON")))
}

/// Find a top-level member's value in a JSON object, as the raw slice after
/// the colon. Nested objects and arrays are skipped whole so a member inside
/// one is never mistaken for a top-level one.
fn member<'a>(json: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"{name}\"");
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = json.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'\\' if !escaped => escaped = true,
                b'"' if !escaped => in_string = false,
                _ => escaped = false,
            }
        } else {
            match byte {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth = depth.saturating_sub(1),
                b'"' if depth == 1 && json[index..].starts_with(&key) => {
                    let after = json[index + key.len()..].trim_start();
                    if let Some(rest) = after.strip_prefix(':') {
                        return Some(rest.trim_start());
                    }
                    in_string = true;
                }
                b'"' => in_string = true,
                _ => {}
            }
        }
        index += 1;
    }

    None
}

fn read_string(raw: &str) -> Option<(String, &str)> {
    let mut rest = raw.strip_prefix('"')?;
    let mut value = String::new();

    loop {
        let mut chars = rest.chars();
        match chars.next()? {
            '"' => return Some((value, chars.as_str())),
            '\\' => {
                let escaped = chars.next()?;
                let unescaped = match escaped {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    'u' => {
                        let hex = chars.as_str().get(..4)?;
                        let code = u32::from_str_radix(hex, 16).ok()?;
                        rest = chars.as_str().get(4..)?;
                        value.push(char::from_u32(code)?);
                        continue;
                    }
                    other => other,
                };
                value.push(unescaped);
            }
            other => value.push(other),
        }
        rest = chars.as_str();
    }
}

fn string_claim(json: &str, name: &str) -> Option<String> {
    read_string(member(json, name)?).map(|(value, _)| value)
}

fn number_claim(json: &str, name: &str) -> Option<i64> {
    let raw = member(json, name)?;
    let end = raw
        .find(|c: char| !(c.is_ascii_digit() || c == '-' || c == '.'))
        .unwrap_or(raw.len());
    let text = &raw[..end];
    text.parse::<i64>()
        .ok()
        .or_else(|| text.parse::<f64>().ok().map(|f| f as i64))
}

fn strings_claim(json: &str, name: &str) -> Vec<String> {
    let Some(raw) = member(json, name) else {
        return Vec::new();
    };
    if let Some((one, _)) = read_string(raw) {
        return vec![one];
    }
    let Some(mut rest) = raw.strip_prefix('[') else {
        return Vec::new();
    };
    let mut values = Vec::new();
    loop {
        rest = rest.trim_start();
        match read_string(rest) {
            Some((value, after)) => {
                values.push(value);
                rest = after.trim_start().strip_prefix(',').unwrap_or(after);
            }
            None => return values,
        }
    }
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
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode(b"sig")
        )
    }

    #[test]
    fn a_compact_token_is_split_at_its_two_dots_and_decoded() {
        let text = token(r#"{"alg":"HS256","kid":"k1"}"#, r#"{"sub":"partner-x"}"#);
        let compact = Compact::parse(&text).expect("three parts");

        assert_eq!(compact.algorithm().as_deref(), Some("HS256"));
        assert_eq!(compact.key_id().as_deref(), Some("k1"));
        assert_eq!(compact.claim("sub").as_deref(), Some("partner-x"));
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
        let failure = Compact::parse("aQ.b!!.aQ").expect_err("not base64url");

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
}
