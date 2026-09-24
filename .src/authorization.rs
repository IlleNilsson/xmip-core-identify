//! The `Authorization` header, read once for both gates.
//!
//! RFC 7235: a scheme, whitespace, then a token68 or a list of `name=value`
//! parameters; the scheme is compared without regard to case. Until
//! 2026-09-22 five technologies split the scheme off themselves, three
//! decoded Basic, and the two gates read a Digest list two ways — the first
//! at every comma, the second outside quotes — so a quoted comma made the
//! first gate claim a different username than the second verified. Every
//! reader of the header on either side reads it here. The name the transport
//! puts it on the arrival under is `context::property::HTTP_AUTHORIZATION`.

use crate::IdentifyError;

/// How many characters of a bearer token its claim shows.
pub const BEARER_SHORT_FORM: usize = 8;

/// The scheme and what follows it, both trimmed; a value with no whitespace
/// is all scheme.
#[must_use]
pub fn scheme(value: &str) -> (&str, &str) {
    let value = value.trim();
    value
        .split_once(|character: char| character.is_ascii_whitespace())
        .map_or((value, ""), |(scheme, rest)| (scheme, rest.trim()))
}

/// What follows `wanted`, where the value is of that scheme and carries
/// something: a scheme alone — `Negotiate` asking to begin — carries no
/// credential.
#[must_use]
pub fn under<'a>(value: &'a str, wanted: &str) -> Option<&'a str> {
    let (found, rest) = scheme(value);
    (found.eq_ignore_ascii_case(wanted) && !rest.is_empty()).then_some(rest)
}

/// RFC 7617: the user-id and password in a Basic credential, the base64
/// text after `Basic `.
///
/// # Errors
///
/// Not base64, not UTF-8, no colon between the two halves, or no user.
pub fn basic(credential: &str) -> Result<(String, String), IdentifyError> {
    let decoded = codec::base64::decode(credential.trim())
        .map_err(|_| IdentifyError::new("the Basic credential is not base64"))?;
    let text = String::from_utf8(decoded)
        .map_err(|_| IdentifyError::new("the Basic credential is not UTF-8"))?;
    let (user, password) = text.split_once(':').ok_or_else(|| {
        IdentifyError::new("the Basic credential has no colon between user and password")
    })?;
    if user.is_empty() {
        return Err(IdentifyError::new("the Basic credential names no user"));
    }
    Ok((user.to_string(), password.to_string()))
}

/// A bearer token as its claim shows it: the first
/// [`BEARER_SHORT_FORM`] characters and an ellipsis, so the record can tell
/// two tokens apart without holding either. The second gate compares the
/// claim with this, so it is computed in one place.
#[must_use]
pub fn bearer_short(token: &str) -> String {
    token
        .chars()
        .take(BEARER_SHORT_FORM)
        .chain(std::iter::once('…'))
        .collect()
}

/// RFC 7235 section 2.1: a parameter list split at the commas outside
/// quotes, each name lower-cased and each quoted value unquoted and
/// unescaped.
#[must_use]
pub fn parameters(list: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in list.chars().chain(std::iter::once(',')) {
        if escaped {
            current.push(character);
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == ',' && !quoted {
            if let Some((name, value)) = current.split_once('=') {
                pairs.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
            current.clear();
        } else {
            current.push(character);
        }
    }
    pairs
}

/// One parameter's value, by name without regard to case.
#[must_use]
pub fn parameter(list: &str, name: &str) -> Option<String> {
    parameters(list)
        .into_iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_is_split_off_and_compared_without_regard_to_case() {
        assert_eq!(scheme("  Basic  YWxp "), ("Basic", "YWxp"));
        assert_eq!(scheme("Negotiate"), ("Negotiate", ""));
        assert_eq!(under("negotiate abc", "Negotiate"), Some("abc"));
        assert_eq!(under("NTLM abc", "Negotiate"), None);
        assert_eq!(under("Negotiate ", "Negotiate"), None);
    }

    #[test]
    fn a_basic_credential_is_its_user_and_password() {
        assert_eq!(
            basic("YWxpY2U6cGVuY2lsOjE=").expect("read"),
            ("alice".to_string(), "pencil:1".to_string())
        );
        assert!(basic("not*base64").is_err());
        assert!(basic("YWxpY2U=").is_err(), "no colon");
        assert!(basic("OnBlbmNpbA==").is_err(), "no user");
    }

    #[test]
    fn a_quoted_comma_does_not_end_a_parameter() {
        let list = r#"username="Mufasa", uri="/a,b", realm="x\"y""#;
        assert_eq!(parameter(list, "USERNAME").as_deref(), Some("Mufasa"));
        assert_eq!(parameter(list, "uri").as_deref(), Some("/a,b"));
        assert_eq!(parameter(list, "realm").as_deref(), Some("x\"y"));
        assert_eq!(parameter(list, "nonce"), None);
    }

    #[test]
    fn a_bearer_claim_shows_eight_characters() {
        assert_eq!(bearer_short("mF_9.B5f-4.1JqM"), "mF_9.B5f…");
    }
}
