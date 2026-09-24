//! The name an API key with no id in it goes by, written once for both
//! gates.
//!
//! A key the issuer put a public id in front of is named by that id. A key
//! with none is named by `sha256:` and the first eight bytes of its SHA-256
//! in hexadecimal: enough to tell two keys apart on the record, too little to
//! stand in for either. The first gate writes that name as the claim and the
//! second finds the stored key by it, so it is computed here, from the hash
//! each side already holds. Until 2026-09-24 each side wrote it itself.

/// What a name that is a digest of the key starts with.
pub const DIGEST_PREFIX: &str = "sha256:";

/// How many bytes of the key's SHA-256 the name carries.
pub const DIGEST_BYTES: usize = 8;

/// The name a key goes by, from its SHA-256: `sha256:` and sixteen
/// hexadecimal digits.
#[must_use]
pub fn digest_name(hash: &[u8]) -> String {
    let shown = hash.get(..DIGEST_BYTES).unwrap_or(hash);
    format!("{DIGEST_PREFIX}{}", codec::hex::encode(shown))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_the_prefix_and_the_first_eight_bytes_in_hex() {
        // SHA-256 of "abc", FIPS 180-2 appendix B.1.
        let hash = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest_name(&hash), "sha256:ba7816bf8f01cfea");
    }
}
