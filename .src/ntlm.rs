//! NTLM as both gates read it: the AUTHENTICATE message, and the client's
//! half of its `NTLMv2` response — when it was made, and which service the
//! client meant to reach.
//!
//! [`Authenticate`] is the type 3 message, read once: the first gate
//! presents its user and the second verifies its response (ADR-0050).
//!
//! An NT response under `NTLMv2` is the 16-byte proof followed by an
//! `NTLMv2_CLIENT_CHALLENGE` ([MS-NLMP] 2.2.2.7): a response type and its
//! highest supported type, one byte each and both 1; six reserved bytes; a
//! timestamp, eight bytes, in hundred-nanosecond ticks since 1601; the
//! client's challenge, eight bytes; four reserved bytes; and then a list of
//! attribute and value pairs (2.2.2.1), each an identifier and a length, two
//! bytes each and little-endian, and that many bytes of value, ending at
//! `MsvAvEOL`. `MsvAvTargetName`, 0x0009, is the service principal name of
//! the target server, UTF-16 and not null-terminated. `MsvAvFlags`, 0x0006,
//! carries a bit, 0x4, that says the client took that name from an
//! untrusted source; section 3.2.5.1.2 has a server treat such a name as no
//! name at all, and [`ClientChallenge::supplied_target`] does. The same flags
//! carry 0x2, which says the AUTHENTICATE message has a MIC, and
//! `MsvAvChannelBindings`, 0x000A, is the MD5 of the channel the client
//! spoke over, sixteen bytes and all zero where it bound to none.
//!
//! Here because both gates read it and neither may copy the other
//! (ADR-0044): the first gate writes the target as evidence, the second holds
//! the client to it once the proof, which covers every byte of this, has
//! verified (ADR-0054). What is handed in is the response after its proof —
//! the part MS-NLMP calls the blob, or `temp`.

use crate::IdentifyError;

const FIXED: usize = 28;
const TIMESTAMP: usize = 8;
const END_OF_LIST: u16 = 0x0000;
const FLAGS: u16 = 0x0006;
const TARGET_NAME: u16 = 0x0009;
const CHANNEL_BINDINGS: u16 = 0x000A;
const HAS_INTEGRITY: u32 = 0x0000_0002;
const UNTRUSTED_SOURCE: u32 = 0x0000_0004;

/// Seconds between 1601-01-01 and the Unix epoch.
const EPOCH_GAP: u64 = 11_644_473_600;
const TICKS_PER_SECOND: u64 = 10_000_000;

/// The most pairs a list is walked for. The specification names eleven
/// kinds; a list far longer than that is not one.
const MOST_PAIRS: usize = 64;

/// What the client put in its `NTLMv2` response besides its challenge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientChallenge {
    /// When the client made the response: hundred-nanosecond ticks since
    /// 1601-01-01, as it is on the wire.
    pub timestamp: u64,
    /// The service principal name of the server the client meant to reach,
    /// as the client wrote it.
    pub target: Option<String>,
    /// Whether the client says it took that name from an untrusted source.
    pub untrusted: bool,
    /// Whether the client says its AUTHENTICATE message carries a MIC.
    pub integrity: bool,
    /// The hash of the channel the client bound the response to, where it
    /// bound to one: all zero on the wire is none.
    pub channel: Option<[u8; 16]>,
}

/// An attribute's identifier, its value, and the bytes after it.
type Pair<'a> = (u16, &'a [u8], &'a [u8]);

impl ClientChallenge {
    /// Read the blob of an NT response: everything after the 16-byte proof.
    /// `None` where it is not an `NTLMv2` client challenge — an `NTLMv1`
    /// response is eight bytes here and carries none of this.
    ///
    /// # Errors
    ///
    /// Where a pair runs past the end of the blob, or the target name is not
    /// UTF-16.
    pub fn read(blob: &[u8]) -> Result<Option<Self>, IdentifyError> {
        // RespType and HiRespType are both 1 in the only version there is.
        if blob.len() < FIXED || blob[..2] != [1, 1] {
            return Ok(None);
        }

        let mut ticks = [0u8; 8];
        ticks.copy_from_slice(&blob[TIMESTAMP..TIMESTAMP + 8]);
        let mut read = Self {
            timestamp: u64::from_le_bytes(ticks),
            ..Self::default()
        };
        let mut rest = &blob[FIXED..];

        for _ in 0..MOST_PAIRS {
            let Some((id, value, after)) = pair(rest)? else {
                break;
            };

            match id {
                END_OF_LIST => break,
                TARGET_NAME => read.target = Some(utf16(value)?).filter(|name| !name.is_empty()),
                FLAGS => {
                    let flags = value.get(..4).map_or(0, |quad| {
                        u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
                    });
                    read.untrusted = flags & UNTRUSTED_SOURCE != 0;
                    read.integrity = flags & HAS_INTEGRITY != 0;
                }
                CHANNEL_BINDINGS => {
                    read.channel = <[u8; 16]>::try_from(value)
                        .ok()
                        .filter(|hash| hash != &[0u8; 16]);
                }
                _ => {}
            }

            rest = after;
        }

        Ok(Some(read))
    }

    /// The target a server may hold the client to: the name it wrote, unless
    /// it flagged the name as taken from an untrusted source, which
    /// [MS-NLMP] 3.2.5.1.2 has a server treat as no name.
    #[must_use]
    pub fn supplied_target(&self) -> Option<&str> {
        if self.untrusted {
            None
        } else {
            self.target.as_deref()
        }
    }

    /// When the response was made, in seconds since the Unix epoch. Zero
    /// where the client wrote a time before it.
    #[must_use]
    pub const fn made_at(&self) -> u64 {
        (self.timestamp / TICKS_PER_SECOND).saturating_sub(EPOCH_GAP)
    }
}

/// One attribute and value pair, and what follows it. `None` where nothing
/// is left to read.
fn pair(bytes: &[u8]) -> Result<Option<Pair<'_>>, IdentifyError> {
    let Some(header) = bytes.get(..4) else {
        return Ok(None);
    };
    let id = u16::from_le_bytes([header[0], header[1]]);
    let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let Some(value) = bytes.get(4..4 + length) else {
        return Err(IdentifyError::new(format!(
            "the NTLMv2 response's attribute {id:#06x} runs past the end of the response"
        )));
    };

    Ok(Some((id, value, &bytes[4 + length..])))
}

fn utf16(value: &[u8]) -> Result<String, IdentifyError> {
    let units: Vec<u16> = value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();

    String::from_utf16(&units)
        .map_err(|_| IdentifyError::new("the NTLMv2 response's target name is not UTF-16"))
}

/// The eight bytes every NTLMSSP message opens with. `Negotiate` carries
/// NTLM as well as Kerberos, and this is how a reader tells.
pub const SIGNATURE: &[u8] = b"NTLMSSP\0";
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
// The offsets of an AUTHENTICATE message's `Len, MaxLen, BufferOffset`
// fields and its flags ([MS-NLMP] 2.2.1.3).
const NT_RESPONSE_FIELDS: usize = 20;
const DOMAIN_FIELDS: usize = 28;
const USER_FIELDS: usize = 36;
const WORKSTATION_FIELDS: usize = 44;
const SESSION_KEY_FIELDS: usize = 52;
const MESSAGE_FLAGS: usize = 60;
const PROOF: usize = 16;
/// An `NTLMv1` NT response is exactly this long.
const NTLMV1: usize = 24;

/// An AUTHENTICATE (type 3) message, read once for both gates.
///
/// [MS-NLMP] 2.2.1.3 lays it out as a fixed header of `Len, MaxLen,
/// BufferOffset` fields pointing into a payload: the LM response at 12, the
/// NT response at 20, the domain at 28, the user at 36, the workstation at
/// 44, the encrypted session key at 52 and the negotiated flags at 60; a
/// version and the MIC may follow, to 88. The first gate reads the names and
/// the client's challenge; the second the proof, the blob it covers, the
/// flags and the session key. Until 2026-09-24 each read the message itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticate {
    /// The `UserName` field, as the client spelled it.
    pub user: String,
    /// The `DomainName` field, as the client spelled it; it enters the hash
    /// exactly so.
    pub domain: String,
    /// The `Workstation` field.
    pub workstation: String,
    /// The flags the two ends negotiated, as the client states them.
    pub flags: u32,
    /// The whole `NtChallengeResponse`.
    pub nt_response: Vec<u8>,
    /// The `EncryptedRandomSessionKey`, empty where no key was exchanged.
    pub session_key: Vec<u8>,
}

impl Authenticate {
    /// Read an NTLMSSP message. `None` for a NEGOTIATE (type 1), which
    /// claims nothing yet.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an NTLMSSP message, are a CHALLENGE, are
    /// truncated, point outside themselves, or name no user.
    pub fn parse(bytes: &[u8]) -> Result<Option<Self>, IdentifyError> {
        if !bytes.starts_with(SIGNATURE) || bytes.len() < 12 {
            return Err(IdentifyError::new(
                "the NTLM message has no NTLMSSP signature",
            ));
        }
        match u32_at(bytes, 8) {
            Some(1) => return Ok(None),
            Some(2) => {
                return Err(IdentifyError::new(
                    "the NTLM message is a CHALLENGE: the server's, not a credential",
                ));
            }
            Some(3) => {}
            _ => return Err(IdentifyError::new("the NTLM message type is not 1, 2 or 3")),
        }
        let flags = u32_at(bytes, MESSAGE_FLAGS).ok_or_else(|| {
            IdentifyError::new("the NTLM AUTHENTICATE message is truncated before its flags")
        })?;
        let unicode = flags & NEGOTIATE_UNICODE != 0;
        let text = |at: usize, name: &str| text(field(bytes, at, name)?, unicode, name);

        let user = text(USER_FIELDS, "UserName")?;
        if user.is_empty() {
            return Err(IdentifyError::new(
                "the NTLM AUTHENTICATE message names no user",
            ));
        }
        Ok(Some(Self {
            user,
            domain: text(DOMAIN_FIELDS, "DomainName")?,
            workstation: text(WORKSTATION_FIELDS, "Workstation")?,
            flags,
            nt_response: field(bytes, NT_RESPONSE_FIELDS, "NtChallengeResponse")?.to_vec(),
            session_key: field(bytes, SESSION_KEY_FIELDS, "EncryptedRandomSessionKey")?.to_vec(),
        }))
    }

    /// The NT response as `NTLMv2` lays it out (2.2.2.8): the sixteen bytes
    /// of `NTProofStr`, and the client's blob they cover.
    ///
    /// # Errors
    ///
    /// Where the response is `NTLMv1`, is too short to be `NTLMv2`, or its
    /// blob is not an `NTLMv2` client challenge.
    pub fn ntlmv2(&self) -> Result<(&[u8; PROOF], &[u8]), IdentifyError> {
        if self.nt_response.len() == NTLMV1 {
            return Err(IdentifyError::new(
                "the NT response is NTLMv1 and this node verifies NTLMv2 only",
            ));
        }
        let Some((proof, blob)) = self.nt_response.split_first_chunk::<PROOF>() else {
            return Err(IdentifyError::new(
                "the NTLM AUTHENTICATE message carries no NTLMv2 response",
            ));
        };
        if !blob.starts_with(&[1, 1]) || blob.len() < FIXED {
            return Err(IdentifyError::new(
                "the NT response's blob is not an NTLMv2 client challenge",
            ));
        }
        Ok((proof, blob))
    }

    /// The client's half of the NT response, where it is an `NTLMv2` one.
    ///
    /// # Errors
    ///
    /// As [`ClientChallenge::read`].
    pub fn client_challenge(&self) -> Result<Option<ClientChallenge>, IdentifyError> {
        match self.nt_response.get(PROOF..) {
            Some(blob) if !blob.is_empty() => ClientChallenge::read(blob),
            _ => Ok(None),
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|two| u16::from_le_bytes([two[0], two[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// One `Len, MaxLen, BufferOffset` field, and the bytes it points at.
fn field<'a>(bytes: &'a [u8], at: usize, name: &str) -> Result<&'a [u8], IdentifyError> {
    let (Some(length), Some(offset)) = (u16_at(bytes, at), u32_at(bytes, at + 4)) else {
        return Err(IdentifyError::new(format!(
            "the NTLM AUTHENTICATE message is truncated before its {name} field"
        )));
    };
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    bytes
        .get(offset..offset.saturating_add(usize::from(length)))
        .ok_or_else(|| {
            IdentifyError::new(format!(
                "the NTLM AUTHENTICATE message's {name} points outside the message"
            ))
        })
}

/// A name field's text: UTF-16 where Unicode was negotiated, else one
/// character a byte.
fn text(payload: &[u8], unicode: bool, name: &str) -> Result<String, IdentifyError> {
    if unicode {
        utf16(payload).map_err(|_| IdentifyError::new(format!("the NTLM {name} is not UTF-16")))
    } else {
        Ok(payload.iter().map(|byte| char::from(*byte)).collect())
    }
}

pub mod fixture;

#[cfg(test)]
mod tests {
    use super::*;

    const THEN: u64 = 1_800_000_000;

    #[test]
    fn the_target_and_the_time_are_read_from_the_client_challenge() {
        let blob = fixture::blob(THEN, Some("HTTP/Xmip.Example"), 0x2);

        let read = ClientChallenge::read(&blob).expect("read").expect("NTLMv2");
        assert_eq!(read.target.as_deref(), Some("HTTP/Xmip.Example"));
        assert_eq!(read.supplied_target(), Some("HTTP/Xmip.Example"));
        assert_eq!(read.made_at(), THEN);
        assert!(!read.untrusted);
    }

    #[test]
    fn a_name_from_an_untrusted_source_is_read_and_is_no_supplied_target() {
        let blob = fixture::blob(THEN, Some("HTTP/xmip.example"), 0x2 | 0x4);

        let read = ClientChallenge::read(&blob).expect("read").expect("NTLMv2");
        assert!(read.untrusted);
        assert_eq!(read.target.as_deref(), Some("HTTP/xmip.example"));
        assert_eq!(read.supplied_target(), None);
    }

    #[test]
    fn the_mic_flag_and_the_channel_are_read_and_a_zero_channel_is_none() {
        let bound = fixture::blob_bound(THEN, None, 0x2, Some([0xC4; 16]));
        let read = ClientChallenge::read(&bound)
            .expect("read")
            .expect("NTLMv2");
        assert!(read.integrity);
        assert_eq!(read.channel, Some([0xC4; 16]));

        let unbound = fixture::blob_bound(THEN, None, 0, Some([0; 16]));
        let read = ClientChallenge::read(&unbound)
            .expect("read")
            .expect("NTLMv2");
        assert!(!read.integrity);
        assert_eq!(read.channel, None);
    }

    #[test]
    fn an_ntlmv1_response_is_no_client_challenge_and_a_list_may_name_no_target() {
        assert!(ClientChallenge::read(&[0x5A; 8]).expect("read").is_none());
        assert!(ClientChallenge::read(&[2u8; 40]).expect("read").is_none());

        let nameless = fixture::blob(THEN, None, 0);
        let read = ClientChallenge::read(&nameless)
            .expect("read")
            .expect("NTLMv2");
        assert_eq!(read.target, None);
    }

    fn authenticate(response: &[u8]) -> Vec<u8> {
        fixture::authenticate("alice", "CORP", "WS01", response, 0, &[])
    }

    #[test]
    fn a_type_3_is_read_into_its_names_its_proof_and_its_blob() {
        let blob = fixture::blob(THEN, Some("HTTP/xmip.example"), 0);
        let mut response = vec![7u8; 16];
        response.extend_from_slice(&blob);

        let read = Authenticate::parse(&authenticate(&response))
            .expect("read")
            .expect("a type 3");
        let (proof, covered) = read.ntlmv2().expect("NTLMv2");

        assert_eq!(
            (
                read.user.as_str(),
                read.domain.as_str(),
                read.workstation.as_str()
            ),
            ("alice", "CORP", "WS01")
        );
        assert_eq!((proof, covered), (&[7u8; 16], blob.as_slice()));
        assert_eq!(read.flags, NEGOTIATE_UNICODE);
        assert!(read.session_key.is_empty());
        let challenge = read.client_challenge().expect("read").expect("NTLMv2");
        assert_eq!(challenge.target.as_deref(), Some("HTTP/xmip.example"));
    }

    #[test]
    fn a_type_1_claims_nothing_and_a_type_2_or_a_stranger_is_refused_by_name() {
        let mut negotiate = SIGNATURE.to_vec();
        negotiate.extend_from_slice(&1u32.to_le_bytes());
        let mut challenge = SIGNATURE.to_vec();
        challenge.extend_from_slice(&2u32.to_le_bytes());

        assert_eq!(Authenticate::parse(&negotiate).expect("read"), None);
        let refused = |bytes: &[u8]| Authenticate::parse(bytes).expect_err("refused").message;
        assert!(refused(&challenge).contains("CHALLENGE"));
        assert!(refused(b"not an NTLM message").contains("NTLMSSP signature"));
        assert!(refused(&authenticate(&[])[..70]).contains("points outside"));
        let nameless = fixture::authenticate("", "CORP", "", &[], 0, &[]);
        assert!(refused(&nameless).contains("names no user"));
    }

    #[test]
    fn an_ntlmv1_or_absent_response_is_no_ntlmv2_and_says_which() {
        let refused = |response: &[u8]| {
            let read = Authenticate::parse(&authenticate(response))
                .expect("read")
                .expect("a type 3");
            assert_eq!(read.client_challenge().expect("read"), None);
            read.ntlmv2().expect_err("refused").message
        };

        assert!(refused(&[0; 24]).contains("NTLMv1"));
        assert!(refused(&[0; 8]).contains("carries no NTLMv2 response"));
    }

    #[test]
    fn a_pair_that_runs_past_the_blob_is_an_error_naming_it() {
        let mut broken = fixture::blob(THEN, None, 0);
        broken.truncate(FIXED);
        broken.extend_from_slice(&[0x09, 0x00, 0xFF, 0x00, b'H', 0]);

        let failure = ClientChallenge::read(&broken).expect_err("truncated");
        assert!(failure.message.contains("0x0009"), "{failure}");
        assert!(failure.message.contains("runs past"), "{failure}");
    }
}
