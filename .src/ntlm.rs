//! The client's half of an `NTLMv2` response: when it was made, and which
//! service the client meant to reach.
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
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();

    String::from_utf16(&units)
        .map_err(|_| IdentifyError::new("the NTLMv2 response's target name is not UTF-16"))
}

/// A blob as a client makes one, for the tests of whoever reads it: made at
/// `unix_seconds`, naming `target` where given, under these flags. Public
/// because two technologies' tests need the same bytes and a fixture copied
/// twice drifts; it builds bytes and verifies nothing.
#[must_use]
pub fn blob_for(unix_seconds: u64, target: Option<&str>, flags: u32) -> Vec<u8> {
    blob_bound(unix_seconds, target, flags, None)
}

/// The same, bound to a channel where one is given.
#[must_use]
pub fn blob_bound(
    unix_seconds: u64,
    target: Option<&str>,
    flags: u32,
    channel: Option<[u8; 16]>,
) -> Vec<u8> {
    let ticks = (unix_seconds + EPOCH_GAP) * TICKS_PER_SECOND;
    let mut blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
    blob.extend_from_slice(&ticks.to_le_bytes());
    blob.extend_from_slice(&[0x22; 8]);
    blob.extend_from_slice(&[0; 4]);

    let mut push = |id: u16, value: &[u8]| {
        let length = u16::try_from(value.len()).unwrap_or(u16::MAX);
        blob.extend_from_slice(&id.to_le_bytes());
        blob.extend_from_slice(&length.to_le_bytes());
        blob.extend_from_slice(value);
    };
    let utf16 =
        |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };

    push(0x0002, &utf16("PARTNERX"));
    push(FLAGS, &flags.to_le_bytes());

    if let Some(target) = target {
        push(TARGET_NAME, &utf16(target));
    }
    if let Some(channel) = channel {
        push(CHANNEL_BINDINGS, &channel);
    }

    push(END_OF_LIST, &[]);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    const THEN: u64 = 1_800_000_000;

    #[test]
    fn the_target_and_the_time_are_read_from_the_client_challenge() {
        let blob = blob_for(THEN, Some("HTTP/Xmip.Example"), 0x2);

        let read = ClientChallenge::read(&blob).expect("read").expect("NTLMv2");
        assert_eq!(read.target.as_deref(), Some("HTTP/Xmip.Example"));
        assert_eq!(read.supplied_target(), Some("HTTP/Xmip.Example"));
        assert_eq!(read.made_at(), THEN);
        assert!(!read.untrusted);
    }

    #[test]
    fn a_name_from_an_untrusted_source_is_read_and_is_no_supplied_target() {
        let blob = blob_for(THEN, Some("HTTP/xmip.example"), 0x2 | 0x4);

        let read = ClientChallenge::read(&blob).expect("read").expect("NTLMv2");
        assert!(read.untrusted);
        assert_eq!(read.target.as_deref(), Some("HTTP/xmip.example"));
        assert_eq!(read.supplied_target(), None);
    }

    #[test]
    fn the_mic_flag_and_the_channel_are_read_and_a_zero_channel_is_none() {
        let bound = blob_bound(THEN, None, 0x2, Some([0xC4; 16]));
        let read = ClientChallenge::read(&bound)
            .expect("read")
            .expect("NTLMv2");
        assert!(read.integrity);
        assert_eq!(read.channel, Some([0xC4; 16]));

        let unbound = blob_bound(THEN, None, 0, Some([0; 16]));
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

        let nameless = blob_for(THEN, None, 0);
        let read = ClientChallenge::read(&nameless)
            .expect("read")
            .expect("NTLMv2");
        assert_eq!(read.target, None);
    }

    #[test]
    fn a_pair_that_runs_past_the_blob_is_an_error_naming_it() {
        let mut broken = blob_for(THEN, None, 0);
        broken.truncate(FIXED);
        broken.extend_from_slice(&[0x09, 0x00, 0xFF, 0x00, b'H', 0]);

        let failure = ClientChallenge::read(&broken).expect_err("truncated");
        assert!(failure.message.contains("0x0009"), "{failure}");
        assert!(failure.message.contains("runs past"), "{failure}");
    }
}
