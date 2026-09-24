//! The bytes a client makes, for the tests of whoever reads them: public
//! because both gates' tests need the same bytes and a fixture copied twice
//! drifts. They build bytes and verify nothing.

use super::{
    CHANNEL_BINDINGS, END_OF_LIST, EPOCH_GAP, FLAGS, NEGOTIATE_UNICODE, SIGNATURE, TARGET_NAME,
    TICKS_PER_SECOND,
};

/// Text as UTF-16, little-endian, as NTLM writes it.
#[must_use]
pub fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A blob made at `unix_seconds`, naming `target` where given, under
/// these `MsvAvFlags`.
#[must_use]
pub fn blob(unix_seconds: u64, target: Option<&str>, flags: u32) -> Vec<u8> {
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

/// A Unicode AUTHENTICATE message naming `user` in `domain` from
/// `workstation`, with this NT response, under `flags` besides Unicode,
/// carrying `session_key`. The version and the MIC are zero; the payload
/// begins at 88, after them.
#[must_use]
pub fn authenticate(
    user: &str,
    domain: &str,
    workstation: &str,
    nt_response: &[u8],
    flags: u32,
    session_key: &[u8],
) -> Vec<u8> {
    let payloads = [
        vec![0; 24],
        nt_response.to_vec(),
        utf16(domain),
        utf16(user),
        utf16(workstation),
        session_key.to_vec(),
    ];
    let mut message = SIGNATURE.to_vec();
    message.extend_from_slice(&3u32.to_le_bytes());
    let mut offset = 88u32;
    for payload in &payloads {
        let length = u16::try_from(payload.len()).unwrap_or(u16::MAX);
        message.extend_from_slice(&length.to_le_bytes());
        message.extend_from_slice(&length.to_le_bytes());
        message.extend_from_slice(&offset.to_le_bytes());
        offset += u32::from(length);
    }
    message.extend_from_slice(&(NEGOTIATE_UNICODE | flags).to_le_bytes());
    message.extend_from_slice(&[0u8; 24]);
    for payload in &payloads {
        message.extend_from_slice(payload);
    }
    message
}
