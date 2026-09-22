//! The socket peer, as a transport puts it on an arrival.
//!
//! Two technologies read it — `xmip-core-identify-ip` presents the address,
//! `-dns` presents the name behind it — and each carried its own copy of the
//! property name and of the reader until 2026-09-22. Neither may depend on
//! the other, so both live up here (ADR-0044).

use std::net::{IpAddr, SocketAddr};

use crate::IdentifyError;

/// The arrival property the transport puts the socket peer on.
pub const PEER_ADDRESS: &str = "peer.address";

/// Read an address as a transport writes it: bare, with a port, or an IPv6
/// address in brackets with or without one.
///
/// # Errors
///
/// Where the text is none of those.
pub fn address(text: &str) -> Result<IpAddr, IdentifyError> {
    let text = text.trim();

    if let Ok(address) = text.parse::<IpAddr>() {
        return Ok(address);
    }
    if let Ok(socket) = text.parse::<SocketAddr>() {
        return Ok(socket.ip());
    }
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        && let Ok(address) = inner.parse::<IpAddr>()
    {
        return Ok(address);
    }

    Err(IdentifyError::new(format!(
        "the peer address {text:?} is not an IP address"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_read_bare_with_a_port_and_in_brackets() {
        let four: IpAddr = "192.0.2.10".parse().unwrap();
        let six: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(address("192.0.2.10").unwrap(), four);
        assert_eq!(address(" 192.0.2.10:4711 ").unwrap(), four);
        assert_eq!(address("2001:db8::1").unwrap(), six);
        assert_eq!(address("[2001:db8::1]").unwrap(), six);
        assert_eq!(address("[2001:db8::1]:443").unwrap(), six);
    }

    #[test]
    fn text_that_is_no_address_is_refused_and_named() {
        let error = address("not-an-address").unwrap_err();
        assert!(error.to_string().contains("not-an-address"), "{error}");
    }
}
