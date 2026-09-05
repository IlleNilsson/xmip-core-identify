#![forbid(unsafe_code)]

//! The first gate: who is claimed.
//!
//! ADR-0019 clause 2 orders three boxes, and this is the first:
//!
//! ```text
//! identity  ->  authentication  ->  authorization
//! who is claimed    is the claim true    may this true identity do this
//! ```
//!
//! **Identification proves nothing.** It establishes who is claimed and hands
//! that on. Whether the claim holds is the next gate's question.
//!
//! Three ways an identity is established, and the gate records which:
//!
//! ```text
//! Passed     the sender presented it      a certificate, a token, a header
//! Inferred   the configuration says so    this folder, this schedule, this credential
//! Detected   read out of what is there    ISA06, a signature, an envelope
//! ```
//!
//! Independent of how the Stream arrived. A pushed Stream can yield a detected
//! identity; a scheduled pickup can only yield an inferred one, because there
//! was nobody there to pass anything. [`Established`] and [`Arriving`] are both
//! on the record because the pair is what makes a disputed Journey explicable.
//!
//! Separate from authentication because the estate needs them separate. X12
//! identifies and never authenticates; a client certificate does both at once
//! but the two answers are still different answers. Collapsing them means a
//! claim and a proof look alike in the record, and telling them apart later is
//! the whole of a dispute.
//!
//! # Two entry points, because they run at different times
//!
//! ADR-0013's lifecycle runs transport identification **before** Message
//! creation and message identification **after** it:
//!
//! ```text
//! Incoming Stream
//!     -> Transport identification          <- TransportIdentifier, given a StreamArrival
//!     -> Transport authentication
//!     -> Transport authorization
//!     -> Message creation
//!     -> Default promotion
//!     -> Optional message identification   <- MessageIdentifier, given a Message
//!     -> Optional message authentication
//!     -> Optional message authorization
//! ```
//!
//! So there are two traits rather than one, and no single evidence bag that
//! pretends both are available at once. A transport identifier cannot see a
//! Message because there is not one yet, and that is the whole reason **Xmip
//! never parses content from an unauthorized sender**. A type that let it would
//! reduce the guarantee to a convention.
//!
//! *Optional* in that lifecycle means configuration decides whether message
//! identification applies. The gate is not skipped; it is asked, and may have
//! nothing to say.

use message::Message;
use std::error::Error;
use std::fmt;
use stream::Stream;
use xcore::{Arriving, Established, Layer, Mechanism};

/// A Stream arriving, and everything readable about it before a Message exists.
///
/// The Stream, how it got here, where it came from, and whatever the transport
/// can say about the connection — header values, a certificate subject, a peer
/// address, the path a file was dropped on.
///
/// Deliberately untyped beyond that. Each transport has its own vocabulary and
/// each [`TransportIdentifier`] knows which names its mechanism cares about;
/// enumerating them centrally would mean every new transport editing this
/// crate.
pub struct StreamArrival<'a> {
    stream: &'a Stream,
    arriving: Arriving,
    source_uri: &'a str,
    properties: &'a [(String, String)],
}

impl<'a> StreamArrival<'a> {
    #[must_use]
    pub const fn new(
        stream: &'a Stream,
        arriving: Arriving,
        source_uri: &'a str,
        properties: &'a [(String, String)],
    ) -> Self {
        Self {
            stream,
            arriving,
            source_uri,
            properties,
        }
    }

    /// Pushed, detected or scheduled.
    ///
    /// An identifier reads this rather than assuming a caller. There is nobody
    /// on the other end of a scheduled pickup, so a mechanism that expects a
    /// presented credential has nothing to say about one.
    #[must_use]
    pub const fn arriving(&self) -> Arriving {
        self.arriving
    }

    /// The bytes. Readable, and read by very few identifiers: a mechanism that
    /// needs the content is usually a message mechanism that has not admitted
    /// it yet.
    #[must_use]
    pub const fn stream(&self) -> &Stream {
        self.stream
    }

    /// Where it came from. The identity of a drop folder is its path, so this
    /// is a claim on its own for [`xcore::mechanism::circumstance`].
    #[must_use]
    pub const fn source_uri(&self) -> &str {
        self.source_uri
    }

    #[must_use]
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn properties(&self) -> impl Iterator<Item = (&str, &str)> {
        self.properties
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

/// A claim, read out of an arrival and not yet proven.
///
/// This is what the second gate is handed. The secret does not appear here —
/// whatever proves the claim belongs to the module that implements the
/// mechanism, not to the thing that read the name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Presented {
    pub mechanism: Mechanism,
    /// The claimed value — `CN=partner-x.example`, `sub=partner-x`,
    /// `ISA06=PARTNERX`.
    pub value: String,
    /// Passed, inferred or detected.
    ///
    /// Declared by the identifier that did the work, never by configuration —
    /// the same rule as class, layer and assurance, and for the same reason. An
    /// operator who could relabel an inferred identity as passed would have
    /// relabelled away the only thing the record is for.
    pub established: Established,
    /// What was observed alongside it. Goes onto the record whether or not the
    /// claim holds.
    pub evidence: Vec<(String, String)>,
}

impl Presented {
    /// The sender presented it.
    #[must_use]
    pub fn passed(mechanism: Mechanism, value: impl Into<String>) -> Self {
        Self::new(mechanism, value, Established::Passed)
    }

    /// The configuration is the identity — this folder, this schedule, this
    /// credential Xmip used to go and fetch it.
    #[must_use]
    pub fn inferred(mechanism: Mechanism, value: impl Into<String>) -> Self {
        Self::new(mechanism, value, Established::Inferred)
    }

    /// Read out of what arrived.
    #[must_use]
    pub fn detected(mechanism: Mechanism, value: impl Into<String>) -> Self {
        Self::new(mechanism, value, Established::Detected)
    }

    #[must_use]
    pub fn new(mechanism: Mechanism, value: impl Into<String>, established: Established) -> Self {
        Self {
            mechanism,
            value: value.into(),
            established,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push((name.into(), value.into()));
        self
    }

    /// Which gate produced it. Comes from the mechanism, so a claim cannot
    /// misreport the layer it was read at.
    #[must_use]
    pub fn layer(&self) -> Layer {
        self.mechanism.layer()
    }
}

#[derive(Debug)]
pub struct IdentifyError {
    pub message: String,
}

impl fmt::Display for IdentifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for IdentifyError {}

/// Reads one mechanism's claim off the connection, before a Message exists.
///
/// `xmip-core-identify-certificate`, `-header`, `-ip`, `-dns`, `-endpoint`,
/// `-api-key`, `-cookie`, `-jwt`, `-kerberos`, `-mac`, `-ntlm`, `-oidc`,
/// `-saml`, `-ssh-key`, `-username`, `-transport`. Each knows one shape and
/// ignores everything else.
pub trait TransportIdentifier: Send + Sync {
    fn mechanism(&self) -> Mechanism;

    /// The claim, or `None` where this arrival carries nothing this mechanism
    /// recognises.
    ///
    /// `None` is ordinary and not a failure: most identifiers see most arrivals
    /// and have nothing to say about them.
    ///
    /// # Errors
    ///
    /// Where the arrival carries something this mechanism recognises and cannot
    /// read — a malformed certificate, a truncated header. Different from
    /// carrying nothing, and an operator acts on the difference.
    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError>;
}

/// Reads one mechanism's claim out of a Message, after it exists.
///
/// `xmip-core-identify-message`, `-contract`, and the envelope readers behind
/// X12, EDIFACT and HL7.
pub trait MessageIdentifier: Send + Sync {
    fn mechanism(&self) -> Mechanism;

    /// # Errors
    ///
    /// As [`TransportIdentifier::identify`].
    fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError>;
}

/// Read every claim the connection carries. Runs before Message creation.
///
/// **All of them, not the first.** ADR-0019 clause 5: identity travels on both
/// layers and neither substitutes for the other, and one connection can carry
/// more than one transport claim — a client certificate and a bearer token on
/// the same request. Stopping at the first would discard exactly the pair a
/// dispute is about.
///
/// # Errors
///
/// The first identifier that fails outright, rather than one that simply has
/// nothing to say.
pub fn identify_transport(
    identifiers: &[&dyn TransportIdentifier],
    arrival: &StreamArrival<'_>,
) -> Result<Vec<Presented>, IdentifyError> {
    let mut claims = Vec::new();

    for identifier in identifiers {
        if let Some(claim) = identifier.identify(arrival)? {
            claims.push(claim);
        }
    }

    Ok(claims)
}

/// Read every claim the Message carries. Runs after Message creation and
/// default promotion.
///
/// # Errors
///
/// As [`identify_transport`].
pub fn identify_message(
    identifiers: &[&dyn MessageIdentifier],
    message: &Message,
) -> Result<Vec<Presented>, IdentifyError> {
    let mut claims = Vec::new();

    for identifier in identifiers {
        if let Some(claim) = identifier.identify(message)? {
            claims.push(claim);
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::MessageContext;
    use message::{
        ExecutionProfile, MessageDurability, MessagePriority, MessageSection, MessageTreatment,
    };
    use xcore::{MessageId, SectionId, StreamId, mechanism};

    /// Reads one named transport property and calls it the claim.
    struct FromProperty {
        mechanism: Mechanism,
        property: &'static str,
    }

    impl TransportIdentifier for FromProperty {
        fn mechanism(&self) -> Mechanism {
            self.mechanism.clone()
        }

        fn identify(
            &self,
            arrival: &StreamArrival<'_>,
        ) -> Result<Option<Presented>, IdentifyError> {
            Ok(arrival
                .property(self.property)
                .map(|value| Presented::passed(self.mechanism.clone(), value)))
        }
    }

    /// Reads the head of the Message and calls it an ISA06.
    struct FromEnvelope;

    impl MessageIdentifier for FromEnvelope {
        fn mechanism(&self) -> Mechanism {
            mechanism::edi_x12_interchange()
        }

        fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError> {
            let bytes = message.sections()[0].stream.bytes();
            let text = core::str::from_utf8(bytes).map_err(|_| IdentifyError {
                message: "the interchange envelope is not text".to_string(),
            })?;

            Ok(text
                .strip_prefix("ISA*")
                .map(|value| Presented::detected(mechanism::edi_x12_interchange(), value)))
        }
    }

    struct Broken;

    impl TransportIdentifier for Broken {
        fn mechanism(&self) -> Mechanism {
            mechanism::mutual_tls()
        }

        fn identify(
            &self,
            _arrival: &StreamArrival<'_>,
        ) -> Result<Option<Presented>, IdentifyError> {
            Err(IdentifyError {
                message: "the certificate did not parse".to_string(),
            })
        }
    }

    fn tls() -> FromProperty {
        FromProperty {
            mechanism: mechanism::mutual_tls(),
            property: "tls.client.subject",
        }
    }

    fn api_key() -> FromProperty {
        FromProperty {
            mechanism: mechanism::api_key(),
            property: "http.header.x-api-key",
        }
    }

    fn stream(bytes: &'static [u8]) -> Stream {
        Stream::new(StreamId::new(1), bytes.to_vec(), None)
    }

    fn message(bytes: &'static [u8]) -> Message {
        Message::received(
            MessageId::new(2),
            vec![MessageSection {
                section_id: SectionId::new(3),
                name: None,
                stream: stream(bytes),
                contract: None,
            }],
            MessageContext::new(),
            MessageTreatment {
                priority: MessagePriority::Normal,
                execution_profile: ExecutionProfile::Business,
                durability: MessageDurability::Recoverable,
            },
        )
    }

    #[test]
    fn every_claim_on_the_connection_is_read_rather_than_the_first() {
        // ADR-0019 clause 5. One request can carry a certificate and a key, and
        // a dispute is usually about the pair.
        let certificate = tls();
        let key = api_key();
        let identifiers: [&dyn TransportIdentifier; 2] = [&certificate, &key];

        let stream = stream(b"<order/>");
        let properties = [
            (
                "tls.client.subject".to_string(),
                "CN=van.example".to_string(),
            ),
            ("http.header.x-api-key".to_string(), "partner-x".to_string()),
        ];

        let claims = identify_transport(
            &identifiers,
            &StreamArrival::new(
                &stream,
                Arriving::Pushed,
                "https://xmip.example/invoices",
                &properties,
            ),
        )
        .expect("read");

        assert_eq!(claims.len(), 2);
        assert!(claims.iter().all(|claim| claim.layer() == Layer::Transport));
    }

    #[test]
    fn an_identifier_with_nothing_to_say_is_not_a_failure() {
        // Most identifiers see most arrivals and recognise nothing in them.
        let certificate = tls();
        let key = api_key();
        let identifiers: [&dyn TransportIdentifier; 2] = [&certificate, &key];

        let stream = stream(b"<order/>");
        let properties = [(
            "tls.client.subject".to_string(),
            "CN=partner-x.example".to_string(),
        )];

        let claims = identify_transport(
            &identifiers,
            &StreamArrival::new(
                &stream,
                Arriving::Pushed,
                "https://xmip.example/invoices",
                &properties,
            ),
        )
        .expect("read");

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].value, "CN=partner-x.example");
    }

    #[test]
    fn an_arrival_carrying_nothing_yields_no_claims() {
        // A raw file on a drop folder. Not an error — the circumstance becomes
        // the identity later, and that is the runtime's decision to make.
        let certificate = tls();
        let identifiers: [&dyn TransportIdentifier; 1] = [&certificate];
        let stream = stream(b"<order/>");

        assert!(
            identify_transport(
                &identifiers,
                &StreamArrival::new(&stream, Arriving::Pushed, "file:///in/x", &[])
            )
            .expect("read")
            .is_empty()
        );
    }

    #[test]
    fn malformed_evidence_is_an_error_and_not_an_absence() {
        // A certificate that does not parse is a different thing from an
        // arrival that has none, and the difference is what an operator acts
        // on.
        let broken = Broken;
        let identifiers: [&dyn TransportIdentifier; 1] = [&broken];
        let stream = stream(b"<order/>");

        let failure = identify_transport(
            &identifiers,
            &StreamArrival::new(&stream, Arriving::Pushed, "file:///in/x", &[]),
        )
        .expect_err("should fail");

        assert_eq!(failure.to_string(), "the certificate did not parse");
    }

    #[test]
    fn the_message_gate_needs_a_message_and_the_transport_gate_cannot_have_one() {
        // ADR-0013's lifecycle, enforced by the signatures rather than by
        // convention: transport identification is handed a StreamArrival and
        // message identification a Message, so no transport identifier can
        // read parsed content.
        let envelope = FromEnvelope;
        let identifiers: [&dyn MessageIdentifier; 1] = [&envelope];

        let claims = identify_message(&identifiers, &message(b"ISA*PARTNERX")).expect("read");

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].layer(), Layer::Message);
        assert_eq!(claims[0].value, "PARTNERX");
    }

    #[test]
    fn a_claim_proves_nothing_by_existing() {
        // The type carries no verdict. Whether the claim holds is the second
        // gate's answer, and nothing here can express it.
        let claim = Presented::detected(mechanism::edi_x12_interchange(), "PARTNERX")
            .with_evidence("source", "file:///in/partner-x");

        assert!(!claim.mechanism.authenticates());
        assert_eq!(claim.evidence.len(), 1);
    }
}
