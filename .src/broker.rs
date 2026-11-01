//! The sender a message broker delivered a message as (ADR-0019, amendment
//! 2026-10-31).
//!
//! A broker — RabbitMQ, IBM MQ, Amazon SQS — delivers a message with a
//! field naming who sent it: AMQP's `user-id`, which RabbitMQ refuses unless
//! it is the user the publishing connection authenticated as; IBM MQ's
//! `UserIdentifier`; SQS's `SenderId`, which the service writes itself.
//! The transport that received the message writes the field under its own
//! name (`context::property::BROKER_SENDERS`), the broker's host under
//! `broker`, and — only where its own connection proved the broker — its
//! word under `broker.verified`. This identifier reads the first sender
//! field present as the `broker` claim, detected, the broker and the field
//! as its evidence, and hands the transport's word on as proof to the
//! `broker` authenticator, which answers vouched for it and claimed
//! without it.

use context::property::{BROKER, BROKER_SENDERS, BROKER_VERIFIED};
use xcore::{Mechanism, mechanism};

use crate::evidence::BROKER_CONNECTION;
use crate::{IdentifyError, Presented, StreamArrival, TransportIdentifier};

/// The `broker` identifier.
#[derive(Clone, Copy, Debug, Default)]
pub struct Broker;

impl TransportIdentifier for Broker {
    fn mechanism(&self) -> Mechanism {
        mechanism::broker()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        let Some((field, sender)) = BROKER_SENDERS.iter().find_map(|field| {
            arrival
                .property(field)
                .map(str::trim)
                .filter(|sender| !sender.is_empty())
                .map(|sender| (*field, sender))
        }) else {
            return Ok(None);
        };

        let mut claim =
            Presented::detected(mechanism::broker(), sender).with_evidence(field, sender);
        if let Some(broker) = arrival.property(BROKER).map(str::trim) {
            claim = claim.with_evidence(BROKER, broker);
        }
        if let Some(word) = arrival.property(BROKER_VERIFIED) {
            claim = claim.with_proof(BROKER_CONNECTION, word.trim());
        }
        Ok(Some(claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::property::{AMQP_USER_ID, SQS_SENDER_ID, TLS_HANDSHAKE_VERIFIED};
    use xcore::{Arriving, Established};

    fn identified(properties: &[(&str, &str)]) -> Option<Presented> {
        let properties: Vec<(String, String)> = properties
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        let arrival = StreamArrival::new(Arriving::Pushed, "https://queue/1#m", &properties);
        Broker.identify(&arrival).expect("read")
    }

    #[test]
    fn the_first_sender_field_is_the_claim_with_the_broker_and_the_transports_word() {
        let claim = identified(&[
            (SQS_SENDER_ID, "AIDAEXAMPLE"),
            (BROKER, "sqs.eu-north-1.amazonaws.com"),
            (BROKER_VERIFIED, TLS_HANDSHAKE_VERIFIED),
        ])
        .expect("a claim");

        assert_eq!(claim.mechanism.name(), "broker");
        assert_eq!(claim.value, "AIDAEXAMPLE");
        assert_eq!(claim.established, Established::Detected);
        assert_eq!(claim.evidence(SQS_SENDER_ID), Some("AIDAEXAMPLE"));
        assert_eq!(claim.evidence(BROKER), Some("sqs.eu-north-1.amazonaws.com"));
        assert_eq!(claim.proof(BROKER_CONNECTION), Some(TLS_HANDSHAKE_VERIFIED));
        assert_eq!(claim.without_proof().proof(BROKER_CONNECTION), None);
    }

    #[test]
    fn no_sender_field_or_an_empty_one_is_no_claim() {
        assert!(identified(&[(BROKER, "broker.example")]).is_none());
        assert!(identified(&[(AMQP_USER_ID, " ")]).is_none());
        let claim = identified(&[(AMQP_USER_ID, "orders")]).expect("a claim");
        assert_eq!(claim.proof(BROKER_CONNECTION), None);
    }
}
