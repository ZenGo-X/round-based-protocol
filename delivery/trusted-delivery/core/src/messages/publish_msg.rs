use std::convert::{TryFrom, TryInto};

use generic_array::typenum::{Unsigned, U1, U2};
use generic_array::GenericArray;
use sha2::Digest;

use educe::Educe;
use thiserror::Error;

use crate::crypto::{CryptoSuite, DigestExt, InvalidSignature, Serializable};
use crate::generic_array_ext::Sum;

use super::{DataMsgParser, FixedSizeMessage};

#[derive(Educe)]
#[educe(Clone, PartialEq, Eq)]
pub struct PublishMessageHeader<C: CryptoSuite> {
    pub recipient: MessageDestination<C::VerificationKey>,
    pub signature: C::Signature,
    pub data_len: u16,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MessageDestination<I> {
    /// Direct (p2p) message
    OneParty { recipient_identity: I },
    /// Broadcast message
    AllParties {
        /// Sequent number of this broadcast message
        sequence_number: u16,
    },
}

impl<I> MessageDestination<I> {
    pub fn is_broadcast(&self) -> bool {
        matches!(self, MessageDestination::AllParties { .. })
    }

    /// Returns recipient identity if it's p2p message
    pub fn recipient_identity(&self) -> Option<&I> {
        match self {
            MessageDestination::OneParty {
                recipient_identity: party_identity,
            } => Some(party_identity),
            _ => None,
        }
    }

    /// Returns message sequent number if it's broadcast message
    pub fn sequence_number(&self) -> Option<u16> {
        match self {
            MessageDestination::AllParties { sequence_number } => Some(*sequence_number),
            _ => None,
        }
    }
}

impl<C: CryptoSuite> PublishMessageHeader<C> {
    pub fn new(
        identity_key: &C::SigningKey,
        recipient: MessageDestination<C::VerificationKey>,
        msg: &[u8],
        tag: &[u8],
    ) -> Self {
        let signature = C::Digest::new()
            .chain(&[u8::from(recipient.is_broadcast())])
            .chain(
                recipient
                    .sequence_number()
                    .map(u16::to_be_bytes)
                    .unwrap_or_default(),
            )
            .chain(
                recipient
                    .recipient_identity()
                    .map(C::VerificationKey::to_bytes)
                    .unwrap_or_default(),
            )
            .chain(msg)
            .chain(tag)
            .sign_message(identity_key);
        Self {
            recipient,
            signature,
            data_len: (msg.len() + tag.len())
                .try_into()
                .expect("message len overflows u16"),
        }
    }

    pub fn verify(
        &self,
        sender_identity: &C::VerificationKey,
        msg: &[u8],
    ) -> Result<(), InvalidSignature> {
        C::Digest::new()
            .chain(&[u8::from(self.recipient.is_broadcast())])
            .chain(
                self.recipient
                    .sequence_number()
                    .map(u16::to_be_bytes)
                    .unwrap_or_default(),
            )
            .chain(
                self.recipient
                    .recipient_identity()
                    .map(C::VerificationKey::to_bytes)
                    .unwrap_or_default(),
            )
            .chain(msg)
            .verify_signature(sender_identity, &self.signature)
    }
}

impl<C: CryptoSuite> FixedSizeMessage for PublishMessageHeader<C> {
    type Size = Sum![
        U1,                     // is_broadcast flag
        C::VerificationKeySize, // recipient identity (zeroes if it's broadcast msg)
        C::SignatureSize,       // signature
        U2,                     // msg len (u16)
    ];
    type ParseError = InvalidPublishMsgHeader;

    fn parse(input: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
        let identity_size = C::VerificationKeySize::to_usize();
        let signature_size = C::SignatureSize::to_usize();

        let is_broadcast = match input[0] {
            0 => false,
            1 => true,
            x => return Err(InvalidPublishMsgHeader::InvalidIsBroadcast(x)),
        };

        let recipient = if !is_broadcast {
            MessageDestination::OneParty {
                recipient_identity: C::VerificationKey::from_bytes(&input[1..1 + identity_size])
                    .map_err(|_| InvalidPublishMsgHeader::InvalidRecipientIdentity)?,
            }
        } else {
            let seq_num_size = 2;
            let seq_num: [u8; 2] = input[1..1 + seq_num_size]
                .try_into()
                .expect("exactly two bytes are given");
            let seq_num = u16::from_be_bytes(seq_num);

            // This sophisticated check ensures that `input[1 + seq_num_size..1 + identity_size]` are zeroes
            if GenericArray::<u8, C::VerificationKeySize>::default()
                .starts_with(&input[1 + seq_num_size..1 + identity_size])
            {
                return Err(InvalidPublishMsgHeader::BroadcastHasDestination);
            }

            MessageDestination::AllParties {
                sequence_number: seq_num,
            }
        };

        let signature =
            C::Signature::from_bytes(&input[1 + identity_size..1 + identity_size + signature_size])
                .map_err(|_| InvalidPublishMsgHeader::InvalidSignature)?;

        let message_body_len = <[u8; 2]>::try_from(&input[1 + identity_size + signature_size..])
            .expect("we gave exactly two bytes");
        let message_body_len = u16::from_be_bytes(message_body_len);

        Ok(Self {
            recipient,
            signature,
            data_len: message_body_len,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let identity_size = C::VerificationKeySize::to_usize();
        let sequence_number_size = 2;
        let signature_size = C::SignatureSize::to_usize();

        let mut msg = GenericArray::<u8, Self::Size>::default();

        msg[0] = self.recipient.is_broadcast().into();
        match &self.recipient {
            MessageDestination::OneParty { recipient_identity } => {
                msg[1..1 + identity_size].copy_from_slice(&recipient_identity.to_bytes())
            }
            MessageDestination::AllParties { sequence_number } => {
                msg[1..1 + sequence_number_size].copy_from_slice(&sequence_number.to_be_bytes())
            }
        }
        msg[1 + identity_size..1 + identity_size + signature_size]
            .copy_from_slice(&self.signature.to_bytes());
        msg[1 + identity_size + signature_size..].copy_from_slice(&self.data_len.to_be_bytes());

        msg
    }
}

pub struct PublishMsg<C: CryptoSuite> {
    sender_identity: C::VerificationKey,
}

impl<C: CryptoSuite> PublishMsg<C> {
    pub fn new(sender_identity: C::VerificationKey) -> Self {
        Self { sender_identity }
    }
}

impl<C: CryptoSuite> DataMsgParser for PublishMsg<C> {
    type Header = PublishMessageHeader<C>;
    type ValidateError = InvalidPublishMsg;

    fn data_size(&self, header: &Self::Header) -> usize {
        header.data_len.into()
    }

    fn validate(&self, header: &Self::Header, data: &[u8]) -> Result<(), Self::ValidateError> {
        if data.len() != self.data_size(header) {
            return Err(InvalidPublishMsg::MismatchedLength {
                expected_len: self.data_size(header),
                actual_len: data.len(),
            });
        }

        header
            .verify(&self.sender_identity, data)
            .map_err(|_| InvalidPublishMsg::InvalidSignature)?;

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum InvalidPublishMsgHeader {
    #[error("is_broadcast flag has incorrect value: {0} (expected 0 or 1)")]
    InvalidIsBroadcast(u8),
    #[error("recipient identity is invalid")]
    InvalidRecipientIdentity,
    #[error("malformed header: specified both is_broadcast=true and destination != 0")]
    BroadcastHasDestination,
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Debug, Error)]
pub enum InvalidPublishMsg {
    #[error("mismatched length of data message: expected {expected_len} bytes, actually {actual_len} bytes")]
    MismatchedLength {
        expected_len: usize,
        actual_len: usize,
    },
    #[error("signature doesn't match the message")]
    InvalidSignature,
}
