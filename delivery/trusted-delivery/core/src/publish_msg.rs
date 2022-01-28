use std::convert::{TryFrom, TryInto};

use generic_array::{ArrayLength, GenericArray};
use sha2::Digest;
use typenum::{Unsigned, U1, U2};

use educe::Educe;
use thiserror::Error;

use crate::crypto::*;
use crate::generic_array_ext::Sum;

pub trait Header
where
    Self: Sized + Unpin,
{
    type CryptoSuite: CryptoSuite;

    type Size: ArrayLength<u8>;
    type ParseError;

    fn parse(raw: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError>;
    fn to_bytes(&self) -> GenericArray<u8, Self::Size>;

    fn data_len(&self) -> u16;
    fn verify(
        &self,
        verification_key: &<Self::CryptoSuite as CryptoSuite>::VerificationKey,
        data: &[u8],
    ) -> Result<(), InvalidSignature>;
}

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
            .sign_message(identity_key);
        Self {
            recipient,
            signature,
            data_len: msg.len().try_into().expect("message len overflows u16"),
        }
    }
}

impl<C: CryptoSuite> Header for PublishMessageHeader<C> {
    type CryptoSuite = C;

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
            let zeroes = &GenericArray::<u8, C::VerificationKeySize>::default()
                [..identity_size - seq_num_size];
            if &input[1 + seq_num_size..1 + identity_size] != zeroes {
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

    fn data_len(&self) -> u16 {
        self.data_len
    }

    fn verify(
        &self,
        sender_identity: &C::VerificationKey,
        data: &[u8],
    ) -> Result<(), InvalidSignature> {
        if data.len() != usize::from(self.data_len) {
            return Err(InvalidSignature);
        }

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
            .chain(data)
            .verify_signature(sender_identity, &self.signature)
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

#[derive(Educe)]
#[educe(Clone, PartialEq, Eq, Debug)]
pub struct ForwardMessageHeader<C: CryptoSuite> {
    pub sender: C::VerificationKey,
    pub is_broadcast: bool,
    pub sequence_number: Option<u16>,
    pub signature: C::Signature,
    pub data_len: u16,
}

impl<C: CryptoSuite> ForwardMessageHeader<C> {
    pub fn new(
        sender_identity_key: &C::SigningKey,
        recipient: MessageDestination<C::VerificationKey>,
        msg: &[u8],
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
            .sign_message(sender_identity_key);
        Self {
            sender: sender_identity_key.verification_key(),
            is_broadcast: recipient.is_broadcast(),
            sequence_number: recipient.sequence_number(),
            signature,
            data_len: msg.len().try_into().unwrap(),
        }
    }
}

impl<C: CryptoSuite> Header for ForwardMessageHeader<C> {
    type CryptoSuite = C;

    type Size = Sum![
        <C::VerificationKey as Serializable>::Size, // Sender identity
        U1,                                         // is_broadcast flag
        U2,                                         // Sequence number
        C::SignatureSize,                           // Signature
        U2,                                         // Data len (u16)
    ];
    type ParseError = InvalidForwardMsgHeader;

    fn parse(input: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
        let identity_size = C::VerificationKeySize::to_usize();
        let seq_num_size = 2;
        let signature_size = C::SignatureSize::to_usize();

        let sender = C::VerificationKey::from_bytes(&input[..identity_size])
            .map_err(|_| InvalidForwardMsgHeader::InvalidSenderIdentity)?;
        let is_broadcast = match input[identity_size] {
            0 => false,
            1 => true,
            x => return Err(InvalidForwardMsgHeader::InvalidIsBroadcast(x)),
        };
        let sequence_number = if is_broadcast {
            if input[identity_size + 1..identity_size + 1 + seq_num_size] != [0u8; 2] {
                return Err(InvalidForwardMsgHeader::NonZeroSequenceNumberForDirectMessage);
            }
            None
        } else {
            let seq_num: [u8; 2] = input[identity_size + 1..identity_size + 1 + seq_num_size]
                .try_into()
                .expect("exactly two bytes are given");
            Some(u16::from_be_bytes(seq_num))
        };
        let signature = C::Signature::from_bytes(
            &input[identity_size + 1 + seq_num_size
                ..identity_size + 1 + seq_num_size + signature_size],
        )
        .map_err(|_| InvalidForwardMsgHeader::InvalidSignature)?;
        let data_len =
            <[u8; 2]>::try_from(&input[identity_size + 1 + seq_num_size + signature_size..])
                .expect("provided exactly 2 bytes");
        let data_len = u16::from_be_bytes(data_len);

        Ok(Self {
            sender,
            is_broadcast,
            sequence_number,
            signature,
            data_len,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let identity_size = C::VerificationKeySize::to_usize();
        let seq_num_size = 2;
        let signature_size = C::SignatureSize::to_usize();

        let mut msg = GenericArray::<u8, Self::Size>::default();

        msg[0..identity_size].copy_from_slice(&self.sender.to_bytes());
        msg[identity_size] = u8::from(self.is_broadcast);
        msg[identity_size + 1..identity_size + 1 + seq_num_size].copy_from_slice(
            &self
                .sequence_number
                .map(u16::to_be_bytes)
                .unwrap_or_default(),
        );
        msg[identity_size + 1 + seq_num_size..identity_size + 1 + seq_num_size + signature_size]
            .copy_from_slice(&self.signature.to_bytes());
        msg[identity_size + 1 + seq_num_size + signature_size..]
            .copy_from_slice(&self.data_len.to_be_bytes());

        msg
    }

    fn data_len(&self) -> u16 {
        self.data_len
    }

    fn verify(
        &self,
        recipient_identity: &C::VerificationKey,
        data: &[u8],
    ) -> Result<(), InvalidSignature> {
        if data.len() != usize::from(self.data_len) {
            return Err(InvalidSignature);
        }

        C::Digest::new()
            .chain(&[u8::from(self.is_broadcast)])
            .chain(
                self.sequence_number
                    .map(u16::to_be_bytes)
                    .unwrap_or_default(),
            )
            .chain(if !self.is_broadcast {
                recipient_identity.to_bytes()
            } else {
                GenericArray::default()
            })
            .chain(data)
            .verify_signature(recipient_identity, &self.signature)
    }
}

pub struct ForwardMsg<C: CryptoSuite> {
    recipient_identity: C::VerificationKey,
}

impl<C: CryptoSuite> ForwardMsg<C> {
    pub fn new(recipient_identity: C::VerificationKey) -> Self {
        Self { recipient_identity }
    }
}

// impl<C: CryptoSuite> DataMsgParser for ForwardMsg<C> {
//     type Header = ForwardMsgHeader<C>;
//     type ValidateError = InvalidForwardMsg;
//
//     fn data_size(&self, header: &Self::Header) -> usize {
//         header.data_len.into()
//     }
//
//     fn validate(&self, header: &Self::Header, data: &[u8]) -> Result<(), Self::ValidateError> {
//         if data.len() != self.data_size(header) {
//             return Err(InvalidForwardMsg::MismatchedLength {
//                 expected_len: self.data_size(header),
//                 actual_len: data.len(),
//             });
//         }
//         header
//             .verify(&self.recipient_identity, data)
//             .map_err(|_| InvalidForwardMsg::InvalidSignature)
//     }
// }

#[derive(Debug, Error)]
pub enum InvalidForwardMsgHeader {
    #[error("invalid sender identity")]
    InvalidSenderIdentity,
    #[error("is_broadcast flag has unexpected value: {0} (expected 0 or 1)")]
    InvalidIsBroadcast(u8),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("p2p message has non zero sequence number")]
    NonZeroSequenceNumberForDirectMessage,
}

#[derive(Debug, Error)]
pub enum InvalidForwardMsg {
    #[error("mismatched length of data message: expected {expected_len} bytes, actually {actual_len} bytes")]
    MismatchedLength {
        expected_len: usize,
        actual_len: usize,
    },
    #[error("signature doesn't match the message")]
    InvalidSignature,
}
