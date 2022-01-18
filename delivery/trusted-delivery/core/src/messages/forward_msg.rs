use std::convert::{TryFrom, TryInto};

use generic_array::typenum::{Unsigned, U1, U2};
use generic_array::GenericArray;
use sha2::Digest;

use educe::Educe;
use thiserror::Error;

use crate::crypto::{CryptoSuite, DigestExt, InvalidSignature, Serializable, SigningKey};
use crate::generic_array_ext::Sum;
use crate::messages::MessageDestination;

use super::{DataMsgParser, FixedSizeMessage};

#[derive(Educe)]
#[educe(Clone, PartialEq, Eq, Debug)]
pub struct ForwardMsgHeader<C: CryptoSuite> {
    pub sender: C::VerificationKey,
    pub is_broadcast: bool,
    pub sequence_number: Option<u16>,
    pub signature: C::Signature,
    pub data_len: u16,
}

impl<C: CryptoSuite> ForwardMsgHeader<C> {
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

    pub fn verify(
        &self,
        recipient_identity: &C::VerificationKey,
        msg: &[u8],
    ) -> Result<(), InvalidSignature> {
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
            .chain(msg)
            .verify_signature(recipient_identity, &self.signature)
    }
}

impl<C: CryptoSuite> FixedSizeMessage for ForwardMsgHeader<C> {
    type Size = Sum![
        <C::VerificationKey as Serializable>::Size, // Sender identity
        U1,                                         // is_broadcast flag
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
}

pub struct ForwardMsg<C: CryptoSuite> {
    recipient_identity: C::VerificationKey,
}

impl<C: CryptoSuite> ForwardMsg<C> {
    pub fn new(recipient_identity: C::VerificationKey) -> Self {
        Self { recipient_identity }
    }
}

impl<C: CryptoSuite> DataMsgParser for ForwardMsg<C> {
    type Header = ForwardMsgHeader<C>;
    type ValidateError = InvalidForwardMsg;

    fn data_size(&self, header: &Self::Header) -> usize {
        header.data_len.into()
    }

    fn validate(&self, header: &Self::Header, data: &[u8]) -> Result<(), Self::ValidateError> {
        if data.len() != self.data_size(header) {
            return Err(InvalidForwardMsg::MismatchedLength {
                expected_len: self.data_size(header),
                actual_len: data.len(),
            });
        }
        header
            .verify(&self.recipient_identity, data)
            .map_err(|_| InvalidForwardMsg::InvalidSignature)
    }
}

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
