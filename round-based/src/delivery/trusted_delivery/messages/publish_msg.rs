use std::convert::{TryFrom, TryInto};

use generic_array::typenum::{Unsigned, U1, U2};
use generic_array::GenericArray;
use sha2::Digest;

use thiserror::Error;

use crate::delivery::trusted_delivery::client::insecure::crypto::{
    CryptoSuite, DigestExt, InvalidSignature, Serializable,
};
use crate::delivery::trusted_delivery::generic_array_ext::Sum;

use super::{DataMsg, FixedSizeMessage};

pub struct PublishMessageHeader<C: CryptoSuite> {
    pub recipient: Option<C::VerificationKey>,
    pub signature: C::Signature,
    pub message_body_len: u16,
}

impl<C: CryptoSuite> PublishMessageHeader<C> {
    pub fn new(
        identity_key: &C::SigningKey,
        recipient: Option<C::VerificationKey>,
        msg: &[u8],
        tag: &[u8],
    ) -> Self {
        let signature = C::Digest::new()
            .chain(&[u8::from(recipient.is_some())])
            .chain(
                recipient
                    .as_ref()
                    .map(C::VerificationKey::to_bytes)
                    .unwrap_or_default(),
            )
            .chain(msg)
            .chain(tag)
            .sign_message(identity_key);
        Self {
            recipient,
            signature,
            message_body_len: (msg.len() + tag.len())
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
            .chain(&[u8::from(self.recipient.is_some())])
            .chain(
                self.recipient
                    .as_ref()
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
            Some(
                C::VerificationKey::from_bytes(&input[1..1 + identity_size])
                    .map_err(|_| InvalidPublishMsgHeader::InvalidRecipientIdentity)?,
            )
        } else {
            if input[1..1 + identity_size] != *GenericArray::<u8, C::VerificationKeySize>::default()
            {
                return Err(InvalidPublishMsgHeader::BroadcastHasDestination);
            }
            None
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
            message_body_len,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let identity_size = C::VerificationKeySize::to_usize();
        let signature_size = C::SignatureSize::to_usize();

        let mut msg = GenericArray::<u8, Self::Size>::default();

        msg[0] = self.recipient.is_some().into();
        if let Some(recipient) = &self.recipient {
            msg[1..1 + identity_size].copy_from_slice(&recipient.to_bytes());
        }
        msg[1 + identity_size..1 + identity_size + signature_size]
            .copy_from_slice(&self.signature.to_bytes());
        msg[1 + identity_size + signature_size..]
            .copy_from_slice(&self.message_body_len.to_be_bytes());

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

impl<C: CryptoSuite> DataMsg for PublishMsg<C> {
    type Header = PublishMessageHeader<C>;
    type ValidateError = InvalidPublishMsg;

    fn data_size(&self, header: &Self::Header) -> usize {
        header.message_body_len.into()
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
