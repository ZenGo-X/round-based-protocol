use std::convert::{TryFrom, TryInto};

use generic_array::typenum::{Unsigned, U1, U2};
use generic_array::GenericArray;
use sha2::Digest;

use thiserror::Error;

use crate::delivery::trusted_delivery::client::insecure::crypto::{
    CryptoSuite, DigestExt, InvalidSignature, PublicKey, SigningKey,
};
use crate::delivery::trusted_delivery::generic_array_ext::Sum;

use super::{DataMsg, FixedSizeMsg};

pub struct ForwardMsgHeader<C: CryptoSuite> {
    pub sender: C::VerificationKey,
    pub is_broadcast: bool,
    pub signature: GenericArray<u8, C::SignatureSize>,
    pub data_len: u16,
}

impl<C: CryptoSuite> ForwardMsgHeader<C> {
    pub fn new(
        sender_identity_key: &C::SigningKey,
        recipient: Option<&C::VerificationKey>,
        msg: &[u8],
    ) -> Self {
        let signature = C::Digest::new()
            .chain(&[u8::from(recipient.is_none())])
            .chain(recipient.map(PublicKey::to_bytes).unwrap_or_default())
            .chain(msg)
            .sign_message(sender_identity_key);
        Self {
            sender: sender_identity_key.verification_key(),
            is_broadcast: recipient.is_none(),
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
            .chain(if !self.is_broadcast {
                recipient_identity.to_bytes()
            } else {
                GenericArray::default()
            })
            .chain(msg)
            .verify_signature(recipient_identity, &self.signature)
    }
}

impl<C: CryptoSuite> FixedSizeMsg for ForwardMsgHeader<C> {
    type Size = Sum![
        <C::VerificationKey as PublicKey>::Size, // Sender identity
        U1,                                      // is_broadcast flag
        C::SignatureSize,                        // Signature
        U2,                                      // Data len (u16)
    ];
    type ParseError = InvalidForwardMsgHeader;

    fn parse(input: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
        let identity_size = C::VerificationKeySize::to_usize();
        let signature_size = C::SignatureSize::to_usize();

        let sender = C::VerificationKey::from_bytes(&input[..identity_size])
            .map_err(|_| InvalidForwardMsgHeader::InvalidSenderIdentity)?;
        let is_broadcast = match input[identity_size] {
            0 => false,
            1 => true,
            x => return Err(InvalidForwardMsgHeader::InvalidIsBroadcast(x)),
        };
        let signature = GenericArray::<u8, C::SignatureSize>::from_slice(
            &input[identity_size + 1..identity_size + 1 + signature_size],
        )
        .clone();
        let data_len = <[u8; 2]>::try_from(&input[identity_size + 1 + signature_size..])
            .expect("provided exactly 2 bytes");
        let data_len = u16::from_be_bytes(data_len);

        Ok(Self {
            sender,
            is_broadcast,
            signature,
            data_len,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let identity_size = C::VerificationKeySize::to_usize();
        let signature_size = C::SignatureSize::to_usize();

        let mut msg = GenericArray::<u8, Self::Size>::default();

        msg[0..identity_size].copy_from_slice(&self.sender.to_bytes());
        msg[identity_size] = u8::from(self.is_broadcast);
        msg[identity_size + 1..identity_size + 1 + signature_size]
            .copy_from_slice(self.signature.as_slice());
        msg[identity_size + 1 + signature_size..].copy_from_slice(&self.data_len.to_be_bytes());

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

impl<C: CryptoSuite> DataMsg for ForwardMsg<C> {
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
    InvalidSignature(#[source] secp256k1::Error),
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
