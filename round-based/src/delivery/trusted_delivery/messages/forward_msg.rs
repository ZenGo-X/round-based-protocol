use std::convert::TryFrom;

use secp256k1::{PublicKey, Signature, SECP256K1};
use sha2::{Digest, Sha256};

use thiserror::Error;

use super::{DataMsg, FixedSizeMsg};

pub struct ForwardMsgHeader {
    pub sender: PublicKey,
    pub is_broadcast: bool,
    pub signature: Signature,
    pub data_len: u16,
}

impl ForwardMsgHeader {
    pub const SIZE: usize = 33 // Sender identity
        + 1  // is_broadcast flag
        + 64 // Signature
        + 2; // Data len (u16)

    pub fn verify(
        &self,
        recipient_identity: &PublicKey,
        msg: &[u8],
    ) -> Result<(), secp256k1::Error> {
        let message_hash = Sha256::new()
            .chain(&[u8::from(self.is_broadcast)])
            .chain(if !self.is_broadcast {
                recipient_identity.serialize()
            } else {
                [0u8; 33]
            })
            .chain(msg)
            .finalize();
        let message_hash = secp256k1::Message::from_slice(&message_hash)
            .expect("sha256 output is a valid secp256k1::Message");
        SECP256K1.verify(&message_hash, &self.signature, &self.sender)
    }
}

impl FixedSizeMsg for ForwardMsgHeader {
    type BytesArray = [u8; ForwardMsgHeader::SIZE];
    type ParseError = InvalidForwardMsgHeader;

    fn parse(input: &Self::BytesArray) -> Result<Self, Self::ParseError> {
        let sender = PublicKey::from_slice(&input[..33])
            .map_err(InvalidForwardMsgHeader::InvalidSenderIdentity)?;
        let is_broadcast = match input[33] {
            0 => false,
            1 => true,
            x => return Err(InvalidForwardMsgHeader::InvalidIsBroadcast(x)),
        };
        let signature = Signature::from_compact(&input[33 + 1..33 + 1 + 64])
            .map_err(InvalidForwardMsgHeader::InvalidSignature)?;
        let data_len =
            <[u8; 2]>::try_from(&input[33 + 1 + 64..]).expect("provided exactly 2 bytes");
        let data_len = u16::from_be_bytes(data_len);

        Ok(Self {
            sender,
            is_broadcast,
            signature,
            data_len,
        })
    }

    fn to_bytes(&self) -> Self::BytesArray {
        let mut msg = [0u8; ForwardMsgHeader::SIZE];

        msg[0..33].copy_from_slice(&self.sender.serialize());
        msg[33] = u8::from(self.is_broadcast);
        msg[33 + 1..33 + 1 + 64].copy_from_slice(&self.signature.serialize_compact());
        msg[33 + 1 + 64..].copy_from_slice(&self.data_len.to_be_bytes());

        msg
    }
}

pub struct ForwardMsg {
    recipient_identity: PublicKey,
}

impl ForwardMsg {
    pub fn new(recipient_identity: PublicKey) -> Self {
        Self { recipient_identity }
    }
}

impl DataMsg for ForwardMsg {
    type Header = ForwardMsgHeader;
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
            .map_err(InvalidForwardMsg::InvalidSignature)
    }
}

#[derive(Debug, Error)]
pub enum InvalidForwardMsgHeader {
    #[error("invalid sender identity")]
    InvalidSenderIdentity(#[source] secp256k1::Error),
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
    InvalidSignature(#[source] secp256k1::Error),
}
