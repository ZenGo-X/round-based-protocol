use std::convert::{TryFrom, TryInto};

use secp256k1::{PublicKey, SecretKey, Signature, SECP256K1};
use sha2::{Digest, Sha256};

use thiserror::Error;

use super::{DataMsg, FixedSizeMsg};

pub struct PublishMsgHeader {
    pub recipient: Option<PublicKey>,
    pub signature: Signature,
    pub message_body_len: u16,
}

impl PublishMsgHeader {
    pub const SIZE: usize = 1 // is_broadcast flag
        + 33 // recipient identity (zeroes if it's broadcast msg)
        + 64 // signature
        + 2; // msg len (u16)

    pub fn new(identity_key: &SecretKey, recipient: Option<PublicKey>, msg: &[u8]) -> Self {
        let message_hash = Sha256::new()
            .chain(&[u8::from(recipient.is_some())])
            .chain(
                recipient
                    .as_ref()
                    .map(PublicKey::serialize)
                    .unwrap_or([0u8; 33]),
            )
            .chain(msg)
            .finalize();
        let message_hash = secp256k1::Message::from_slice(&message_hash)
            .expect("sha256 output is a valid secp256k1::Message");
        let signature = SECP256K1.sign(&message_hash, identity_key);
        Self {
            recipient,
            signature,
            message_body_len: msg.len().try_into().expect("message len overflows u16"),
        }
    }

    pub fn verify(&self, sender_identity: &PublicKey, msg: &[u8]) -> Result<(), secp256k1::Error> {
        let message_hash = Sha256::new()
            .chain(&[u8::from(self.recipient.is_some())])
            .chain(
                self.recipient
                    .as_ref()
                    .map(PublicKey::serialize)
                    .unwrap_or([0u8; 33]),
            )
            .chain(msg)
            .finalize();
        let message_hash = secp256k1::Message::from_slice(&message_hash)
            .expect("sha256 output is a valid secp256k1::Message");
        SECP256K1.verify(&message_hash, &self.signature, sender_identity)
    }
}

impl FixedSizeMsg for PublishMsgHeader {
    type BytesArray = [u8; PublishMsgHeader::SIZE];
    type ParseError = InvalidPublishMsgHeader;

    fn parse(input: &Self::BytesArray) -> Result<Self, Self::ParseError> {
        let is_broadcast = match input[0] {
            0 => false,
            1 => false,
            x => return Err(InvalidPublishMsgHeader::InvalidIsBroadcast(x)),
        };

        let recipient = if !is_broadcast {
            Some(
                PublicKey::from_slice(&input[1..1 + 33])
                    .map_err(InvalidPublishMsgHeader::InvalidRecipientIdentity)?,
            )
        } else {
            if input[1..1 + 33] != [0u8; 33] {
                return Err(InvalidPublishMsgHeader::BroadcastHasDestination);
            }
            None
        };

        let signature = Signature::from_compact(&input[1 + 33..1 + 33 + 64])
            .map_err(InvalidPublishMsgHeader::InvalidSignature)?;

        let message_body_len =
            <[u8; 2]>::try_from(&input[1 + 33 + 64..]).expect("we gave exactly two bytes");
        let message_body_len = u16::from_be_bytes(message_body_len);

        Ok(Self {
            recipient,
            signature,
            message_body_len,
        })
    }

    fn to_bytes(&self) -> Self::BytesArray {
        let mut msg = [0u8; PublishMsgHeader::SIZE];

        msg[0] = self.recipient.is_some().into();
        if let Some(recipient) = &self.recipient {
            msg[1..1 + 33].copy_from_slice(&recipient.serialize());
        }
        msg[1 + 33..1 + 33 + 64].copy_from_slice(&self.signature.serialize_compact());
        msg[1 + 33 + 64..].copy_from_slice(&self.message_body_len.to_be_bytes());

        msg
    }
}

pub struct PublishMsg {
    sender_identity: PublicKey,
}

impl PublishMsg {
    pub fn new(sender_identity: PublicKey) -> Self {
        Self { sender_identity }
    }
}

impl DataMsg for PublishMsg {
    type Header = PublishMsgHeader;
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
            .map_err(InvalidPublishMsg::InvalidSignature)?;

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum InvalidPublishMsgHeader {
    #[error("is_broadcast flag has incorrect value: {0} (expected 0 or 1)")]
    InvalidIsBroadcast(u8),
    #[error("recipient identity is invalid")]
    InvalidRecipientIdentity(#[source] secp256k1::Error),
    #[error("malformed header: specified both is_broadcast=true and destination != 0")]
    BroadcastHasDestination,
    #[error("invalid signature")]
    InvalidSignature(#[source] secp256k1::Error),
}

#[derive(Debug, Error)]
pub enum InvalidPublishMsg {
    #[error("mismatched length of data message: expected {expected_len} bytes, actually {actual_len} bytes")]
    MismatchedLength {
        expected_len: usize,
        actual_len: usize,
    },
    #[error("signature doesn't match the message")]
    InvalidSignature(#[source] secp256k1::Error),
}
