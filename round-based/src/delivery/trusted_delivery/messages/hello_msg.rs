use secp256k1::{PublicKey, SecretKey, Signature, SECP256K1};
use sha2::{Digest, Sha256};

use thiserror::Error;

use super::FixedSizeMsg;

pub type RoomId = [u8; 32];

pub struct HelloMsg {
    pub identity: PublicKey,
    pub room_id: RoomId,
    pub signature: Signature,
}

impl HelloMsg {
    const SIZE: usize = 33 // identity
        + 32 // room_id
        + 64; // compact signature

    pub fn new(identity_key: &SecretKey, room_id: RoomId) -> Self {
        let message_hash = Sha256::digest(&room_id);
        let message_hash = secp256k1::Message::from_slice(&message_hash)
            .expect("sha256 output is a valid message");
        let signature = SECP256K1.sign(&message_hash, &identity_key);

        Self {
            identity: PublicKey::from_secret_key(&SECP256K1, &identity_key),
            room_id,
            signature,
        }
    }
}

impl FixedSizeMsg for HelloMsg {
    type BytesArray = [u8; HelloMsg::SIZE];
    type ParseError = InvalidHelloMsg;

    fn parse(input: &Self::BytesArray) -> Result<Self, Self::ParseError> {
        let identity =
            PublicKey::from_slice(&input[0..33]).map_err(InvalidHelloMsg::InvalidIdentity)?;

        let mut room_id = [0u8; 32];
        room_id.copy_from_slice(&input[33..33 + 32]);

        let signature = &input[33 + 32..];
        let signature =
            Signature::from_compact(&signature).map_err(InvalidHelloMsg::InvalidSignature)?;

        let message_hash = Sha256::digest(&room_id);
        let message_hash = secp256k1::Message::from_slice(&message_hash)
            .expect("sha256 output is a valid message");

        SECP256K1
            .verify(&message_hash, &signature, &identity)
            .map_err(InvalidHelloMsg::InvalidSignature)?;

        Ok(HelloMsg {
            identity,
            room_id,
            signature,
        })
    }

    fn to_bytes(&self) -> Self::BytesArray {
        let mut msg = [0u8; HelloMsg::SIZE];

        msg[0..33].copy_from_slice(&self.identity.serialize());
        msg[33..33 + 32].copy_from_slice(&self.room_id);
        msg[33 + 32..].copy_from_slice(&self.signature.serialize_compact());

        msg
    }
}

#[derive(Debug, Error)]
pub enum InvalidHelloMsg {
    #[error("party identity (public key) is invalid")]
    InvalidIdentity(#[source] secp256k1::Error),
    #[error("invalid signature")]
    InvalidSignature(#[source] secp256k1::Error),
}
