use generic_array::GenericArray;
use sha2::Digest;
use typenum::{Unsigned, U16, U32};

use thiserror::Error;

use crate::crypto::{CryptoSuite, DigestExt, Serializable, SigningKey};

use super::FixedSizeMessage;
use crate::generic_array_ext::Sum;

pub type RoomId = [u8; 32];
pub type Nonce = [u8; 16];

pub struct HelloMsg<C: CryptoSuite> {
    pub identity: C::VerificationKey,
    pub room_id: RoomId,
    pub nonce: Nonce,
    pub signature: C::Signature,
}

impl<C: CryptoSuite> HelloMsg<C> {
    pub fn new(identity_key: &C::SigningKey, room_id: RoomId, nonce: Nonce) -> Self {
        let signature = C::Digest::new()
            .chain(&room_id)
            .chain(&nonce)
            .sign_message(identity_key);

        Self {
            identity: identity_key.verification_key(),
            room_id,
            nonce,
            signature,
        }
    }
}

impl<C: CryptoSuite> FixedSizeMessage for HelloMsg<C> {
    type Size = Sum![
        C::VerificationKeySize, // identity
        U32,                    // room_id
        U16,                    // nonce
        C::SignatureSize,       // signature
    ];
    type ParseError = InvalidHelloMsg;

    fn parse(input: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
        let identity_size = C::VerificationKeySize::to_usize();
        let room_size = 32;
        let nonce_size = 16;

        let identity = C::VerificationKey::from_bytes(&input[0..identity_size])
            .map_err(|_| InvalidHelloMsg::InvalidIdentity)?;

        let mut room_id = [0u8; 32];
        room_id.copy_from_slice(&input[identity_size..identity_size + room_size]);

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(
            &input[identity_size + room_size..identity_size + room_size + nonce_size],
        );

        let signature = C::Signature::from_bytes(&input[identity_size + room_size + nonce_size..])
            .map_err(|_| InvalidHelloMsg::InvalidSignature)?;

        C::Digest::new()
            .chain(&room_id)
            .chain(&nonce)
            .verify_signature(&identity, &signature)
            .map_err(|_| InvalidHelloMsg::InvalidSignature)?;

        Ok(HelloMsg {
            identity,
            room_id,
            nonce,
            signature,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let identity_size = C::VerificationKeySize::to_usize();
        let room_size = 32;
        let nonce_size = 16;

        let mut msg = GenericArray::<u8, Self::Size>::default();

        msg[0..identity_size].copy_from_slice(&self.identity.to_bytes());
        msg[identity_size..identity_size + room_size].copy_from_slice(&self.room_id);
        msg[identity_size + room_size..identity_size + room_size + nonce_size]
            .copy_from_slice(&self.nonce);
        msg[identity_size + room_size + nonce_size..].copy_from_slice(&self.signature.to_bytes());

        msg
    }
}

#[derive(Debug, Error)]
pub enum InvalidHelloMsg {
    #[error("party identity (public key) is invalid")]
    InvalidIdentity,
    #[error("invalid signature")]
    InvalidSignature,
}
