use sha2::Digest;

use thiserror::Error;

use crate::delivery::trusted_delivery::client::insecure::crypto::{
    CryptoSuite, DigestExt, Serializable, SigningKey,
};

use super::FixedSizeMsg;
use crate::delivery::trusted_delivery::generic_array_ext::Sum;
use generic_array::typenum::{Unsigned, U32};
use generic_array::GenericArray;

pub type RoomId = [u8; 32];

pub struct HelloMsg<C: CryptoSuite> {
    pub identity: C::VerificationKey,
    pub room_id: RoomId,
    pub signature: C::Signature,
}

impl<C: CryptoSuite> HelloMsg<C> {
    pub fn new(identity_key: &C::SigningKey, room_id: RoomId) -> Self {
        let signature = C::Digest::new().chain(&room_id).sign_message(identity_key);

        Self {
            identity: identity_key.verification_key(),
            room_id,
            signature,
        }
    }
}

impl<C: CryptoSuite> FixedSizeMsg for HelloMsg<C> {
    type Size = Sum![
        C::VerificationKeySize, // identity
        U32,                    // room_id
        C::SignatureSize,       // signature
    ];
    type ParseError = InvalidHelloMsg;

    fn parse(input: &GenericArray<u8, Self::Size>) -> Result<Self, Self::ParseError> {
        let identity_size = C::VerificationKeySize::to_usize();
        let room_size = 32;

        let identity = C::VerificationKey::from_bytes(&input[0..identity_size])
            .map_err(|_| InvalidHelloMsg::InvalidIdentity)?;

        let mut room_id = [0u8; 32];
        room_id.copy_from_slice(&input[identity_size..identity_size + room_size]);

        let signature = C::Signature::from_bytes(&input[identity_size + room_size..])
            .map_err(|_| InvalidHelloMsg::InvalidSignature)?;

        C::Digest::new()
            .chain(&room_id)
            .verify_signature(&identity, &signature)
            .map_err(|_| InvalidHelloMsg::InvalidSignature)?;

        Ok(HelloMsg {
            identity,
            room_id,
            signature,
        })
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let identity_size = C::VerificationKeySize::to_usize();
        let room_size = 32;

        let mut msg = GenericArray::<u8, Self::Size>::default();

        msg[0..identity_size].copy_from_slice(&self.identity.to_bytes());
        msg[identity_size..identity_size + room_size].copy_from_slice(&self.room_id);
        msg[identity_size + room_size..].copy_from_slice(&self.signature.to_bytes());

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
