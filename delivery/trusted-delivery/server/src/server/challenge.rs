use std::borrow::Borrow;
use std::marker::PhantomData;

use digest::Digest;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use trusted_delivery_core::crypto::{CryptoSuite, DigestExt};

#[derive(educe::Educe)]
#[educe(Hash, Eq, PartialEq, Debug)]
pub struct Challenge<C: CryptoSuite> {
    challenge: [u8; 32],
    _crypto_suite: PhantomData<C>,
}

impl<C: CryptoSuite> Challenge<C> {
    pub fn generate() -> Self {
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        Self {
            challenge,
            _crypto_suite: PhantomData,
        }
    }

    pub fn validate_response(
        self,
        public_key: &C::VerificationKey,
        response: &C::Signature,
    ) -> Result<(), InvalidResponse> {
        C::Digest::new()
            .chain("AUTH-CHALLENGE-RESPONSE")
            .chain(self.challenge)
            .verify_signature(public_key, response)
            .or(Err(InvalidResponse))
    }

    pub fn to_serializable(&self) -> SerializableChallenge {
        SerializableChallenge {
            challenge: self.challenge,
        }
    }
}

impl<C: CryptoSuite> Borrow<[u8]> for Challenge<C> {
    fn borrow(&self) -> &[u8] {
        &self.challenge
    }
}

#[derive(Debug, Error)]
#[error("authentication failed")]
pub struct InvalidResponse;

#[derive(Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SerializableChallenge {
    #[serde(with = "hex::serde")]
    challenge: [u8; 32],
}

impl SerializableChallenge {
    pub fn as_bytes(&self) -> &[u8] {
        &self.challenge
    }
}
