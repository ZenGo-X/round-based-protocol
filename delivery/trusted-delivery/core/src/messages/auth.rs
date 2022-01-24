use serde::{Deserialize, Serialize};

use crate::challenge::SerializableChallenge;
use crate::crypto::{self, CryptoSuite};

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AuthReq<C: CryptoSuite> {
    #[serde(with = "crypto::serde")]
    pub public_key: C::VerificationKey,
    pub challenge: SerializableChallenge,
    #[serde(with = "crypto::serde")]
    pub response: C::Signature,
}

#[derive(Serialize, Deserialize)]
pub enum AuthError {
    ChallengeResponseNotValid,
    UnknownChallenge,
}
