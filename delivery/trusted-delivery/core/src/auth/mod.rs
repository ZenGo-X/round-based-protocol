use serde::{Deserialize, Serialize};

pub use self::{challenge::*, server_key::*};
use crate::crypto::{self, CryptoSuite};

mod challenge;
mod server_key;

pub const WITNESS_HEADER_NAME: &str = "Auth-Witness";

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
pub struct AuthResp<C: CryptoSuite> {
    #[serde(with = "hex::serde")]
    pub witness: Witness<C>,
}
