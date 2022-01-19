mod challenge;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use trusted_delivery_core::crypto::{self, CryptoSuite};

use crate::db::Db;

pub use self::challenge::*;

pub struct ServerState<C: CryptoSuite> {
    db: Db<C>,
    challenges: Mutex<HashSet<Challenge<C>>>,
}

impl<C: CryptoSuite> ServerState<C> {
    pub async fn get_challenge(&self) -> SerializableChallenge {
        let mut challenges = self.challenges.lock().await;

        let challenge = loop {
            let challenge = Challenge::<C>::generate();
            let serializable_challenge = challenge.to_serializable();
            if challenges.insert(challenge) {
                break serializable_challenge;
            }
        };

        challenge
    }

    pub async fn auth(&self, req: AuthReq<C>) -> Result<(), AuthError> {
        let challenge = {
            let mut challenges = self.challenges.lock().await;
            challenges
                .take(req.challenge.as_bytes())
                .ok_or(AuthError::UnknownChallenge)?
        };
        challenge
            .validate_response(&req.public_key, &req.response)
            .or(Err(AuthError::ChallengeResponseNotValid))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AuthReq<C: CryptoSuite> {
    #[serde(with = "crypto::serde")]
    public_key: C::VerificationKey,
    challenge: SerializableChallenge,
    #[serde(with = "crypto::serde")]
    response: C::Signature,
}

#[derive(Serialize, Deserialize)]
pub enum AuthError {
    ChallengeResponseNotValid,
    UnknownChallenge,
}
