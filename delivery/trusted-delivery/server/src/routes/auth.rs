use std::collections::HashSet;

use hex::FromHex;
use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::serde::json::Json;
use rocket::{Request, State};
use thiserror::Error;
use tokio::sync::Mutex;

use trusted_delivery_core::auth::{
    AuthReq, AuthResp, Challenge, SerializableChallenge, ServerKey, Witness, WITNESS_HEADER_NAME,
};
use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::CryptoSuite;

pub struct Challenges<C: CryptoSuite>(Mutex<HashSet<Challenge<C>>>);

impl<C: CryptoSuite> Challenges<C> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<C: CryptoSuite> Default for Challenges<C> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[rocket::get("/auth/challenge")]
pub async fn get_challenge(
    challenges: &State<Challenges<DefaultSuite>>,
) -> Json<SerializableChallenge> {
    Json(get_challenge_private(&challenges).await)
}

async fn get_challenge_private<C: CryptoSuite>(
    challenges: &Challenges<C>,
) -> SerializableChallenge {
    let mut challenges = challenges.0.lock().await;

    let challenge = loop {
        let challenge = Challenge::<C>::generate();
        let serializable_challenge = challenge.to_serializable();
        if challenges.insert(challenge) {
            break serializable_challenge;
        }
    };

    challenge
}

#[rocket::post("/auth", data = "<auth_req>")]
pub async fn auth(
    server_key: &State<ServerKey<DefaultSuite>>,
    challenges: &State<Challenges<DefaultSuite>>,
    auth_req: Json<AuthReq<DefaultSuite>>,
) -> (Status, Json<Result<AuthResp<DefaultSuite>, String>>) {
    match auth_private(&server_key, &challenges, &auth_req).await {
        Ok(witness) => (Status::Ok, Json(Ok(AuthResp { witness }))),
        Err(err) => (Status::BadRequest, Json(Err(err.to_string()))),
    }
}

async fn auth_private<C: CryptoSuite>(
    server_key: &ServerKey<C>,
    challenges: &Challenges<C>,
    auth_req: &AuthReq<C>,
) -> Result<Witness<C>, AuthError> {
    let challenge = {
        let mut challenges = challenges.0.lock().await;
        challenges
            .take(auth_req.challenge.as_bytes())
            .ok_or(AuthError::UnknownChallenge)?
    };
    server_key
        .attest(&auth_req.public_key, challenge, &auth_req.response)
        .or(Err(AuthError::ChallengeResponseNotValid))
}

#[derive(Debug, Error)]
enum AuthError {
    #[error("unknown challenge")]
    UnknownChallenge,
    #[error("challenge response is not valid")]
    ChallengeResponseNotValid,
}

pub struct Authenticated<C: CryptoSuite> {
    pub public_key: C::VerificationKey,
}

#[derive(Debug)]
pub struct NotAuthenticated;

#[rocket::async_trait]
impl<'r, C: CryptoSuite> FromRequest<'r> for Authenticated<C> {
    type Error = NotAuthenticated;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let witness = match req.headers().get_one(WITNESS_HEADER_NAME) {
            Some(witness) => witness,
            None => return request::Outcome::Failure((Status::Forbidden, NotAuthenticated)),
        };
        let witness = match Witness::<C>::from_hex(witness) {
            Ok(witness) => witness,
            Err(_not_hex) => {
                return request::Outcome::Failure((Status::Forbidden, NotAuthenticated))
            }
        };

        let server_key = match req.guard::<&State<ServerKey<C>>>().await {
            request::Outcome::Success(key) => key,
            _ => panic!("server key not found"),
        };

        let public_key = match server_key.verify(&witness) {
            Ok(public_key) => public_key,
            Err(_witness_not_valid) => {
                return request::Outcome::Failure((Status::Forbidden, NotAuthenticated))
            }
        };

        request::Outcome::Success(Authenticated { public_key })
    }
}
