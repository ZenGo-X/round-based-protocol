use std::collections::HashSet;

use generic_array::GenericArray;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::serde::json::Json;

use rocket::request::{self, FromRequest};
use rocket::{Request, State};
use tokio::sync::Mutex;

use trusted_delivery_core::challenge::{Challenge, SerializableChallenge};
use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::{CryptoSuite, Serializable};
use trusted_delivery_core::messages::{AuthError, AuthReq};

const AUTH_COOKIE: &str = "auth";

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
    cookies: &CookieJar<'_>,
    challenges: &State<Challenges<DefaultSuite>>,
    auth_req: Json<AuthReq<DefaultSuite>>,
) -> Json<Result<(), AuthError>> {
    if let Err(e) = auth_private(&challenges, &auth_req.0).await {
        return Json(Err(e));
    }
    cookies.add_private(Cookie::new(
        AUTH_COOKIE,
        hex::encode(auth_req.public_key.to_bytes()),
    ));
    Json(Ok(()))
}

async fn auth_private<C: CryptoSuite>(
    challenges: &Challenges<C>,
    auth_req: &AuthReq<C>,
) -> Result<(), AuthError> {
    let challenge = {
        let mut challenges = challenges.0.lock().await;
        challenges
            .take(auth_req.challenge.as_bytes())
            .ok_or(AuthError::UnknownChallenge)?
    };
    challenge
        .validate_response(&auth_req.public_key, &auth_req.response)
        .or(Err(AuthError::ChallengeResponseNotValid))
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
        let cookies = req.cookies();
        let public_key_hex = match cookies.get_private(AUTH_COOKIE) {
            Some(pk) => pk,
            None => return request::Outcome::Failure((Status::Forbidden, NotAuthenticated)),
        };

        let mut public_key_bytes = GenericArray::<u8, C::VerificationKeySize>::default();
        if hex::decode_to_slice(public_key_hex.value(), &mut public_key_bytes).is_err() {
            return request::Outcome::Failure((Status::Forbidden, NotAuthenticated));
        }

        let public_key = match C::VerificationKey::from_bytes(&public_key_bytes) {
            Ok(pk) => pk,
            Err(_) => return request::Outcome::Failure((Status::Forbidden, NotAuthenticated)),
        };

        request::Outcome::Success(Self { public_key })
    }
}
