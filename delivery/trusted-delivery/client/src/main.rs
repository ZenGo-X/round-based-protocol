use reqwest::{Client, Url};

use digest::Digest;
use trusted_delivery_core::auth::AuthReq;
use trusted_delivery_core::auth::SerializableChallenge;
use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::*;
use trusted_delivery_core::publish_msg::{Header, MessageDestination, PublishMessageHeader};

#[tokio::main]
async fn main() {
    match std::env::args().nth(1).unwrap().as_str() {
        "read" => read::<DefaultSuite>().await,
        "write" => write::<DefaultSuite>().await,
        _ => panic!(),
    }
}

const ROOM_ID: [u8; 32] = *b"1234567890abcdef1234567890abcdef";

async fn read<C: CryptoSuite>() {
    let sk = C::SigningKey::generate();
    let pk = sk.verification_key();

    let client = Client::builder().build().unwrap();
    let base_url = Url::parse("http://localhost:8000/").unwrap();

    // Get challenge
    let challenge: SerializableChallenge = client
        .get(base_url.join("/auth/challenge").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("Challenge: {:?}", challenge);

    // Sign challenge
    let signature = C::Digest::new()
        .chain(b"AUTH-CHALLENGE-RESPONSE")
        .chain(challenge.as_bytes())
        .sign_message(&sk);

    // Auth
    let req = AuthReq::<C> {
        public_key: pk.clone(),
        challenge,
        response: signature,
    };
    let response: Result<(), String> = client
        .post(base_url.join("/auth").unwrap())
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("AuthResponse: {:?}", response);

    // Subscribe
    let mut response = client
        .get(
            base_url
                .join(&format!(
                    "/room/{room}/subscribe",
                    room = hex::encode(ROOM_ID)
                ))
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    println!("Subscribed: {:?}", response.status());
    loop {
        let chunk = match response.chunk().await.unwrap() {
            Some(c) => c,
            None => {
                println!("No more data");
                return;
            }
        };
        println!("Recv chunk: {}", hex::encode(chunk));
    }
}

async fn write<C: CryptoSuite>() {
    let sk = C::SigningKey::generate();
    let pk = sk.verification_key();

    let client = Client::builder().build().unwrap();
    let base_url = Url::parse("http://localhost:8000/").unwrap();

    // Get challenge
    let challenge: SerializableChallenge = client
        .get(base_url.join("/auth/challenge").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("Challenge: {:?}", challenge);

    // Sign challenge
    let signature = C::Digest::new()
        .chain(b"AUTH-CHALLENGE-RESPONSE")
        .chain(challenge.as_bytes())
        .sign_message(&sk);

    // Auth
    let req = AuthReq::<C> {
        public_key: pk.clone(),
        challenge,
        response: signature,
    };
    let response: Result<(), String> = client
        .post(base_url.join("/auth").unwrap())
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("AuthResponse: {:?}", response);

    for i in 0..10u128 {
        let data = i.to_be_bytes();
        println!("Data: {}", hex::encode(data));

        let header = PublishMessageHeader::<C>::new(
            &sk,
            MessageDestination::AllParties {
                sequence_number: i.try_into().unwrap(),
            },
            &data,
        );

        let mut msg = header.to_bytes().to_vec();
        msg.extend_from_slice(&data);
        println!("Sending: {}", hex::encode(&msg));

        let response = client
            .post(
                base_url
                    .join(&format!("/room/{room}/send", room = hex::encode(ROOM_ID)))
                    .unwrap(),
            )
            .body(msg)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        println!("Result: {:?}", response);
    }
}
