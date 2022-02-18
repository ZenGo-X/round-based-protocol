use anyhow::Context;
use std::iter;

use futures::future;
use hex_literal::hex;
use rand::rngs::OsRng;

use random_generation_protocol::protocol_of_random_generation;
use round_based::delivery::trusted_delivery::crypto::{default_suite::DefaultSuite, *};
use round_based::delivery::trusted_delivery::{ApiClient, Delivery, Group, HttpClient, SortedList};
use round_based::MpcParty;
use trusted_delivery_server::dev::TestServer;

const ROOM_ID: [u8; 32] = hex!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

#[tokio::test]
async fn generate_randomness() {
    generate_randomness_generic::<DefaultSuite>().await
}

async fn generate_randomness_generic<C: CryptoSuite>() {
    // Trusted Delivery server is working in background
    let server = TestServer::launch().await;
    let server_address = server.address();

    // 10 parties are willing to generate randomness communicating through Trusted Delivery server
    let n = 10_u16;
    let secret_keys: Vec<C::SigningKey> = iter::repeat_with(C::SigningKey::generate)
        .take(usize::from(n))
        .collect();
    let public_keys: Vec<C::VerificationKey> = secret_keys
        .iter()
        .map(C::SigningKey::verification_key)
        .collect();
    let parties_list = SortedList::from(public_keys);

    let mut running = vec![];
    for sk in secret_keys {
        let group = Group {
            id: ROOM_ID,
            parties: parties_list.clone(),
        };

        running.push(run_party::<C>(server_address.clone(), group, sk))
    }

    let outputs = future::try_join_all(running)
        .await
        .expect("protocol failed");

    // Check that every party outputed the same randomness
    for output in &outputs {
        assert_eq!(*output, outputs[0]);
    }

    println!("Protocol output: {}", hex::encode(&outputs[0]));
}

async fn run_party<C: CryptoSuite>(
    server_address: url::Url,
    group: Group<C>,
    secret_key: C::SigningKey,
) -> anyhow::Result<[u8; 32]> {
    let http_client = HttpClient::new();
    let api_client = ApiClient::new(http_client, server_address.clone())
        .auth::<C>(secret_key)
        .await
        .context("authentication failed")?;

    let delivery = Delivery::connect(api_client, group)
        .await
        .context("connect error")?;
    let i = delivery.party_index();
    let n = delivery.parties_number();
    let party = MpcParty::connected(delivery);

    protocol_of_random_generation(party, i, n, OsRng)
        .await
        .context("run the protocol")
}
