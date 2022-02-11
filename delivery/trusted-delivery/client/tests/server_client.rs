use std::iter;

use trusted_delivery::{ApiClient, JoinedRoom, Subscription};
use trusted_delivery_core::crypto::default_suite::DefaultSuite;
use trusted_delivery_core::crypto::*;
use trusted_delivery_core::publish_msg::Header;
use trusted_delivery_core::RoomId;
use trusted_delivery_server::dev::TestServer;

const TEST_ROOM: RoomId = *b"0123456789abcdef0123456789abcdef";
const ANOTHER_ROOM: RoomId = *b"abcdabcdabcdabcdabcdabcdabcdabcd";

#[tokio::test]
async fn message_is_broadcasted_to_everyone() {
    message_is_broadcasted_to_everyone_generic::<DefaultSuite>().await
}

async fn message_is_broadcasted_to_everyone_generic<C: CryptoSuite>() {
    let server = TestServer::launch().await;
    let address = server.address();

    let mut group = MockedParties::<C>::generate(&address, TEST_ROOM, 3).await;

    let data1 = b"hello guys";
    group.client[0].send(None, data1).await.unwrap();

    let data2 = b"wussap";
    group.client[0].send(None, data2).await.unwrap();

    for (i, subscription) in group.subscription.iter_mut().enumerate() {
        let (header, received) = subscription.next().await.unwrap().unwrap();

        assert_eq!(header.sender, group.pk[0]);
        assert_eq!(header.is_broadcast, true);
        assert_eq!(header.sequence_number, Some(0));
        header.verify(&group.pk[i], received).unwrap();

        assert_eq!(received, data1);
    }

    for (i, subscription) in group.subscription.iter_mut().enumerate() {
        let (header, received) = subscription.next().await.unwrap().unwrap();

        assert_eq!(header.sender, group.pk[0]);
        assert_eq!(header.is_broadcast, true);
        assert_eq!(header.sequence_number, Some(1));
        header.verify(&group.pk[i], received).unwrap();

        assert_eq!(received, data2);
    }
}

#[tokio::test]
async fn p2p_message_is_sent_only_to_destination() {
    p2p_message_is_sent_only_to_destination_generic::<DefaultSuite>().await;
}

async fn p2p_message_is_sent_only_to_destination_generic<C: CryptoSuite>() {
    let server = TestServer::launch().await;
    let address = server.address();

    let mut group = MockedParties::<C>::generate(&address, TEST_ROOM, 3).await;

    let direct_message = b"this is a direct message that'll be received only by destination";
    group.client[0]
        .send(Some(group.pk[1].clone()), direct_message)
        .await
        .unwrap();

    let public_message = b"this message is seen by everyone";
    group.client[0].send(None, public_message).await.unwrap();

    for (i, subscription_i) in group.subscription.iter_mut().enumerate() {
        if i == 1 {
            let (header, msg) = subscription_i.next().await.unwrap().unwrap();

            assert_eq!(header.sender, group.pk[0]);
            assert_eq!(header.is_broadcast, false);
            assert_eq!(header.sequence_number, None);
            header.verify(&group.pk[1], direct_message).unwrap();

            assert_eq!(msg, direct_message);
        }

        let (header, msg) = subscription_i.next().await.unwrap().unwrap();

        assert_eq!(header.sender, group.pk[0]);
        assert_eq!(header.is_broadcast, true);
        assert_eq!(header.sequence_number, Some(0));
        header.verify(&group.pk[i], public_message).unwrap();

        assert_eq!(msg, public_message);
    }
}

#[tokio::test]
async fn message_appears_only_in_its_room() {
    message_appears_only_in_its_room_generic::<DefaultSuite>().await
}

async fn message_appears_only_in_its_room_generic<C: CryptoSuite>() {
    let server = TestServer::launch().await;
    let address = server.address();

    let mut group1 = MockedParties::<C>::generate(&address, TEST_ROOM, 3).await;
    let mut group2 = MockedParties::<C>::generate(&address, ANOTHER_ROOM, 2).await;

    let msg1 = b"some message";
    group1.client[0].send(None, msg1).await.unwrap();

    let msg2 = b"another message";
    group2.client[0].send(None, msg2).await.unwrap();

    for (pk, subscription) in group1.pk.iter().zip(&mut group1.subscription) {
        let (header, msg) = subscription.next().await.unwrap().unwrap();

        assert_eq!(header.sender, group1.pk[0]);
        assert_eq!(header.is_broadcast, true);
        assert_eq!(header.sequence_number, Some(0));
        header.verify(pk, msg).unwrap();

        assert_eq!(msg, msg1);
    }

    for (pk, subscription) in group2.pk.iter().zip(&mut group2.subscription) {
        let (header, msg) = subscription.next().await.unwrap().unwrap();

        assert_eq!(header.sender, group2.pk[0]);
        assert_eq!(header.is_broadcast, true);
        assert_eq!(header.sequence_number, Some(0));
        header.verify(pk, msg).unwrap();

        assert_eq!(msg, msg2)
    }
}

pub struct MockedParties<C: CryptoSuite> {
    pub sk: Vec<C::SigningKey>,
    pub pk: Vec<C::VerificationKey>,
    pub subscription: Vec<Subscription<C>>,
    pub client: Vec<ApiClient<JoinedRoom<C>>>,
}

impl<C: CryptoSuite> MockedParties<C> {
    pub async fn generate(base_url: &reqwest::Url, room_id: RoomId, n: usize) -> Self {
        let sk: Vec<C::SigningKey> = iter::repeat_with(C::SigningKey::generate).take(n).collect();
        let pk = sk.iter().map(C::SigningKey::verification_key).collect();

        let mut client = vec![];
        let mut subscription = vec![];
        for sk_i in &sk {
            let http_client = reqwest::Client::new();

            let client_i = ApiClient::new(http_client, base_url.clone());
            let client_i = client_i
                .auth::<C>(sk_i.clone())
                .await
                .unwrap()
                .join_room(room_id);

            subscription.push(client_i.subscribe().await.unwrap());
            client.push(client_i);
        }

        Self {
            sk,
            pk,
            subscription,
            client,
        }
    }
}
