use std::net::SocketAddr;

use anyhow::Context;
use rand::RngCore;
use tokio::net::TcpListener;

use random_generation_protocol::{protocol_of_random_generation, Msg};
use round_based::delivery::two_party::{TcpClientBuilder, TcpServer};
use round_based::MpcParty;

#[tokio::test]
async fn generate_randomness_between_two_parties_over_tcp() -> anyhow::Result<()> {
    let server_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind server")?;
    let server_addr = server_listener
        .local_addr()
        .context("retrieve server address")?;

    let server = tokio::spawn(server(server_listener, rand::rngs::OsRng));
    let client = tokio::spawn(client(server_addr, rand::rngs::OsRng));

    let server_randomness = server.await??;
    let client_randomness = client.await??;

    assert_eq!(server_randomness, client_randomness);
    Ok(())
}

async fn server<R: RngCore>(listener: TcpListener, rng: R) -> anyhow::Result<[u8; 32]> {
    let (delivery, _addr) = TcpServer::<Msg>::new(listener)
        .set_message_size_limit(50)
        .accept()
        .await
        .context("accept a client")?;
    let party = MpcParty::connect(delivery);
    protocol_of_random_generation(party, 0, 2, rng)
        .await
        .context("protocol didn't complete")
}

async fn client<R: RngCore>(server_addr: SocketAddr, rng: R) -> anyhow::Result<[u8; 32]> {
    let delivery = TcpClientBuilder::<Msg>::new()
        .set_message_size_limit(50)
        .connect(server_addr)
        .await
        .context("connect to the server")?;
    let party = MpcParty::connect(delivery);
    protocol_of_random_generation(party, 1, 2, rng)
        .await
        .context("protocol didn't complete")
}
