use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::ServerName;
use tokio::net::TcpListener;

use random_generation_protocol::{protocol_of_random_generation, Msg};
use round_based::delivery::two_party::{TlsClientBuilder, TlsServer};
use round_based::delivery::utils::mock_tls::MockTls;
use round_based::MpcParty;

#[tokio::test]
async fn generate_randomness_between_two_parties_over_tls_tcp() -> anyhow::Result<()> {
    let tls_config = MockTls::generate();

    let server_certificate = tls_config.issue_server_cert(vec!["example.com".to_string()]);
    let client_certificate = tls_config.issue_client_cert(vec!["john".to_string()]);

    let server_config = server_certificate.derive_server_config();
    let client_config = client_certificate.derive_client_config();

    let tcp_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind a server")?;
    let server_address = tcp_listener
        .local_addr()
        .context("retrieve server address")?;

    let server = tokio::spawn(server(tcp_listener, server_config, OsRng));
    let client = tokio::spawn(client(server_address, client_config, OsRng));

    let server_randomness = server.await??;
    let client_randomness = client.await??;

    assert_eq!(server_randomness, client_randomness);
    Ok(())
}

async fn server<R: RngCore>(
    tcp_listener: TcpListener,
    tls_config: rustls::ServerConfig,
    rng: R,
) -> anyhow::Result<[u8; 32]> {
    let (delivery, _addr) = TlsServer::<Msg>::new(tcp_listener, Arc::new(tls_config))
        .set_message_size_limit(50)
        .accept()
        .await
        .context("accept client")?;
    let party = MpcParty::connect(delivery);

    protocol_of_random_generation(party, 0, 2, rng)
        .await
        .context("protocol didn't complete")
}

async fn client<R: RngCore>(
    server_addr: SocketAddr,
    tls_config: rustls::ClientConfig,
    rng: R,
) -> anyhow::Result<[u8; 32]> {
    let delivery = TlsClientBuilder::<Msg>::with_rustls_config(Arc::new(tls_config))
        .set_message_size_limit(50)
        .connect(ServerName::try_from("example.com")?, server_addr)
        .await
        .context("connect to server")?;
    let party = MpcParty::connect(delivery);

    protocol_of_random_generation(party, 1, 2, rng)
        .await
        .context("protocol didn't complete")
}
