use std::sync::Arc;

use futures::future::join;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use delivery_core::utils::mock_tls::MockTls;

#[tokio::test]
async fn self_signed_certificates_are_valid() {
    let cfg = MockTls::generate();
    let server_cert = cfg.issue_server_cert(vec!["my-server.local".to_string()]);
    let client_cert = cfg.issue_client_cert(vec!["party0.local".to_string()]);
    let server_cfg = server_cert.derive_server_config();
    let client_cfg = client_cert.derive_client_config();

    let (server_conn, client_conn) = io::duplex(1024);
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let tls_connector = TlsConnector::from(Arc::new(client_cfg));
    let server_handshake = tls_acceptor.accept(server_conn);
    let client_handshake = tls_connector.connect(
        rustls::client::ServerName::try_from("my-server.local").unwrap(),
        client_conn,
    );

    let (server_result, client_result) = join(server_handshake, client_handshake).await;
    println!("Server result: {:?}", server_result);
    println!("Client result: {:?}", client_result);

    let mut server_conn = server_result.map(io::BufReader::new).unwrap();
    let mut client_conn = client_result.map(io::BufReader::new).unwrap();
    let (mut line1, mut line2) = (String::new(), String::new());

    server_conn.write_all(b"Hello, Client!\n").await.unwrap();
    client_conn.read_line(&mut line1).await.unwrap();
    client_conn.write_all(b"Hello, Server!\n").await.unwrap();
    server_conn.read_line(&mut line2).await.unwrap();

    assert_eq!(line1, "Hello, Client!\n");
    assert_eq!(line2, "Hello, Server!\n");
}
