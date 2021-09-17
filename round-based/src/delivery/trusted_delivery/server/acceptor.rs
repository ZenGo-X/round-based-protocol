use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream as _};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_rustls::{server::TlsStream, Accept as TlsAccept, TlsAcceptor};

use secp256k1::PublicKey;

use crate::delivery::trusted_delivery::messages::{HelloMsg, ReceiveFixed};
use crate::delivery::utils::tls::ServerTlsConfig;

pub struct Acceptor {
    tls_acceptor: TlsAcceptor,
}

pub struct Accept<IO>(State<IO>);

enum State<IO> {
    Handshake(TlsAccept<IO>),
    ReadHello(ReceiveFixed<HelloMsg, TlsStream<IO>>),
    Accepted(Stream<IO>),
    Gone,
}

pub struct Stream<IO> {
    stream: TlsStream<IO>,
    client_identity: PublicKey,
    room_id: [u8; 32],
}

impl Acceptor {
    pub fn with_config(config: &ServerTlsConfig) -> Self {
        Self {
            tls_acceptor: TlsAcceptor::from(config.to_rustls_config()),
        }
    }

    pub fn with_tls_acceptor(tls_acceptor: TlsAcceptor) -> Self {
        Self { tls_acceptor }
    }

    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Accept(State::Handshake(self.tls_acceptor.accept(stream)))
    }
}

impl<IO> Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn connected(stream: TlsStream<IO>) -> Self {
        Self(State::ReadHello(ReceiveFixed::new(stream)))
    }
}

impl<IO> Future for Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<Stream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.0 {
                State::Handshake(handshake) => {
                    let stream = ready!(Pin::new(handshake).poll(cx))?;
                    self.0 = State::ReadHello(ReceiveFixed::new(stream));
                }
                State::ReadHello(reader) => {
                    let hello_msg = ready!(Pin::new(reader).poll_next(cx))
                        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))??;
                    self.0 = State::Accepted(Stream {
                        stream: self.0.take().unwrap_read_hello().into_inner(),
                        client_identity: hello_msg.identity,
                        room_id: hello_msg.room_id,
                    })
                }
                State::Accepted(_stream) => {
                    return Poll::Ready(Ok(self.0.take().unwrap_accepted()))
                }
                State::Gone => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "poll after complete",
                    )))
                }
            }
        }
    }
}

impl<IO> Stream<IO> {
    pub fn room_id(&self) -> [u8; 32] {
        self.room_id
    }

    pub fn client_identity(&self) -> PublicKey {
        self.client_identity
    }

    pub fn into_inner(self) -> TlsStream<IO> {
        self.stream
    }
}

impl<IO> State<IO> {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Gone)
    }
    pub fn unwrap_read_hello(self) -> ReceiveFixed<HelloMsg, TlsStream<IO>> {
        match self {
            State::ReadHello(h) => h,
            _ => panic!("expected ReadHello"),
        }
    }
    pub fn unwrap_accepted(self) -> Stream<IO> {
        match self {
            State::Accepted(s) => s,
            _ => panic!("expected Accepted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net;
    use tokio_rustls::TlsConnector;

    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1::{PublicKey, SecretKey, SECP256K1};

    use crate::delivery::trusted_delivery::messages::{FixedSizeMsg, HelloMsg};
    use crate::delivery::utils::tls::mock::MockTls;

    use super::Acceptor;

    #[tokio::test]
    async fn server_accepts_connection() {
        let mock_tls = MockTls::generate();
        let server_config = mock_tls.issue_server_cert(vec!["my-server.local".to_string()]);
        let client_config = mock_tls.issue_client_cert(vec!["party0.local".to_string()]);

        let server = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client_sk = loop {
            let mut client_sk = [0u8; 32];
            OsRng.fill_bytes(&mut client_sk);
            if let Ok(sk) = SecretKey::from_slice(&client_sk) {
                break sk;
            }
        };
        let client_pk = PublicKey::from_secret_key(&SECP256K1, &client_sk);
        let mut room_id = [0u8; 32];
        OsRng.fill_bytes(&mut room_id);

        let client = tokio::spawn(async move {
            let conn = net::TcpStream::connect(server_addr).await.unwrap();
            let mut tls_conn = TlsConnector::from(client_config.to_rustls_config())
                .connect(
                    webpki::DNSNameRef::try_from_ascii(b"my-server.local").unwrap(),
                    conn,
                )
                .await
                .unwrap();

            let msg = HelloMsg::new(&client_sk, room_id);
            tls_conn.write_all(&msg.to_bytes()).await.unwrap();
        });

        let (conn, _) = server.accept().await.unwrap();
        let conn = Acceptor::with_config(&server_config)
            .accept(conn)
            .await
            .unwrap();
        client.await.unwrap();

        assert_eq!(conn.client_identity(), client_pk);
        assert_eq!(conn.room_id(), room_id);
    }

    #[tokio::test]
    async fn server_doesnt_accept_connection_with_bad_signature() {
        let mock_tls = MockTls::generate();
        let server_config = mock_tls.issue_server_cert(vec!["my-server.local".to_string()]);
        let client_config = mock_tls.issue_client_cert(vec!["party0.local".to_string()]);

        let server = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client_sk = loop {
            let mut client_sk = [0u8; 32];
            OsRng.fill_bytes(&mut client_sk);
            if let Ok(sk) = SecretKey::from_slice(&client_sk) {
                break sk;
            }
        };
        let client_pk = PublicKey::from_secret_key(&SECP256K1, &client_sk);
        let mut room_id = [0u8; 32];
        OsRng.fill_bytes(&mut room_id);

        let client = tokio::spawn(async move {
            let conn = net::TcpStream::connect(server_addr).await.unwrap();
            let mut tls_conn = TlsConnector::from(client_config.to_rustls_config())
                .connect(
                    webpki::DNSNameRef::try_from_ascii(b"my-server.local").unwrap(),
                    conn,
                )
                .await
                .unwrap();

            let hashed_msg = [6u8; 32];
            let hashed_msg = secp256k1::Message::from_slice(&hashed_msg).unwrap();
            let signature = SECP256K1.sign(&hashed_msg, &client_sk);

            let msg = HelloMsg {
                identity: client_pk,
                room_id,
                signature,
            };
            tls_conn.write_all(&msg.to_bytes()).await.unwrap();
        });

        let (conn, _) = server.accept().await.unwrap();
        let result = Acceptor::with_config(&server_config).accept(conn).await;
        client.await.unwrap();

        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        } else {
            panic!("expected error")
        }
    }
}
