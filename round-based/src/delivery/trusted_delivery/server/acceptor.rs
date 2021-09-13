use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{server::TlsStream, Accept as TlsAccept, TlsAcceptor};

use secp256k1::PublicKey;

use crate::delivery::trusted_delivery::message::{HelloMsg, HELLO_MSG_LEN};
use crate::delivery::utils::tls::ServerTlsConfig;

pub struct Acceptor {
    tls_acceptor: TlsAcceptor,
}

pub struct Accept<IO> {
    tls_handshake: TlsHandshake<IO>,
    hello_msg: [u8; HELLO_MSG_LEN],
    hello_msg_received: usize,
}

enum TlsHandshake<IO> {
    Empty,
    InProgress(TlsAccept<IO>),
    Completed(TlsStream<IO>),
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
        Accept {
            tls_handshake: TlsHandshake::InProgress(self.tls_acceptor.accept(stream)),
            hello_msg: [0u8; HELLO_MSG_LEN],
            hello_msg_received: 0,
        }
    }
}

impl<IO> Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn connected(stream: TlsStream<IO>) -> Self {
        Self {
            tls_handshake: TlsHandshake::Completed(stream),
            hello_msg: [0u8; HELLO_MSG_LEN],
            hello_msg_received: 0,
        }
    }

    fn poll_handshake<'h>(
        handshake: &'h mut TlsHandshake<IO>,
        cx: &mut Context,
    ) -> Poll<io::Result<&'h mut TlsStream<IO>>> {
        match handshake {
            TlsHandshake::Empty => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "poll after complete",
            ))),
            TlsHandshake::Completed(stream) => Poll::Ready(Ok(stream)),
            TlsHandshake::InProgress(tls_handshake) => {
                let stream = ready!(Pin::new(tls_handshake).poll(cx))?;
                *handshake = TlsHandshake::Completed(stream);
                Poll::Ready(Ok(
                    handshake.expect_completed("tls handshake guaranteed to be completed")
                ))
            }
        }
    }
}

impl<IO> Future for Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<Stream<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self {
            tls_handshake,
            hello_msg,
            hello_msg_received,
        } = &mut *self;
        let stream = ready!(Self::poll_handshake(tls_handshake, cx))?;
        while *hello_msg_received < HELLO_MSG_LEN {
            let buffer = &mut hello_msg[*hello_msg_received..];
            let mut buffer = ReadBuf::new(buffer);
            ready!(Pin::new(&mut *stream).poll_read(cx, &mut buffer))?;
            *hello_msg_received += buffer.filled().len();
        }

        let hello_msg = HelloMsg::parse(&*hello_msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Poll::Ready(Ok(Stream {
            stream: self
                .tls_handshake
                .take_completed()
                .ok()
                .expect("guaranteed to be completed"),
            client_identity: hello_msg.public_key,
            room_id: hello_msg.room_id,
        }))
    }
}

impl<IO> TlsHandshake<IO> {
    pub fn take_completed(&mut self) -> Result<TlsStream<IO>, Self> {
        match std::mem::replace(self, TlsHandshake::Empty) {
            TlsHandshake::Completed(stream) => Ok(stream),
            state => Err(state),
        }
    }

    #[track_caller]
    pub fn expect_completed(&mut self, msg: &str) -> &mut TlsStream<IO> {
        match self {
            TlsHandshake::Completed(stream) => stream,
            TlsHandshake::InProgress(_) => panic!(
                "expected completed handshake, actually it's in progress: {}",
                msg
            ),
            TlsHandshake::Empty => {
                panic!("expected completed handshake, actually it's empty: {}", msg)
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

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net;
    use tokio_rustls::TlsConnector;

    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1::{PublicKey, SecretKey, SECP256K1};
    use sha2::{Digest, Sha256};

    use crate::delivery::trusted_delivery::message::HELLO_MSG_LEN;
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

            let hashed_msg = Sha256::digest(&room_id);
            let hashed_msg = secp256k1::Message::from_slice(hashed_msg.as_slice()).unwrap();
            let signature = SECP256K1.sign(&hashed_msg, &client_sk);

            let mut msg = [0u8; HELLO_MSG_LEN];
            msg[0..33].copy_from_slice(&client_pk.serialize());
            msg[33..33 + 32].copy_from_slice(&room_id);
            msg[33 + 32..].copy_from_slice(&signature.serialize_compact());
            tls_conn.write_all(&msg).await.unwrap();
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

            let mut msg = [0u8; HELLO_MSG_LEN];
            msg[0..33].copy_from_slice(&client_pk.serialize());
            msg[33..33 + 32].copy_from_slice(&room_id);
            msg[33 + 32..].copy_from_slice(&signature.serialize_compact());
            tls_conn.write_all(&msg).await.unwrap();
        });

        let (conn, _) = server.accept().await.unwrap();
        let result = Acceptor::with_config(&server_config).accept(conn).await;
        client.await.unwrap();

        assert!(result.is_err());
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => {
                println!("{}", e);
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
            }
        }
    }
}
