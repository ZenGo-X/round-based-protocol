use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_rustls::{client::TlsStream, Connect as TlsConnect, TlsConnector};

use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::delivery::utils::tls::ClientTlsConfig;

use super::message::HELLO_MSG_LEN;
use crate::delivery::trusted_delivery::message::HelloMsg;

pub struct Connector {
    tls_connector: TlsConnector,
    identity_key: SecretKey,
}

pub struct Connect<IO> {
    handshake: TlsHandshake<IO>,
    identity_key: SecretKey,
    hello_msg: [u8; HELLO_MSG_LEN],
    sent_bytes: usize,
}

pub enum TlsHandshake<IO> {
    Empty,
    InProgress(TlsConnect<IO>),
    Completed(TlsStream<IO>),
}

impl Connector {
    pub fn new(tls_config: &ClientTlsConfig, identity_key: SecretKey) -> Self {
        Self {
            tls_connector: TlsConnector::from(tls_config.to_rustls_config()),
            identity_key,
        }
    }

    pub fn with_connector(tls_connector: TlsConnector, identity_key: SecretKey) -> Self {
        Self {
            tls_connector,
            identity_key,
        }
    }

    pub fn connect<IO>(
        &self,
        domain: webpki::DNSNameRef,
        stream: IO,
        room_id: [u8; 32],
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let hashed_msg = Sha256::digest(&room_id);
        let hashed_msg = Message::from_slice(&hashed_msg)
            .expect("message has appropriate length, from_slice must never fail");

        let signature = SECP256K1.sign(&hashed_msg, &self.identity_key);
        let hello_msg = HelloMsg {
            public_key: PublicKey::from_secret_key(&SECP256K1, &self.identity_key),
            room_id,
            signature,
        };

        Connect {
            handshake: TlsHandshake::InProgress(self.tls_connector.connect(domain, stream)),
            identity_key: self.identity_key,
            hello_msg: hello_msg.to_bytes(),
            sent_bytes: 0,
        }
    }
}

impl<IO> Connect<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
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

impl<IO> Future for Connect<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<ConnectedClient<IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self {
            handshake,
            hello_msg,
            sent_bytes,
            ..
        } = &mut *self;
        let stream = ready!(Self::poll_handshake(handshake, cx))?;
        while *sent_bytes < HELLO_MSG_LEN {
            let bytes_written =
                ready!(Pin::new(&mut *stream).poll_write(cx, &hello_msg[*sent_bytes..]))?;
            if bytes_written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            *sent_bytes += bytes_written;
        }
        ready!(Pin::new(stream).poll_flush(cx))?;

        Poll::Ready(Ok(ConnectedClient {
            stream: self
                .handshake
                .take_completed()
                .ok()
                .expect("guaranteed to be completed"),
            identity_key: self.identity_key,
        }))
    }
}

pub struct ConnectedClient<IO> {
    stream: TlsStream<IO>,
    identity_key: SecretKey,
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
