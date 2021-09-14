use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_rustls::{client::TlsStream, Connect as TlsConnect, TlsConnector};

use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::delivery::utils::tls::ClientTlsConfig;

use crate::delivery::trusted_delivery::message::{HelloMsg, HELLO_MSG_LEN};

type TlsHandshake<IO> =
    crate::delivery::trusted_delivery::tls_handshake::TlsHandshake<TlsConnect<IO>, TlsStream<IO>>;

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
        let stream = ready!(handshake.poll_handshake(cx))?;
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
