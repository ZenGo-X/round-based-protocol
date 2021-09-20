use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{self, AsyncRead, AsyncWrite};

use secp256k1::{PublicKey, SecretKey, SECP256K1};
use tokio_rustls::{client::TlsStream, Connect as TlsConnect, TlsConnector};

use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::messages::{HelloMsg, RoomId, SendFixed};
use crate::delivery::utils::tls::ClientTlsConfig;

pub struct Connector {
    tls_connector: TlsConnector,
    identity_key: SecretKey,
    identity: PublicKey,
}

pub struct Connect<P, IO> {
    identity_key: SecretKey,
    identity: PublicKey,
    parties: P,
    room_id: RoomId,
    state: ConnectionState<IO>,
}

enum ConnectionState<IO> {
    Handshake(TlsConnect<IO>),
    SendHello(SendFixed<HelloMsg, TlsStream<IO>>),
    Connected(TlsStream<IO>),
    Gone,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct MalformedListOfParties(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("list of parties doesn't include identity of local party")]
    DoesntIncludeIdentityOfLocalParty,
    #[error("list of parties consist of {n} identity, at least 2 are required")]
    TooFewParties { n: u16 },
}

impl Connector {
    pub fn new(tls_config: &ClientTlsConfig, identity_key: SecretKey) -> Self {
        Self::with_connector(
            TlsConnector::from(tls_config.to_rustls_config()),
            identity_key,
        )
    }

    pub fn with_connector(tls_connector: TlsConnector, identity_key: SecretKey) -> Self {
        Self {
            tls_connector,
            identity: PublicKey::from_secret_key(&SECP256K1, &identity_key),
            identity_key,
        }
    }

    pub fn connect<P, IO>(
        &self,
        room_id: RoomId,
        parties: P,
        domain: webpki::DNSNameRef,
        stream: IO,
    ) -> Result<Connect<P, IO>, MalformedListOfParties>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        P: IdentityResolver,
    {
        if parties.lookup_party_index(&self.identity).is_none() {
            return Err(Reason::DoesntIncludeIdentityOfLocalParty.into());
        }
        if parties.number_of_parties() < 2 {
            return Err(Reason::TooFewParties { n: 1 }.into());
        }

        Ok(Connect {
            identity_key: self.identity_key,
            identity: self.identity,
            room_id,
            parties,
            state: ConnectionState::Handshake(self.tls_connector.connect(domain, stream)),
        })
    }
}

impl<P, IO> Future for Connect<P, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    P: IdentityResolver + Unpin,
{
    type Output = io::Result<ConnectedClient<P, IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let this = &mut *self;
            match &mut this.state {
                ConnectionState::Handshake(handshake) => {
                    let stream = ready!(Pin::new(handshake).poll(cx))?;
                    this.state = ConnectionState::SendHello(SendFixed::initiate(
                        HelloMsg::new(&this.identity_key, this.room_id),
                        stream,
                    ));
                }
                ConnectionState::SendHello(sending) => {
                    ready!(Pin::new(sending).poll(cx))?;
                    this.state = ConnectionState::Connected(
                        this.state.take().unwrap_send_hello().into_inner(),
                    );
                }
                ConnectionState::Connected(_stream) => {
                    return Poll::Ready(Ok(ConnectedClient {
                        stream: this.state.take().unwrap_connected(),
                        identity_key: this.identity_key,
                        parties: this.parties.clone(),
                    }))
                }
                ConnectionState::Gone => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "poll after complete",
                    )))
                }
            }
        }
    }
}

impl<IO> ConnectionState<IO> {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Gone)
    }
    pub fn unwrap_send_hello(self) -> SendFixed<HelloMsg, TlsStream<IO>> {
        match self {
            Self::SendHello(h) => h,
            _ => panic!("expected SendHello"),
        }
    }
    pub fn unwrap_connected(self) -> TlsStream<IO> {
        match self {
            Self::Connected(s) => s,
            _ => panic!("expected Connected"),
        }
    }
}

pub struct ConnectedClient<P, IO> {
    stream: TlsStream<IO>,
    identity_key: SecretKey,
    parties: P,
}
