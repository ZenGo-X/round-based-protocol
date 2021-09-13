//! Two party delivery over TLS+TCP socket
//!
//! ## Example: Server
//! ```rust,no_run
//! use round_based::delivery::two_party::tls::{TlsServer, ServerTlsConfig};
//! use round_based::MpcParty;
//! # use serde::{Serialize, Deserialize};
//! # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[derive(Serialize, Deserialize, Clone, round_based::ProtocolMessage)] enum Msg {}
//! # async fn protocol_of_random_generation<R: rand::RngCore, M: round_based::Mpc<ProtocolMessage = Msg>>(party: M,i: u16,n: u16,mut rng: R) -> Result<[u8; 32], Box<dyn std::error::Error>> { todo!() }
//! # let (client_ca, cert, private_key) = unimplemented!();
//!
//! let config = ServerTlsConfig::builder()
//!     .set_clients_ca(&client_ca)?
//!     .set_private_key(cert, private_key)?
//!     .build();
//!
//! let mut server = TlsServer::<Msg>::bind("127.0.0.1:9090", &config).await?;
//! loop {
//!     let (client, _client_addr) = server.accept().await?;
//!     let party = MpcParty::connect(client);
//!
//!     // ... run mpc here, e.g.:
//!     let randomness = protocol_of_random_generation(party, 0, 2, rand::rngs::OsRng).await?;
//!     println!("Randomness: {}", hex::encode(randomness));
//! }
//! #
//! # Ok(()) }
//! ```
//!
//! ## Example: Client
//! ```rust,no_run
//! use round_based::delivery::two_party::tls::{TlsClientBuilder, ClientTlsConfig};
//! use round_based::MpcParty;
//! # use serde::{Serialize, Deserialize};
//! # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[derive(Serialize, Deserialize, Clone, round_based::ProtocolMessage)] enum Msg {}
//! # async fn protocol_of_random_generation<R: rand::RngCore, M: round_based::Mpc<ProtocolMessage = Msg>>(party: M,i: u16,n: u16,mut rng: R) -> Result<[u8; 32], Box<dyn std::error::Error>> { todo!() }
//! # let (server_ca, cert, private_key) = unimplemented!();
//!
//! let config = ClientTlsConfig::builder()
//!     .set_server_ca(&server_ca)?
//!     .set_private_key(cert, private_key)?
//!     .build();
//!
//! let conn = TlsClientBuilder::new()
//!     .connect::<Msg, _>(
//!         webpki::DNSNameRef::try_from_ascii(b"example.com")?,
//!         "example.com",
//!         &config,
//!     )
//!     .await?;
//! let party = MpcParty::connect(conn);
//!
//! // ... run mpc here, e.g.:
//! let randomness = protocol_of_random_generation(party, 1, 2, rand::rngs::OsRng).await?;
//! println!("Randomness: {}", hex::encode(randomness));
//! #
//! # Ok(()) }
//! ```
//!
//! _Note:_ `protocol_of_random_generation` is defined in [examples/mpc_random_generation.rs]
//!
//! [examples/mpc_random_generation.rs]: https://github.com/ZenGo-X/round-based-protocol/blob/main/round-based/examples/mpc_random_generation.rs

use std::net::SocketAddr;
use std::ops;

use tokio::io;
use tokio::net;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use phantom_type::PhantomType;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{Side, TwoParty};

// Re-exports
pub use crate::delivery::utils::tls::{ClientTlsConfig, ServerTlsConfig};

/// Server connection established with client over TLS+TCP
pub type TwoPartyServerTls<M> = TwoParty<
    M,
    io::ReadHalf<tokio_rustls::server::TlsStream<net::TcpStream>>,
    io::WriteHalf<tokio_rustls::server::TlsStream<net::TcpStream>>,
>;
/// Client connection established with server over TLS+TCP
pub type TwoPartyClientTls<M> = TwoParty<
    M,
    io::ReadHalf<tokio_rustls::client::TlsStream<net::TcpStream>>,
    io::WriteHalf<tokio_rustls::client::TlsStream<net::TcpStream>>,
>;

/// A party of two party protocol who runs a TLS server
///
/// Wraps a tokio [TcpListener](net::TcpListener) and [TlsAcceptor]. Provides [`accept`](Self::accept)
/// method that returns [TwoPartyServerTls] implementing [Delivery] for every new connection
///
/// [Delivery]: crate::Delivery
pub struct TlsServer<M> {
    listener: net::TcpListener,
    acceptor: TlsAcceptor,

    buffer_capacity: usize,
    msg_len_limit: usize,

    _ph: PhantomType<M>,
}

impl<M> TlsServer<M>
where
    M: Serialize + DeserializeOwned + Clone,
{
    /// Binds a TCP server at given address with given TLS config
    ///
    /// If you need more precise control on socket binding, use [new](Self::new) constructor.
    pub async fn bind<A: net::ToSocketAddrs>(
        addr: A,
        config: &ServerTlsConfig,
    ) -> io::Result<Self> {
        Ok(Self::new(net::TcpListener::bind(addr).await?, config))
    }

    /// Wraps existing TcpListener and TLS config into TlsServer
    ///
    /// If you need to provide custom [rustls::ServerConfig], use [with_acceptor] constructor.
    ///
    /// [with_acceptor]: Self::with_acceptor
    pub fn new(listener: net::TcpListener, config: &ServerTlsConfig) -> Self {
        Self::with_acceptor(listener, TlsAcceptor::from(config.to_rustls_config()))
    }

    /// Wraps existing TcpListener and acceptor into TlsServer
    pub fn with_acceptor(listener: net::TcpListener, acceptor: TlsAcceptor) -> Self {
        Self {
            listener,
            acceptor,

            buffer_capacity: 4096,
            msg_len_limit: 10_000,

            _ph: PhantomType::new(),
        }
    }

    /// Sets internal buffer capacity
    ///
    /// Ideally, capacity should be chosen to fit 2 serialized messages, ie. choose it to be
    /// `2*average_msg_size`. Buffer grows if it's too small to send/receive a single message unless
    /// it exceeds [message size limit].
    ///
    /// [message size limit]: Self::set_message_size_limit
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 4096 bytes.
    pub fn set_buffer_capacity(&mut self, capacity: usize) {
        self.buffer_capacity = capacity
    }

    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(&mut self, limit: usize) {
        self.msg_len_limit = limit;
    }

    /// Accepts a new client, performs TLS handshake, and then returns a [TwoPartyServerTls] implementing
    /// [Delivery] trait
    ///
    /// [Delivery]: crate::Delivery
    pub async fn accept(&mut self) -> io::Result<(TwoPartyServerTls<M>, SocketAddr)> {
        let (conn, addr) = self.listener.accept().await?;
        let tls_conn = self.acceptor.accept(conn).await?;
        let (read, write) = io::split(tls_conn);
        Ok((
            TwoPartyServerTls::new(
                Side::Server,
                read,
                write,
                self.buffer_capacity,
                self.msg_len_limit,
            ),
            addr,
        ))
    }
}
impl<M> ops::Deref for TlsServer<M> {
    type Target = net::TcpListener;
    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}

/// Builds a party of two party protocol who acts as TLS client
pub struct TlsClientBuilder {
    buffer_capacity: usize,
    msg_len_limit: usize,
}

impl TlsClientBuilder {
    /// Constructs a client builder
    pub fn new() -> Self {
        Self {
            buffer_capacity: 4096,
            msg_len_limit: 10_000,
        }
    }

    /// Sets internal buffer capacity
    ///
    /// Ideally, capacity should be chosen to fit 2 serialized messages, ie. choose it to be
    /// `2*average_msg_size`. Buffer grows if it's too small to send/receive a single message unless
    /// it exceeds [message size limit].
    ///
    /// [message size limit]: Self::set_message_size_limit
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 4096 bytes.
    pub fn set_buffer_capacity(&mut self, capacity: usize) {
        self.buffer_capacity = capacity
    }

    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(&mut self, limit: usize) {
        self.msg_len_limit = limit;
    }

    /// Opens a TCP connection to a remote host, performs TLS handshake and establishes secure
    /// communication channel
    ///
    /// If you need more precise control on socket creation, use [connected](Self::connected) constructor.
    pub async fn connect<M, A>(
        self,
        domain: webpki::DNSNameRef<'_>,
        addr: A,
        config: &ClientTlsConfig,
    ) -> io::Result<TwoPartyClientTls<M>>
    where
        A: net::ToSocketAddrs,
        M: Serialize + DeserializeOwned + Clone,
    {
        let conn = net::TcpStream::connect(addr).await?;
        let tls_conn = TlsConnector::from(config.to_rustls_config())
            .connect(domain, conn)
            .await?;
        self.connected(tls_conn)
    }

    /// Constructs TwoPartyClientTls from TlsStream
    pub fn connected<M>(
        self,
        tls_conn: tokio_rustls::client::TlsStream<net::TcpStream>,
    ) -> io::Result<TwoPartyClientTls<M>>
    where
        M: Serialize + DeserializeOwned + Clone,
    {
        let (read, write) = io::split(tls_conn);
        Ok(TwoPartyClientTls::new(
            Side::Client,
            read,
            write,
            self.buffer_capacity,
            self.msg_len_limit,
        ))
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use serde::{Deserialize, Serialize};

    use crate::delivery::utils::tls::mock::MockTls;
    use crate::{DeliverOutgoingExt, Delivery, Incoming, Outgoing};

    use super::*;

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct TestMessage(String);

    /// This is a demonstrative test that shows how we can simply deploy a TCP server/client that can
    /// exchange messages
    #[tokio::test]
    async fn exchange_tls_server_client_messages() {
        let mock_tls = MockTls::generate();

        let server_tls_config = mock_tls.issue_server_cert(vec!["my-server.local".to_string()]);
        let client_tls_config = mock_tls.issue_client_cert(vec!["party0.local".to_string()]);

        let mut server = TlsServer::<TestMessage>::bind("127.0.0.1:0", &server_tls_config)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // The server
        let server = tokio::spawn(async move {
            let (link, _addr) = server.accept().await.unwrap();
            let (recv, mut send) = link.split();

            // Server sends some messages to the client
            let sending = tokio::spawn(async move {
                let msgs = vec![
                    "Hi, client!".to_string(),
                    "Wanna see some ads?".to_string(),
                    "Bye".to_string(),
                ];
                send.send_all(msgs.iter().map(|msg| Outgoing {
                    recipient: Some(1),
                    msg,
                }))
                .await
                .unwrap();
                // Shutdown the channel
                DeliverOutgoingExt::<TestMessage>::shutdown(&mut send)
                    .await
                    .unwrap();
            });

            // Server receives messages from the client and asserts that they are what we
            // expected to receive
            let receiving = tokio::spawn(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = vec![
                    Incoming {
                        sender: 1,
                        msg: TestMessage("Hi, server!".to_string()),
                    },
                    Incoming {
                        sender: 1,
                        msg: TestMessage("No thanks".to_string()),
                    },
                    Incoming {
                        sender: 1,
                        msg: TestMessage("Bye".to_string()),
                    },
                ];
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        // The client
        let client = tokio::spawn(async move {
            let link = TlsClientBuilder::new()
                .connect::<TestMessage, _>(
                    webpki::DNSNameRef::try_from_ascii(b"my-server.local").unwrap(),
                    server_addr,
                    &client_tls_config,
                )
                .await
                .unwrap();
            let (recv, mut send) = link.split();

            // Client sends some messages to the server
            let sending = tokio::spawn(async move {
                let msgs = vec![
                    "Hi, server!".to_string(),
                    "No thanks".to_string(),
                    "Bye".to_string(),
                ];
                send.send_all(msgs.iter().map(|msg| Outgoing {
                    recipient: Some(0),
                    msg,
                }))
                .await
                .unwrap();
                // Shutdown the channel
                DeliverOutgoingExt::<TestMessage>::shutdown(&mut send)
                    .await
                    .unwrap();
            });

            // Client receives messages from the server and asserts that they are what we
            // expected to receive
            let receiving = tokio::spawn(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = vec![
                    Incoming {
                        sender: 0,
                        msg: TestMessage("Hi, client!".to_string()),
                    },
                    Incoming {
                        sender: 0,
                        msg: TestMessage("Wanna see some ads?".to_string()),
                    },
                    Incoming {
                        sender: 0,
                        msg: TestMessage("Bye".to_string()),
                    },
                ];
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        client.await.unwrap();
        server.await.unwrap();
    }
}
