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
//!     let party = MpcParty::connected(client);
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
//! let party = MpcParty::connected(conn);
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
use std::sync::Arc;

use phantom_type::PhantomType;
use tokio::{io, net};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use delivery_core::serialization_backend::Bincode;

use crate::core::{Connection, Side};

/// Server connection established with client over TLS+TCP
pub type TlsServerConnection<M, S = Bincode, D = Bincode> = Connection<
    M,
    Compat<io::ReadHalf<tokio_rustls::server::TlsStream<net::TcpStream>>>,
    Compat<io::WriteHalf<tokio_rustls::server::TlsStream<net::TcpStream>>>,
    S,
    D,
>;
/// Client connection established with server over TLS+TCP
pub type TlsClientConnection<M, S = Bincode, D = Bincode> = Connection<
    M,
    Compat<io::ReadHalf<tokio_rustls::client::TlsStream<net::TcpStream>>>,
    Compat<io::WriteHalf<tokio_rustls::client::TlsStream<net::TcpStream>>>,
    S,
    D,
>;

/// A party of two party protocol who runs a TLS server
///
/// Wraps a tokio [TcpListener](net::TcpListener) and [TlsAcceptor]. Provides [`accept`](Self::accept)
/// method that returns [TwoPartyServerTls] implementing [Delivery] for every new connection
///
/// [Delivery]: crate::Delivery
pub struct TlsServer<M, S = Bincode, D = Bincode> {
    listener: net::TcpListener,
    acceptor: TlsAcceptor,

    message_size_limit: usize,

    serializer: S,
    deserializer: D,

    _ph: PhantomType<M>,
}

impl<M> TlsServer<M> {
    /// Binds a TCP server at given address with given TLS config
    ///
    /// If you need more precise control on socket binding, use [new](Self::new) constructor.
    pub async fn bind<A: net::ToSocketAddrs>(
        addr: A,
        config: Arc<rustls::ServerConfig>,
    ) -> io::Result<Self> {
        Ok(Self::new(net::TcpListener::bind(addr).await?, config))
    }

    /// Wraps existing TcpListener and TLS config into TlsServer
    ///
    /// If you need to provide custom [rustls::ServerConfig], use [with_acceptor] constructor.
    ///
    /// [with_acceptor]: Self::with_acceptor
    pub fn new(listener: net::TcpListener, config: Arc<rustls::ServerConfig>) -> Self {
        Self::with_acceptor(listener, TlsAcceptor::from(config))
    }

    /// Wraps existing TcpListener and acceptor into TlsServer
    pub fn with_acceptor(listener: net::TcpListener, acceptor: TlsAcceptor) -> Self {
        Self {
            listener,
            acceptor,

            message_size_limit: 10_000,

            serializer: Bincode::default(),
            deserializer: Bincode::default(),

            _ph: PhantomType::new(),
        }
    }
}

impl<M, S: Clone, D: Clone> TlsServer<M, S, D> {
    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(mut self, limit: usize) -> Self {
        self.message_size_limit = limit;
        self
    }

    pub fn set_serialization_backend<B>(self, backend: B) -> TlsServer<M, B, D> {
        TlsServer {
            serializer: backend,

            listener: self.listener,
            acceptor: self.acceptor,
            message_size_limit: self.message_size_limit,
            deserializer: self.deserializer,
            _ph: PhantomType::new(),
        }
    }

    pub fn set_deserialization_backend<B>(self, backend: B) -> TlsServer<M, S, B> {
        TlsServer {
            deserializer: backend,

            listener: self.listener,
            acceptor: self.acceptor,
            message_size_limit: self.message_size_limit,
            serializer: self.serializer,
            _ph: PhantomType::new(),
        }
    }

    /// Accepts a new client, performs TLS handshake, and then returns a [TwoPartyServerTls] implementing
    /// [Delivery] trait
    ///
    /// [Delivery]: crate::Delivery
    pub async fn accept(&mut self) -> io::Result<(TlsServerConnection<M, S, D>, SocketAddr)> {
        let (conn, addr) = self.listener.accept().await?;
        let tls_conn = self.acceptor.accept(conn).await?;
        let (read, write) = io::split(tls_conn);
        Ok((
            TlsServerConnection::with_limit(
                Side::Server,
                read.compat(),
                write.compat_write(),
                self.message_size_limit,
            )
            .set_serialization_backend(self.serializer.clone())
            .set_deserialization_backend(self.deserializer.clone()),
            addr,
        ))
    }
}

/// Builds a party of two party protocol who acts as TLS client
pub struct TlsClientBuilder<M, S = Bincode, D = Bincode> {
    connector: TlsConnector,
    message_size_limit: usize,
    serializer: S,
    deserializer: D,
    _ph: PhantomType<M>,
}

impl<M> TlsClientBuilder<M> {
    pub fn with_rustls_config(config: Arc<rustls::ClientConfig>) -> Self {
        Self::with_connector(TlsConnector::from(config))
    }

    pub fn with_connector(connector: TlsConnector) -> Self {
        Self {
            connector,
            message_size_limit: 10_000,

            serializer: Bincode::default(),
            deserializer: Bincode::default(),

            _ph: PhantomType::new(),
        }
    }
}

impl<M, S: Clone, D: Clone> TlsClientBuilder<M, S, D> {
    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(mut self, limit: usize) -> Self {
        self.message_size_limit = limit;
        self
    }

    /// Opens a TCP connection to a remote host, performs TLS handshake and establishes secure
    /// communication channel
    ///
    /// If you need more precise control on socket creation, use [connected](Self::connected) constructor.
    pub async fn connect<A>(
        self,
        domain: rustls::ServerName,
        addr: A,
    ) -> io::Result<TlsClientConnection<M, S, D>>
    where
        A: net::ToSocketAddrs,
    {
        let conn = net::TcpStream::connect(addr).await?;
        let tls_conn = self.connector.connect(domain, conn).await?;
        self.connected(tls_conn)
    }

    /// Wraps already established TlsStream
    pub fn connected(
        self,
        tls_conn: tokio_rustls::client::TlsStream<net::TcpStream>,
    ) -> io::Result<TlsClientConnection<M, S, D>> {
        let (read, write) = io::split(tls_conn);
        Ok(TlsClientConnection::with_limit(
            Side::Client,
            read.compat(),
            write.compat_write(),
            self.message_size_limit,
        )
        .set_serialization_backend(self.serializer.clone())
        .set_deserialization_backend(self.deserializer.clone()))
    }
}
