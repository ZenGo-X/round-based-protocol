//! Two party delivery over plain TCP socket
//!
//! __*Warning:*__ it does not encrypt/authenticate messages, anything you send on the wire can be
//! easily forged. Use it for development purposes only. See [tls](super::tls) delivery if you need
//! a secure communication channel.
//!
//! ## Example: Server
//! ```rust,no_run
//! use round_based::delivery::two_party::insecure::Server;
//! use round_based::MpcParty;
//! # use serde::{Serialize, Deserialize};
//! # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[derive(Serialize, Deserialize, Clone, round_based::ProtocolMessage)] enum Msg {}
//! # async fn protocol_of_random_generation<R: rand::RngCore, M: round_based::Mpc<ProtocolMessage = Msg>>(party: M,i: u16,n: u16,mut rng: R) -> Result<[u8; 32], Box<dyn std::error::Error>> { todo!() }
//!
//! let mut server = Server::<Msg>::bind("127.0.0.1:9090").await?;
//! loop {
//!     let (client, _client_addr) = server.accept().await?;
//!     let party = MpcParty::connect(client);
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
//! use round_based::delivery::two_party::insecure::ClientBuilder;
//! use round_based::MpcParty;
//! # use serde::{Serialize, Deserialize};
//! # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[derive(Serialize, Deserialize, Clone, round_based::ProtocolMessage)] enum Msg {}
//! # async fn protocol_of_random_generation<R: rand::RngCore, M: round_based::Mpc<ProtocolMessage = Msg>>(party: M,i: u16,n: u16,mut rng: R) -> Result<[u8; 32], Box<dyn std::error::Error>> { todo!() }
//!
//! let conn = ClientBuilder::new().connect::<Msg, _>("127.0.0.1:9090").await?;
//! let party = MpcParty::connect(conn);
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
use std::{io, ops};

use tokio::net::{
    self,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use phantom_type::PhantomType;

use delivery_core::serialization_backend::Bincode;

use crate::core::{Connection, Side};

/// A connection established between two parties over plain TCP
pub type TcpConnection<M, S = Bincode, D = Bincode> =
    Connection<M, Compat<OwnedReadHalf>, Compat<OwnedWriteHalf>, S, D>;

/// A party of two party protocol who runs a TCP server
///
/// Server is a wrapper around tokio [TcpListener](net::TcpListener) with overloaded [`accept`](Self::accept)
/// method that returns [TwoPartyTcp] implementing [Delivery] trait.
///
/// [Delivery]: crate::Delivery
pub struct TcpServer<M, S = Bincode, D = Bincode> {
    listener: net::TcpListener,
    msg_size_limit: usize,

    serializer: S,
    deserializer: D,

    _ph: PhantomType<M>,
}

impl<M> TcpServer<M> {
    /// Constructs a server from TcpListener
    pub fn new(listener: net::TcpListener) -> Self {
        Self {
            listener,
            msg_size_limit: 10_000,
            serializer: Bincode::default(),
            deserializer: Bincode::default(),
            _ph: PhantomType::new(),
        }
    }

    /// Binds a TCP server
    ///
    /// Method is similar to a [tokio one](net::TcpListener::bind). To configure socket more precisely,
    /// please use [Server::new] constructor.
    pub async fn bind<A: net::ToSocketAddrs>(addrs: A) -> io::Result<Self> {
        net::TcpListener::bind(addrs).await.map(Self::new)
    }
}

impl<M, S: Clone, D: Clone> TcpServer<M, S, D> {
    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(mut self, limit: usize) -> Self {
        self.msg_size_limit = limit;
        self
    }

    pub fn set_serialization_backend<B>(self, backend: B) -> TcpServer<M, B, D> {
        TcpServer {
            serializer: backend,

            listener: self.listener,
            msg_size_limit: self.msg_size_limit,
            deserializer: self.deserializer,
            _ph: PhantomType::new(),
        }
    }

    pub fn set_deserialization_backend<B>(self, backend: B) -> TcpServer<M, S, B> {
        TcpServer {
            deserializer: backend,

            listener: self.listener,
            msg_size_limit: self.msg_size_limit,
            serializer: self.serializer,
            _ph: PhantomType::new(),
        }
    }

    /// Accepts a new incoming connection
    ///
    /// Returns a [TwoPartyTcp] that implements [Delivery] trait, and address of the client.
    ///
    /// [Delivery]: crate::Delivery
    pub async fn accept(&mut self) -> io::Result<(TcpConnection<M, S, D>, SocketAddr)> {
        let (conn, remote_addr) = self.listener.accept().await?;
        let (recv, send) = conn.into_split();
        Ok((
            Connection::with_limit(
                Side::Server,
                recv.compat(),
                send.compat_write(),
                self.msg_size_limit,
            )
            .set_serialization_backend(self.serializer.clone())
            .set_deserialization_backend(self.deserializer.clone()),
            remote_addr,
        ))
    }
}

impl<M> ops::Deref for TcpServer<M> {
    type Target = net::TcpListener;
    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}
impl<M> ops::DerefMut for TcpServer<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.listener
    }
}

/// Builds a party of two party protocol who acts as TCP client
pub struct TcpClientBuilder<M, S = Bincode, D = Bincode> {
    msg_size_limit: usize,
    serializer: S,
    deserializer: D,
    _ph: PhantomType<M>,
}

impl<M> TcpClientBuilder<M> {
    /// Constructs a client builder
    pub fn new() -> Self {
        Self {
            msg_size_limit: 10_000,
            serializer: Bincode::default(),
            deserializer: Bincode::default(),
            _ph: PhantomType::new(),
        }
    }
}

impl<M, S, D> TcpClientBuilder<M, S, D> {
    /// Limits length of serialized messages being sent or received
    ///
    /// Sending / receiving larger messages results into error and causes channel to be closed.
    ///
    /// Calling this method affects only subsequently accepted connections.
    ///
    /// Default value is 10KB (10 000 bytes).
    pub fn set_message_size_limit(mut self, limit: usize) -> Self {
        self.msg_size_limit = limit;
        self
    }

    pub fn set_serialization_backend<B>(self, backend: B) -> TcpClientBuilder<M, B, D> {
        TcpClientBuilder {
            serializer: backend,

            msg_size_limit: self.msg_size_limit,
            deserializer: self.deserializer,
            _ph: PhantomType::new(),
        }
    }

    pub fn set_deserialization_backend<B>(self, backend: B) -> TcpClientBuilder<M, S, B> {
        TcpClientBuilder {
            deserializer: backend,

            msg_size_limit: self.msg_size_limit,
            serializer: self.serializer,
            _ph: PhantomType::new(),
        }
    }
}

impl<M, S: Clone, D: Clone> TcpClientBuilder<M, S, D> {
    /// Opens a TCP connection to a remote host
    ///
    /// Similar to [TcpStream::connect](net::TcpStream::connect). To configure connection more precisely,
    /// please use [connected](Self::connected) constructor
    pub async fn connect<A>(&self, addr: A) -> io::Result<TcpConnection<M, S, D>>
    where
        A: net::ToSocketAddrs,
    {
        let conn = net::TcpStream::connect(addr).await?;
        self.connected(conn)
    }

    /// Constructs TwoPartyTcp from TcpStream
    pub fn connected(&self, tcp_stream: net::TcpStream) -> io::Result<TcpConnection<M, S, D>> {
        let (recv, send) = tcp_stream.into_split();
        Ok(Connection::with_limit(
            Side::Client,
            recv.compat(),
            send.compat_write(),
            self.msg_size_limit,
        )
        .set_serialization_backend(self.serializer.clone())
        .set_deserialization_backend(self.deserializer.clone()))
    }
}

impl<M> Default for TcpClientBuilder<M> {
    fn default() -> Self {
        Self::new()
    }
}
