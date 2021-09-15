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
use std::ops;

use tokio::io::{self};
use tokio::net::{
    self,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use phantom_type::PhantomType;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{Side, TwoParty};

/// A connection established between two parties over plain TCP
pub type TwoPartyTcp<M> = TwoParty<M, OwnedReadHalf, OwnedWriteHalf>;

/// A party of two party protocol who runs a TCP server
///
/// Server is a wrapper around tokio [TcpListener](net::TcpListener) with overloaded [`accept`](Self::accept)
/// method that returns [TwoPartyTcp] implementing [Delivery] trait.
///
/// [Delivery]: crate::Delivery
pub struct Server<M> {
    listener: net::TcpListener,
    buffer_capacity: usize,
    msg_len_limit: usize,
    _ph: PhantomType<M>,
}

impl<M> Server<M>
where
    M: Serialize + DeserializeOwned + Clone,
{
    /// Constructs a server from TcpListener
    pub fn new(listener: net::TcpListener) -> Self {
        Self {
            listener,
            buffer_capacity: 4096,
            msg_len_limit: 10_000,
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

    /// Accepts a new incoming connection
    ///
    /// Returns a [TwoPartyTcp] that implements [Delivery] trait, and address of the client.
    ///
    /// [Delivery]: crate::Delivery
    pub async fn accept(&mut self) -> io::Result<(TwoPartyTcp<M>, SocketAddr)> {
        let (conn, remote_addr) = self.listener.accept().await?;
        let (recv, send) = conn.into_split();
        Ok((
            TwoParty::new(
                Side::Server,
                recv,
                send,
                self.buffer_capacity,
                self.msg_len_limit,
            ),
            remote_addr,
        ))
    }
}

impl<M> ops::Deref for Server<M> {
    type Target = net::TcpListener;
    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}
impl<M> ops::DerefMut for Server<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.listener
    }
}

/// Builds a party of two party protocol who acts as TCP client
pub struct ClientBuilder {
    buffer_capacity: usize,
    msg_len_limit: usize,
}

impl ClientBuilder {
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

    /// Opens a TCP connection to a remote host
    ///
    /// Similar to [TcpStream::connect](net::TcpStream::connect). To configure connection more precisely,
    /// please use [connected](Self::connected) constructor
    pub async fn connect<M, A>(self, addr: A) -> io::Result<TwoPartyTcp<M>>
    where
        A: net::ToSocketAddrs,
        M: Serialize + DeserializeOwned + Clone,
    {
        let conn = net::TcpStream::connect(addr).await?;
        self.connected(conn)
    }

    /// Constructs TwoPartyTcp from TcpStream
    pub fn connected<M>(self, tcp_stream: net::TcpStream) -> io::Result<TwoPartyTcp<M>>
    where
        M: Serialize + DeserializeOwned + Clone,
    {
        let (recv, send) = tcp_stream.into_split();
        Ok(TwoParty::new(
            Side::Client,
            recv,
            send,
            self.buffer_capacity,
            self.msg_len_limit,
        ))
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use futures::TryStreamExt;
    use tokio::task::{spawn_local, LocalSet};

    use serde::{Deserialize, Serialize};

    use crate::delivery::{DeliverOutgoingExt, Delivery, Incoming, Outgoing};

    use super::{ClientBuilder, Server};

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct TestMessage(u16);

    /// This is a demonstrative test that shows how we can simply deploy a TCP server/client that can
    /// exchange messages
    #[tokio::test]
    async fn exchange_server_client_messages() {
        let local_set = LocalSet::new();

        let mut server = Server::<TestMessage>::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // The client
        let client = local_set.spawn_local(async move {
            let link = ClientBuilder::new()
                .connect::<TestMessage, _>(server_addr)
                .await
                .unwrap();
            let (recv, mut send) = link.split();

            // Client sends 1+2+3 messages to the server
            let sending = spawn_local(async move {
                for i in 1..=3 {
                    let msgs = vec![TestMessage(i); usize::from(i)];
                    send.send_all(msgs.iter().map(|msg| Outgoing {
                        recipient: Some(0),
                        msg,
                    }))
                    .await
                    .unwrap()
                }
            });

            // Client receives 1+2+3 messages from the server and asserts that they are what we
            // expected to receive
            let receiving = spawn_local(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = (1..=3)
                    .flat_map(|i| {
                        vec![
                            Incoming {
                                sender: 0,
                                msg: TestMessage(i + 100)
                            };
                            usize::from(i)
                        ]
                    })
                    .collect::<Vec<_>>();
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        // The server
        let server = local_set.spawn_local(async move {
            let (link, _addr) = server.accept().await.unwrap();
            let (recv, mut send) = link.split();

            // Server sends 1+2+3 messages to the client. Note that messages payload is different from
            // what client sends to us
            let sending = spawn_local(async move {
                for i in 1..=3 {
                    let msgs = vec![TestMessage(i + 100); usize::from(i)];
                    send.send_all(msgs.iter().map(|msg| Outgoing {
                        recipient: Some(1),
                        msg,
                    }))
                    .await
                    .unwrap();
                }
            });

            // Server receives 1+2+3 messages from the client and asserts that they are what we
            // expected to receive
            let receiving = spawn_local(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = (1..=3)
                    .flat_map(|i| {
                        vec![
                            Incoming {
                                sender: 1,
                                msg: TestMessage(i)
                            };
                            usize::from(i)
                        ]
                    })
                    .collect::<Vec<_>>();
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        local_set.await;
        client.await.unwrap();
        server.await.unwrap();
    }
}
