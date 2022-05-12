//! Multiparty protocol simulation
//!
//! [`Simulation`] is an essential developer tool for testing the multiparty protocol locally.
//! It covers most of the boilerplate by mocking networking.
//!
//! ## Example
//!
//! ```rust
//! use round_based::Mpc;
//! use round_based::simulation::Simulation;
//! use futures::future::try_join_all;
//!
//! # type Result<T, E = ()> = std::result::Result<T, E>;
//! # type Randomness = [u8; 32];
//! # type Msg = ();
//! // Any MPC protocol you want to test
//! pub async fn protocol_of_random_generation<M>(party: M, i: u16, n: u16) -> Result<Randomness>
//! where M: Mpc<ProtocolMessage = Msg>
//! {
//!     // ...
//! # todo!()
//! }
//!
//! async fn test_randomness_generation() {
//!     let n = 3;
//!
//!     let mut simulation = Simulation::<Msg>::new();
//!     let mut outputs = vec![];
//!     for i in 0..n {
//!         let party = simulation.add_party();
//!         outputs.push(protocol_of_random_generation(party, i, n));
//!     }   
//!
//!     // Waits each party to complete the protocol
//!     let outputs = try_join_all(outputs).await.expect("protocol wasn't completed successfully");
//!     // Asserts that all parties output the same randomness
//!     for output in outputs.iter().skip(1) {
//!         assert_eq!(&outputs[0], output);
//!     }  
//! }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Sink, Stream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};

use crate::delivery::{Delivery, Incoming, Outgoing};
use crate::{MessageDestination, MpcParty};

/// Multiparty protocol simulator
pub struct Simulation<M> {
    channel: broadcast::Sender<Outgoing<Incoming<M>>>,
    next_party_idx: u16,
}

impl<M> Simulation<M>
where
    M: Clone + Send + Unpin + 'static,
{
    /// Instantiates a new simulation
    pub fn new() -> Self {
        Self {
            channel: broadcast::channel(500).0,
            next_party_idx: 0,
        }
    }

    /// Instantiates a new simulation with given capacity
    ///
    /// `Simulation` stores internally all sent messages. Capacity limits size of the internal buffer.
    /// Because of that you might run into error if you choose too small capacity. Choose capacity
    /// that can fit all the messages sent by all the parties during entire protocol lifetime.
    ///
    /// Default capacity is 500 (i.e. if you call `Simulation::new()`)
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            channel: broadcast::channel(capacity).0,
            next_party_idx: 0,
        }
    }

    /// Adds new party to the network
    pub fn add_party(&mut self) -> MpcParty<M, MockedDelivery<M>> {
        let local_party_idx = self.next_party_idx;
        self.next_party_idx += 1;

        MpcParty::connected(MockedDelivery {
            incoming: MockedIncoming {
                local_party_idx,
                receiver: BroadcastStream::new(self.channel.subscribe()),
            },
            outgoing: MockedOutgoing {
                local_party_idx,
                sender: self.channel.clone(),
            },
        })
    }

    /// Connects new party to the network
    ///
    /// Similar to [`.add_party()`](Self::add_party) but returns `MockedDelivery<M>` instead of
    /// `MpcParty<M, MockedDelivery<M>>`
    pub fn connect_new_party(&mut self) -> MockedDelivery<M> {
        let local_party_idx = self.next_party_idx;
        self.next_party_idx += 1;

        MockedDelivery {
            incoming: MockedIncoming {
                local_party_idx,
                receiver: BroadcastStream::new(self.channel.subscribe()),
            },
            outgoing: MockedOutgoing {
                local_party_idx,
                sender: self.channel.clone(),
            },
        }
    }
}

impl<M> Default for Simulation<M>
where
    M: Clone + Send + Unpin + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Mocked networking
pub struct MockedDelivery<M> {
    incoming: MockedIncoming<M>,
    outgoing: MockedOutgoing<M>,
}

impl<M> Delivery<M> for MockedDelivery<M>
where
    M: Clone + Send + Unpin + 'static,
{
    type Send = MockedOutgoing<M>;
    type Receive = MockedIncoming<M>;
    type SendError = broadcast::error::SendError<()>;
    type ReceiveError = BroadcastStreamRecvError;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.incoming, self.outgoing)
    }
}

/// Incoming channel of mocked network
pub struct MockedIncoming<M> {
    local_party_idx: u16,
    receiver: BroadcastStream<Outgoing<Incoming<M>>>,
}

impl<M> Stream for MockedIncoming<M>
where
    M: Clone + Send + 'static,
{
    type Item = Result<Incoming<M>, BroadcastStreamRecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let msg = match ready!(Pin::new(&mut self.receiver).poll_next(cx)) {
                Some(Ok(m)) => m,
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => return Poll::Ready(None),
            };
            if msg.recipient.is_p2p()
                && msg.recipient != MessageDestination::OneParty(self.local_party_idx)
            {
                continue;
            }
            return Poll::Ready(Some(Ok(msg.msg)));
        }
    }
}

/// Outgoing channel of mocked network
pub struct MockedOutgoing<M> {
    local_party_idx: u16,
    sender: broadcast::Sender<Outgoing<Incoming<M>>>,
}

impl<M> Sink<Outgoing<M>> for MockedOutgoing<M> {
    type Error = broadcast::error::SendError<()>;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, msg: Outgoing<M>) -> Result<(), Self::Error> {
        self.sender
            .send(msg.map(|m| Incoming {
                sender: self.local_party_idx,
                msg: m,
            }))
            .map_err(|_| broadcast::error::SendError(()))?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
