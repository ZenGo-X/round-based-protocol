//! # Round-based protocols execution
//!
//! ## What is round-based protocol?
//! In round-based protocol we have `n` parties which can send and receive messages within rounds
//! (number of parties is known prior to starting protocol).
//!
//! At every round party may send a P2P or broadcast message, and receives all broadcast
//! messages sent in this round by other parties or P2P messages sent directly to it. After
//! party receives enough round messages, it either proceeds (evaluates something on received
//! messages and goes to next round) or finishes the protocol.
//!
//! ## Purpose
//! Most of MPC protocols uses round-based notation. Whereas all of them achieve various
//! goals and rely on different math, most of them use the same communication model. Purpose
//! of this crate is to define generic round-based protocol, and develop generic protocol
//! executors with smallest setup.
//!
//! ## How to define own round-based protocol
//! To define own round-based protocol, you need to implement [StateMachine] trait. I.e.
//! you need to define type of [protocol message](StateMachine::MessageBody) which will be
//! transmitted on wire, determine rules how to
//! [handle incoming message](StateMachine::handle_incoming) and how to
//! [proceed state](StateMachine::proceed), etc.
//!
//! We divide methods in StateMachine on which can block and which can not. Most of MPC protocols
//! rely on computationally expensive math operations, such operations should not be executed
//! in async environment (i.e. on green-thread), that's why the only method which capable of
//! doing expensive operations is [proceed](StateMachine::proceed).
//!
//! ## How to execute round-based protocol
//! To run round-based protocol you need only stream of incoming messages and sink for outcoming ones.
//! Then you can do the thing using [AsyncProtocol] (backed by [tokio]):
//! ```no_run
//! # use futures::stream::{self, Stream, FusedStream};
//! # use futures::sink::{self, Sink, SinkExt};
//! # use round_based::{Msg, StateMachine, AsyncProtocol};
//! # struct M;
//! # #[derive(Debug)] struct Error;
//! # impl From<std::convert::Infallible> for Error {
//! #    fn from(_: std::convert::Infallible) -> Error { Error }
//! # }
//! # trait Constructable { fn initial() -> Self; }
//! fn incoming() -> impl Stream<Item=Result<Msg<M>, Error>> + FusedStream + Unpin {
//!     // ...
//! # stream::pending()
//! }
//! fn outcoming() -> impl Sink<Msg<M>, Error=Error> + Unpin {
//!     // ...
//! # sink::drain().with(|x| futures::future::ok(x))
//! }
//! # async fn execute_protocol<State>() -> Result<(), round_based::async_runtime::Error<State::Err, Error, Error>>
//! # where State: StateMachine<MessageBody = M, Err = Error> + Constructable + Send + 'static
//! # {
//! let output: State::Output = AsyncProtocol::new(State::initial(), incoming(), outcoming())
//!     .run().await?;
//! // ...
//! # let _ = output; Ok(())
//! # }
//! ```
//!
//! Usually protocols assume that P2P messages are encrypted, in this case it's up to you to provide
//! secure channels.
//!
//! For development purposes, you can also find useful [Simulation](dev::Simulation) and
//! [AsyncSimulation](dev::AsyncSimulation) simulators which can run protocols locally.

pub mod containers;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

mod sm;
pub use sm::*;

#[cfg(feature = "async-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-runtime")))]
pub mod async_runtime;
#[cfg(feature = "async-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-runtime")))]
pub use async_runtime::AsyncProtocol;
