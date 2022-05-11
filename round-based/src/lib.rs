#![cfg_attr(docsrs, feature(doc_cfg))]

//! An MPC framework that unifies and simplifies the way of developing and working with
//! multiparty protocols (e.g. threshold signing, random beacons, etc.).
//!
//! ## Goals
//!
//! * Async friendly \
//!   Async is the most simple and efficient way of doing networking in Rust, and MPC has to deal
//!   with networking
//! * Simple, configurable \
//!   Protocol can be carried out in a few lines of code: check out examples.
//! * Independent of networking layer \
//!   We use abstractions [`Stream`](futures::Stream) and [`Sink`](futures::Sink) to receive and send messages.
//!
//! ## Networking
//!
//! In order to run an MPC protocol, transport layer needs to be defined. All you have to do is to
//! define [`Delivery`] trait which is basically a stream and a sink for receiving and sending messages.
//!
//! Message delivery should meet certain criterias that differ from protocol to protocol (refer to
//! the documentation of the protocol you're using), but usually they are:
//!
//! * Messages should be authenticated \
//!   Each message should be signed with identity key of the sender. This implies having Public Key
//!   Infrastructure.
//! * P2P messages should be encrypted \
//!   Only recipient should be able to learn the content of p2p message
//! * Broadcast should be reliable \
//!   Simply saying, when party receives a broadcast message it should be ensured that everybody else
//!   received the same message.
//!
//! You can develop your own implementation of messages delivery that matches your infrastructure and
//! needs, or use one of published general-purpose delivery implementations:
//!
//! * Trusted delivery _[github](https://github.com/dfnsco/trusted-delivery)_ \
//!   Dedicated communication server is used by parties to exchange messages. Messages are authenticated,
//!   p2p messages are encrypted. Server needs to be trusted to assume reliable broadcast (if you
//!   don't need it, the server can be considered trustless).
//! * We may list your implementation here, ping us!
//!
//! ## Available MPC protocols
//!
//! Following MPC protocols are built upon `round-based` framework:
//!
//! * Threshold ECDSA \
//!   `round-based-ing` implements t-ECDSA based on GG18 paper
//! * More protocols are coming: t-Schnorr, t-EdDSA
//!

pub mod blocking;
mod delivery;
pub mod party;
pub mod rounds;
pub mod simulation;

pub use self::delivery::*;
#[doc(hidden)]
pub use self::{
    party::{Mpc, MpcParty},
    rounds::store::{ProtocolMessage, RoundMessage},
};

#[cfg(feature = "derive")]
pub use round_based_derive::ProtocolMessage;
