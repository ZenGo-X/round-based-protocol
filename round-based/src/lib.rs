#![cfg_attr(docsrs, feature(doc_cfg))]

//! An MPC framework that unifies and simplifies the way of developing and working with
//! multiparty protocols (e.g. threshold signing, random beacons, etc.).
//!
//! ## Goals
//!
//! * Async friendly \
//!   Async is the most simple and efficient way of doing networking in Rust
//! * Simple, configurable \
//!   Protocol can be carried out in a few lines of code: check out examples.
//! * Independent of networking layer \
//!   We use abstractions [`Stream`](futures::Stream) and [`Sink`](futures::Sink) to receive and send messages.
//!
//! ## Networking
//!
//! In order to run an MPC protocol, transport layer needs to be defined. All you have to do is to
//! implement [`Delivery`] trait which is basically a stream and a sink for receiving and sending messages.
//!
//! Message delivery should meet certain criterias that differ from protocol to protocol (refer to
//! the documentation of the protocol you're using), but usually they are:
//!
//! * Messages should be authenticated \
//!   Each message should be signed with identity key of the sender. This implies having Public Key
//!   Infrastructure.
//! * P2P messages should be encrypted \
//!   Only recipient should be able to learn the content of p2p message
//! * Should have reliable broadcast channel \
//!   Simply saying, when party receives a broadcast message over reliable channel it should be ensured that
//!   everybody else received the same message. Protocol indicates whether outgoing message should be sent
//!   over reliable channel, see [`.is_reliable_broadcast()`](Outgoing::is_reliable_broadcast).
//!
//! ## Available MPC protocols
//!
//! Following MPC protocols are built upon `round-based` framework:
//!
//! * Threshold ECDSA \
//!   `round-based-ing` implements t-ECDSA based on GG18 paper
//!

pub mod blocking;
mod delivery;
pub mod party;
pub mod rounds;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod simulation;

pub use self::delivery::*;
#[doc(no_inline)]
pub use self::{
    party::{Mpc, MpcParty},
    rounds::{ProtocolMessage, RoundMessage},
};

#[doc(hidden)]
pub mod _docs;

/// Derives [`ProtocolMessage`] and [`RoundMessage`] traits
///
/// See [`ProtocolMessage`] docs for more details
#[cfg(feature = "derive")]
#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
pub use round_based_derive::ProtocolMessage;
