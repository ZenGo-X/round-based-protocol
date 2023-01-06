//! Party of MPC protocol
//!
//! [`MpcParty`] is party of MPC protocol, connected to network, ready to start carrying out the protocol.
//!
//! ```rust
//! use round_based::{Mpc, MpcParty, Delivery, PartyIndex};
//!
//! # struct KeygenMsg;
//! # struct KeyShare;
//! # struct Error;
//! # type Result<T> = std::result::Result<T, Error>;
//! # async fn doc() -> Result<()> {
//! async fn keygen<M>(party: M, i: PartyIndex, n: u16) -> Result<KeyShare>
//! where
//!     M: Mpc<ProtocolMessage = KeygenMsg>
//! {
//!     // ...
//! # unimplemented!()
//! }
//! async fn connect() -> impl Delivery<KeygenMsg> {
//!     // ...
//! # round_based::_docs::fake_delivery()
//! }
//!
//! let delivery = connect().await;
//! let party = MpcParty::connected(delivery);
//!
//! # let (i, n) = (1, 3);
//! let keyshare = keygen(party, i, n).await?;
//! # Ok(()) }
//! ```

use std::error::Error;

use phantom_type::PhantomType;

use crate::blocking::{Blocking, SpawnBlocking, TokioSpawnBlocking};
use crate::delivery::Delivery;

/// Party of MPC protocol (trait)
///
/// [`MpcParty`] is the only struct that implement this trait. Motivation to have this trait is to fewer amount of
/// generic bounds that are needed to be specified.
///
/// Typical usage of this trait when implementing MPC protocol:
///
/// ```rust
/// use round_based::{Mpc, MpcParty, PartyIndex};
///
/// # struct Msg;
/// async fn keygen<M>(party: M, i: PartyIndex, n: u16)
/// where
///     M: Mpc<ProtocolMessage = Msg>
/// {
///     let MpcParty{ delivery, .. } = party.into_party();
///     // ...
/// }
/// ```
///
/// If we didn't have this trait, generics would be less readable:
/// ```rust
/// use round_based::{MpcParty, Delivery, blocking::SpawnBlocking, PartyIndex};
///
/// # struct Msg;
/// async fn keygen<D, B>(party: MpcParty<Msg, D, B>, i: PartyIndex, n: u16)
/// where
///     D: Delivery<Msg>,
///     B: SpawnBlocking
/// {
///     // ...
/// }
/// ```
pub trait Mpc: internal::Sealed {
    /// MPC message
    type ProtocolMessage;
    /// Transport layer implementation
    type Delivery: Delivery<
        Self::ProtocolMessage,
        SendError = Self::SendError,
        ReceiveError = Self::ReceiveError,
    >;
    /// Specifies how computationally heavy tasks should be handled
    type SpawnBlocking: SpawnBlocking;

    /// Sending message error
    type SendError: Error + Send + Sync + 'static;
    /// Receiving message error
    type ReceiveError: Error + Send + Sync + 'static;

    /// Converts into [`MpcParty`]
    fn into_party(self) -> MpcParty<Self::ProtocolMessage, Self::Delivery, Self::SpawnBlocking>;
}

mod internal {
    pub trait Sealed {}
}

/// Party of MPC protocol
#[non_exhaustive]
pub struct MpcParty<M, D, B = TokioSpawnBlocking> {
    /// Defines transport layer
    pub delivery: D,
    /// Defines how computationally heavy tasks should be handled
    pub blocking: Blocking<B>,
    _msg: PhantomType<M>,
}

impl<M, D> MpcParty<M, D>
where
    M: Send + 'static,
    D: Delivery<M>,
{
    /// Party connected to the network
    ///
    /// Takes the delivery object determining how to deliver/receive other parties' messages
    pub fn connected(delivery: D) -> Self {
        Self {
            delivery,
            blocking: Blocking::new(TokioSpawnBlocking),
            _msg: PhantomType::new(),
        }
    }
}

impl<M, D, X> MpcParty<M, D, X>
where
    M: Send + 'static,
    D: Delivery<M>,
{
    /// Specifies how computationally heavy tasks are handled
    ///
    /// By default, [tokio::task::spawn_blocking] is used. You can, for instance, override it to use
    /// a thread pool.
    pub fn set_spawn_blocking<B>(self, spawn_blocking: B) -> MpcParty<M, D, B>
    where
        B: SpawnBlocking,
    {
        MpcParty {
            delivery: self.delivery,
            blocking: Blocking::new(spawn_blocking),
            _msg: self._msg,
        }
    }
}

impl<M, D, B> internal::Sealed for MpcParty<M, D, B> {}

impl<M, D, B> Mpc for MpcParty<M, D, B>
where
    D: Delivery<M>,
    D::SendError: Error + Send + Sync + 'static,
    D::ReceiveError: Error + Send + Sync + 'static,
    B: SpawnBlocking,
{
    type ProtocolMessage = M;
    type Delivery = D;
    type SpawnBlocking = B;

    type SendError = D::SendError;
    type ReceiveError = D::ReceiveError;

    fn into_party(self) -> MpcParty<Self::ProtocolMessage, Self::Delivery, Self::SpawnBlocking> {
        self
    }
}
