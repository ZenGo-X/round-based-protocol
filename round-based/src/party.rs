use std::error::Error;

use phantom_type::PhantomType;

use crate::blocking::{Blocking, SpawnBlocking, TokioSpawnBlocking};
use crate::delivery::Delivery;

pub trait Mpc: internal::Sealed {
    type ProtocolMessage: Send + 'static;
    type Delivery: Delivery<
        Self::ProtocolMessage,
        SendError = Self::SendError,
        ReceiveError = Self::ReceiveError,
    >;
    type SpawnBlocking: SpawnBlocking;

    type SendError: Error;
    type ReceiveError: Error + Send + Sync + Unpin + 'static;

    fn into_party(self) -> MpcParty<Self::ProtocolMessage, Self::Delivery, Self::SpawnBlocking>;
}

mod internal {
    pub trait Sealed {}
}

#[non_exhaustive]
pub struct MpcParty<M, D, B = TokioSpawnBlocking> {
    pub delivery: D,
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
    /// Overrides the way how protocol will spawn blocking tasks
    ///
    /// By default, [tokio::task::spawn_blocking] is used. You can, for instance, override it to use
    /// a thread pool.
    pub fn override_spawn_blocking<B>(self, spawn_blocking: B) -> MpcParty<M, D, B>
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
    M: Send + 'static,
    D: Delivery<M>,
    D::SendError: Error,
    D::ReceiveError: Error + Send + Sync + Unpin + 'static,
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
