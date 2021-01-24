//! Containers convenient for implementing [StateMachine](crate::StateMachine) trait

pub mod push;

mod broadcast;
mod p2p;
mod store_err;
mod traits;

pub use broadcast::*;
pub use p2p::*;
pub use store_err::*;
pub use traits::*;

pub type Store<C> = <C as MessageContainer>::Store;
