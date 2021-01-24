//! Useful development utils

#[cfg(feature = "async-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-runtime")))]
mod async_simulation;
mod simulation;

#[cfg(feature = "async-runtime")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-runtime")))]
pub use async_simulation::*;
pub use simulation::*;
