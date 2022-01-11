//! # Messages delivery
//!
//! In this module we provide traits determining a way of exchanging messages between parties. Prior to
//! carrying out any protocol, you typically need to obtain an instance of [`Delivery`] trait, basically
//! it's a pair of delivery channels of incoming and outgoing messages.
//!
//! Receiving channel (or channel of incoming messages) is a [`Stream`], quite popular asynchronous
//! abstraction. Sending channel (or channel of outgoing messages) is defined with [`Sink`]
//! trait.
//!
//! We provide several delivery implementations for most common cases. See [two_party] module.

#[doc(inline)]
pub use delivery_core::*;

#[cfg(feature = "two-party")]
pub mod two_party {
    pub use two_party_delivery::*;
}
