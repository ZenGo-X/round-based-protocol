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

use std::error::Error;

use futures::{Sink, Stream};

/// A pair of incoming and outgoing delivery channels
pub trait Delivery<M> {
    /// Outgoing delivery channel
    type Send: Sink<Outgoing<M>, Error = Self::SendError> + Send + Unpin;
    /// Incoming delivery channel
    type Receive: Stream<Item = Result<Incoming<M>, Self::ReceiveError>> + Send + Unpin + 'static;
    /// Error of outgoing delivery channel
    type SendError: Error;
    /// Error of incoming delivery channel
    type ReceiveError: Error + Send + 'static;
    /// Returns a pair of incoming and outgoing delivery channels
    fn split(self) -> (Self::Receive, Self::Send);
}

/// Incoming message
///
/// Contains a received message and index of party who sent the message
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Incoming<M> {
    /// Index of a party who sent the message
    pub sender: u16,
    /// Received message
    pub msg: M,
}

impl<M> Incoming<M> {
    pub fn map<M2, F>(self, f: F) -> Incoming<M2>
    where
        F: FnOnce(M) -> M2,
    {
        Incoming {
            sender: self.sender,
            msg: f(self.msg),
        }
    }

    pub fn as_ref(&self) -> Incoming<&M> {
        Incoming {
            sender: self.sender,
            msg: &self.msg,
        }
    }
}

/// Outgoing message
///
/// Contains a message that local party needs to send, and index of recipient party (`None` if it's
/// broadcast message)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Outgoing<M> {
    /// Index of recipient
    ///
    /// `None` if the message is meant to be received by all the parties (ie. it's broadcast message)
    pub recipient: Option<u16>,
    /// Message being sent
    pub msg: M,
}

impl<M> Outgoing<M> {
    pub fn map<M2, F>(self, f: F) -> Outgoing<M2>
    where
        F: FnOnce(M) -> M2,
    {
        Outgoing {
            recipient: self.recipient,
            msg: f(self.msg),
        }
    }

    pub fn as_ref(&self) -> Outgoing<&M> {
        Outgoing {
            recipient: self.recipient,
            msg: &self.msg,
        }
    }
}
