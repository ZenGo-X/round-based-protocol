use std::error::Error;

use futures::{Sink, Stream};

/// Networking abstraction
///
/// Basically, it's pair of channels: [`Stream`] for receiving messages, and [`Sink`] for sending
/// messages to other parties.
pub trait Delivery<M> {
    /// Outgoing delivery channel
    type Send: Sink<Outgoing<M>, Error = Self::SendError> + Unpin;
    /// Incoming delivery channel
    type Receive: Stream<Item = Result<Incoming<M>, Self::ReceiveError>> + Unpin;
    /// Error of outgoing delivery channel
    type SendError: Error;
    /// Error of incoming delivery channel
    type ReceiveError: Error;
    /// Returns a pair of incoming and outgoing delivery channels
    fn split(self) -> (Self::Receive, Self::Send);
}

/// Incoming message
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Incoming<M> {
    /// Index of a party who sent the message
    pub sender: u16,
    /// Indicates whether it's a broadcast message (meaning that this message is received by all the
    /// parties), or p2p (private message sent by `sender`)
    pub msg_type: MessageType,
    /// Received message
    pub msg: M,
}

/// Message type (broadcast or p2p)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Broadcast,
    P2P,
}

impl<M> Incoming<M> {
    /// Maps `Incoming<M>` to `Incoming<T>` by applying a function to the message body
    pub fn map<T, F>(self, f: F) -> Incoming<T>
    where
        F: FnOnce(M) -> T,
    {
        Incoming {
            sender: self.sender,
            msg_type: self.msg_type,
            msg: f(self.msg),
        }
    }

    /// Maps `Incoming<M>` to `Result<Incoming<T>, E>` by applying a function `fn(M) -> Result<T, E>`
    /// to the message body
    pub fn try_map<T, E, F>(self, f: F) -> Result<Incoming<T>, E>
    where
        F: FnOnce(M) -> Result<T, E>,
    {
        Ok(Incoming {
            sender: self.sender,
            msg_type: self.msg_type,
            msg: f(self.msg)?,
        })
    }

    /// Converts `&Incoming<M>` to `Incoming<&M>`
    pub fn as_ref(&self) -> Incoming<&M> {
        Incoming {
            sender: self.sender,
            msg_type: self.msg_type,
            msg: &self.msg,
        }
    }

    /// Checks whether it's broadcast message
    pub fn is_broadcast(&self) -> bool {
        matches!(self.msg_type, MessageType::Broadcast)
    }

    /// Checks whether it's p2p message
    pub fn is_p2p(&self) -> bool {
        matches!(self.msg_type, MessageType::P2P)
    }
}

/// Outgoing message
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Outgoing<M> {
    /// Message destination: either one party (p2p message) or all parties (broadcast message)
    pub recipient: MessageDestination,
    /// Message being sent
    pub msg: M,
}

impl<M> Outgoing<M> {
    /// Maps `Outgoing<M>` to `Outgoing<M2>` by applying a function to the message body
    pub fn map<M2, F>(self, f: F) -> Outgoing<M2>
    where
        F: FnOnce(M) -> M2,
    {
        Outgoing {
            recipient: self.recipient,
            msg: f(self.msg),
        }
    }

    /// Converts `&Outgoing<M>` to `Outgoing<&M>`
    pub fn as_ref(&self) -> Outgoing<&M> {
        Outgoing {
            recipient: self.recipient,
            msg: &self.msg,
        }
    }

    /// Checks whether it's broadcast message
    pub fn is_broadcast(&self) -> bool {
        matches!(self.recipient, MessageDestination::AllParties)
    }

    /// Checks whether it's p2p message
    pub fn is_p2p(&self) -> bool {
        matches!(self.recipient, MessageDestination::OneParty(_))
    }
}

/// Destination of an outgoing message
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageDestination {
    /// Broadcast message
    AllParties,
    /// P2P message
    OneParty(u16),
}

impl MessageDestination {
    /// Returns `true` if it's p2p message
    pub fn is_p2p(&self) -> bool {
        matches!(self, MessageDestination::OneParty(_))
    }
    /// Returns `true` if it's broadcast message
    pub fn is_broadcast(&self) -> bool {
        matches!(self, MessageDestination::AllParties)
    }
}
