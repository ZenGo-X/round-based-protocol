use thiserror::Error;

/// Common error type for [MessageStore](super::MessageStore) implementations in this crate
#[derive(Debug, PartialEq, Error)]
#[non_exhaustive]
pub enum StoreErr {
    /// Got message which was already received (no matter how similar they are)
    #[error("got message which was already received")]
    MsgOverwrite,
    /// Got message from unknown party
    #[error("unknown message sender: {sender}")]
    UnknownSender { sender: u16 },
    /// Got broadcast message, whereas P2P message is expected
    #[error("unexpected broadcast message (P2P is expected)")]
    ExpectedP2P,
    /// Got P2P message, whereas broadcast message is expected
    #[error("unexpected P2P message (broadcast is expected)")]
    ExpectedBroadcast,
    /// Got message that addressed to another party (`msg.receiver != me`)
    #[error("got message which was addressed to someone else")]
    NotForMe,
    /// Got message which sent by this party
    #[error("got message which was sent by this party")]
    ItsFromMe,
    /// Called [finish](super::MessageStore::finish), but more messages are wanted
    #[error("more messages are expected to receive")]
    WantsMoreMessages,
}
