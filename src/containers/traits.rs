use crate::sm::Msg;

/// Message container holding received messages
///
/// Trait only purpose is to pin [MessageStore] constructing this container
pub trait MessageContainer {
    type Store: MessageStore;
}

/// Accumulates messages received from other parties
///
/// StateMachine implementations need to handle incoming messages: they need to store messages
/// somewhere until sufficient messages received, incoming messages needs to be pre-validated
/// (haven't we received message from this party at this round? is it a p2p message, as we expected?
/// and so on). MessageStore encapsulates all this boilerplate.
pub trait MessageStore {
    /// Message body
    type M;
    /// Error type
    type Err;
    /// Resulting messages container holding received messages
    type Output;

    /// Pushes received message to store
    ///
    /// Might result in error if pre-validation failed. However, it does not
    /// prevent MessageStore from accepting further messages.
    fn push_msg(&mut self, msg: Msg<Self::M>) -> Result<(), Self::Err>;
    /// Indicates if store contains message from this party
    fn contains_msg_from(&self, sender: u16) -> bool;
    /// Indicates whether store needs more messages to receive
    fn wants_more(&self) -> bool;
    /// Returns resulting messages container
    ///
    /// Returns error if store needs more messages (see [wants_more](Self::wants_more)).
    fn finish(self) -> Result<Self::Output, Self::Err>;
    /// Retrieve uncooperative parties
    ///
    /// Returns how many more messages we expected to receive and list of parties who didn't send
    /// a message
    fn blame(&self) -> (u16, Vec<u16>);
}
