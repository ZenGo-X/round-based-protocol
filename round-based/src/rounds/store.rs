use std::iter;
use thiserror::Error;

use crate::Incoming;

/// Stores messages received at particular round
///
/// In MPC protocol, party at every round usually needs to receive and handle up to `n` messages.
/// It also needs to validate input in case if any party tries to cheat. All this logic should
/// be encapsulated inside `MessagesStore` trait implementation.
///
/// Every received message should be handled by calling [`.add_message(msg)`] method. Once store
/// indicates that it received all needed message (see [`.wants_more()`] method), you can obtain
/// output by calling [`.output()`] method. Usually, output is a `Vec<_>` of received messages.
///
/// [`.add_message(msg)`]: Self::add_message
/// [`.wants_more()`]: Self::wants_more
/// [`.output()`]: Self::output
pub trait MessagesStore: Sized + 'static {
    /// Message type
    type Msg;
    /// Store output (i.e. `Vec<_>` of received messages)
    type Output;
    /// Store error
    type Error;

    /// Adds received message to the store
    ///
    /// Returns error if message is invalid. Usually it means that party behaves maliciously.
    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error>;
    /// Indicates if store expects more messages to receive
    fn wants_more(&self) -> bool;
    /// Retrieves store output if enough messages are received
    ///
    /// Returns `Err(self)` if more message are needed to be received.
    ///
    /// If store indicated that it needs no more messages (ie `store.wants_more() == false`), then
    /// this function must return `Ok(_)`.
    fn output(self) -> Result<Self::Output, Self>;
}

/// Message of MPC protocol
///
/// MPC protocols typically consist of several rounds, so protocol message carries a number of the round
/// plus [round message](RoundMessage)
///
/// ## Example
/// Protocol message can be naturally represented as an enum:
///
/// ```rust
/// # pub struct Msg1;
/// # pub struct Msg2;
/// #
/// # use round_based::ProtocolMessage;
///
/// pub enum Message {
///     Round1(Msg1),
///     Round2(Msg2),
///     // ...
/// }
///
/// impl ProtocolMessage for Message {
///     fn round(&self) -> u16 {
///         match self {
///             Message::Round1(_) => 1,
///             Message::Round2(_) => 2,
///             // ...
///         }
///     }
/// }
/// ```
///
/// This implementation can be automatically derived (if you enabled `derive` feature):
/// ```rust
/// # pub struct Msg1;
/// # pub struct Msg2;
/// #
/// # use round_based::ProtocolMessage;
///
/// #[derive(ProtocolMessage)]
/// pub enum Message {
///     Round1(Msg1),
///     Round2(Msg2),
///     // ...
/// }
/// ```
pub trait ProtocolMessage: Sized {
    /// Number of round this message originates from
    fn round(&self) -> u16;
}

/// Round message
///
/// As said in [`ProtocolMessage trait`] documentation, it carries round number + round message.
/// While `ProtocolMessage` trait only allows you to retrieve number of the round (using [`.round()`]
/// method), this trait lets you obtain the message itself (using [from_protocol_message] constructor).
///
/// [`ProtocolMessage trait`]: ProtocolMessage
/// [`.round()`]: ProtocolMessage::round
/// [from_protocol_message]: Self::from_protocol_message
///
/// ## Example
/// Protocol message can be naturally represented as an enum:
///
/// ```rust
/// # use round_based::rounds::store::{ProtocolMessage, RoundMessage};
/// #
/// pub enum Message {
///     Round1(Msg1),
///     Round2(Msg2),
///     // ...
/// }
///
/// pub struct Msg1 { /* ... */ }
/// pub struct Msg2 { /* ... */ }
///
/// impl ProtocolMessage for Message {
///     fn round(&self) -> u16 {
///         match self {
///             Message::Round1(_) => 1,
///             Message::Round2(_) => 2,
///             // ...
///         }  
///     }
/// }
/// impl RoundMessage<Msg1> for Message {
///     const ROUND: u16 = 1;
///     fn to_protocol_message(round_message: Msg1) -> Self {
///         Message::Round1(round_message)
///     }
///     fn from_protocol_message(protocol_message: Self) -> Result<Msg1, Self> {
///         match protocol_message {
///             Message::Round1(msg) => Ok(msg),
///             msg => Err(msg),
///         }
///     }
/// }
/// impl RoundMessage<Msg2> for Message {
///     const ROUND: u16 = 2;
///     fn to_protocol_message(round_message: Msg2) -> Self {
///         Message::Round2(round_message)
///     }
///     fn from_protocol_message(protocol_message: Self) -> Result<Msg2, Self> {
///         match protocol_message {
///             Message::Round2(msg) => Ok(msg),
///             msg => Err(msg),
///         }
///     }
/// }
/// ```
///
/// This implementation can be automatically derived (if you enabled `derive` feature):
/// ```rust
/// # use round_based::ProtocolMessage;
///
/// #[derive(ProtocolMessage)]
/// pub enum Message {
///     Round1(Msg1),
///     Round2(Msg2),
///     // ...
/// }
///
/// pub struct Msg1 { /* ... */ }
/// pub struct Msg2 { /* ... */ }
/// ```
pub trait RoundMessage<M>: ProtocolMessage {
    /// Number of the round this message belongs to
    const ROUND: u16;

    /// Converts round message into protocol message (never fails)
    fn to_protocol_message(round_message: M) -> Self;
    /// Extracts round message from protocol message
    ///
    /// Returns `Err(protocol_message)` if `protocol_message.round() != Self::ROUND`, otherwise
    /// returns `Ok(round_message)`
    fn from_protocol_message(protocol_message: Self) -> Result<M, Self>;
}

/// Simple implementation of [MessagesStore] that waits for all parties to send a message
///
/// Round is considered complete when the store received a message from every party. Note that the
/// store will ignore all the messages sent by local party.
///
///
/// ## Example
/// ```rust
/// # use round_based::rounds::store::{MessagesStore, RoundInput};
/// # use round_based::Incoming;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut input = RoundInput::<&'static str>::new(1, 3);
/// input.add_message(Incoming{ sender: 0, msg: "first party message" })?;
/// input.add_message(Incoming{ sender: 2, msg: "third party message" })?;
/// assert!(!input.wants_more());
///
/// let output = input.output().unwrap();
/// assert_eq!(output.clone().into_vec_without_me(), ["first party message", "third party message"]);
/// assert_eq!(output.clone().into_vec_including_me("my msg"), ["first party message", "my msg", "third party message"]);
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct RoundInput<M> {
    i: u16,
    n: u16,
    messages: Vec<Option<M>>,
    left_messages: u16,
}

#[derive(Debug, Clone)]
pub struct RoundMsgs<M> {
    i: u16,
    messages: Vec<M>,
}

impl<M> RoundInput<M> {
    /// Constructs new messages store
    ///
    /// Takes index of local party `i` and amount of parties `n`
    ///
    /// ## Panics
    /// Panics if `n` is less than 2 or `i` is not in the range `[0; n)`.
    pub fn new(i: u16, n: u16) -> Self {
        assert!(n >= 2);
        assert!(i < n);

        Self {
            i,
            n,
            messages: iter::repeat_with(|| None)
                .take(usize::from(n) - 1)
                .collect(),
            left_messages: n - 1,
        }
    }
}

impl<M> MessagesStore for RoundInput<M>
where
    M: 'static,
{
    type Msg = M;
    type Output = RoundMsgs<M>;
    type Error = Error;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if msg.sender == self.i {
            // Ignore own messages
            return Ok(());
        }

        let index = if msg.sender < self.i {
            msg.sender
        } else {
            msg.sender - 1
        };

        match self.messages.get_mut(usize::from(index)) {
            Some(vacant @ None) => {
                *vacant = Some(msg.msg);
                self.left_messages -= 1;
                Ok(())
            }
            Some(Some(_)) => {
                Err(Reason::AttemptToOverwriteReceivedMsg { sender: msg.sender }.into())
            }
            None => Err(Reason::SenderIndexOutOfRange {
                sender: msg.sender,
                n: self.n,
            }
            .into()),
        }
    }

    fn wants_more(&self) -> bool {
        self.left_messages > 0
    }

    fn output(self) -> Result<Self::Output, Self> {
        if self.left_messages > 0 {
            Err(self)
        } else {
            Ok(RoundMsgs {
                i: self.i,
                messages: self.messages.into_iter().flatten().collect(),
            })
        }
    }
}

impl<M> RoundMsgs<M> {
    pub fn into_vec_without_me(self) -> Vec<M> {
        self.messages
    }

    pub fn into_vec_including_me(mut self, my_msg: M) -> Vec<M> {
        self.messages.insert(usize::from(self.i), my_msg);
        self.messages
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("party {sender} tries to overwrite message")]
    AttemptToOverwriteReceivedMsg { sender: u16 },
    #[error("sender index is out of range: sender={sender}, n={n}")]
    SenderIndexOutOfRange { sender: u16, n: u16 },
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;

    use crate::rounds::store::MessagesStore;
    use crate::Incoming;

    use super::{Error, Reason, RoundInput};

    #[derive(Debug, Clone, PartialEq)]
    pub struct Msg(u16);

    #[test]
    fn store_outputs_received_messages() {
        let mut store = RoundInput::<Msg>::new(3, 5);

        let msgs = (0..5)
            .map(|s| Incoming {
                sender: s,
                msg: Msg(10 + s),
            })
            .filter(|incoming| incoming.sender != 3)
            .collect::<Vec<_>>();

        for msg in &msgs {
            assert!(store.wants_more());
            store.add_message(msg.clone()).unwrap();
        }

        assert!(!store.wants_more());
        let received = store.output().unwrap();

        // without me
        let msgs: Vec<_> = msgs.into_iter().map(|msg| msg.msg).collect();
        assert_eq!(received.clone().into_vec_without_me(), msgs);

        // including me
        let received = received.into_vec_including_me(Msg(13));
        assert_eq!(received[0..3], msgs[0..3]);
        assert_eq!(received[3], Msg(13));
        assert_eq!(received[4..5], msgs[3..4]);
    }

    #[test]
    fn store_returns_error_if_sender_index_is_out_of_range() {
        let mut store = RoundInput::new(3, 5);
        let error = store
            .add_message(Incoming {
                sender: 5,
                msg: Msg(123),
            })
            .unwrap_err();
        assert_matches!(
            error,
            Error(Reason::SenderIndexOutOfRange { sender, n }) if sender == 5 && n == 5
        );
    }

    #[test]
    fn store_returns_error_if_incoming_msg_overwrites_already_received_one() {
        let mut store = RoundInput::new(0, 3);
        store
            .add_message(Incoming {
                sender: 1,
                msg: Msg(11),
            })
            .unwrap();
        let error = store
            .add_message(Incoming {
                sender: 1,
                msg: Msg(112),
            })
            .unwrap_err();
        assert_matches!(error, Error(Reason::AttemptToOverwriteReceivedMsg { sender }) if sender == 1);
        store
            .add_message(Incoming {
                sender: 2,
                msg: Msg(22),
            })
            .unwrap();

        let output = store.output().unwrap().into_vec_without_me();
        assert_eq!(output, [Msg(11), Msg(22)]);
    }

    #[test]
    fn store_returns_error_if_tried_to_output_before_receiving_enough_messages() {
        let mut store = RoundInput::<Msg>::new(3, 5);

        let msgs = (0..5)
            .map(|s| Incoming {
                sender: s,
                msg: Msg(10 + s),
            })
            .filter(|incoming| incoming.sender != 3);

        for msg in msgs {
            assert!(store.wants_more());
            store = store.output().unwrap_err();

            store.add_message(msg).unwrap();
        }

        let _ = store.output().unwrap();
    }
}
