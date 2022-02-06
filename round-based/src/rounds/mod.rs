pub mod round_input;
pub mod rounds;

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
    /// Store output (usually, `Vec<_>` of received messages)
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
/// use round_based::ProtocolMessage;
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
/// use round_based::ProtocolMessage;
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
/// use round_based::{ProtocolMessage, RoundMessage};
///
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
/// use round_based::ProtocolMessage;
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
    /// returns `Ok(_)`
    fn from_protocol_message(protocol_message: Self) -> Result<M, Self>;
}
