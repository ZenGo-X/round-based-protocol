use std::time::Duration;

use serde::{Deserialize, Serialize};

/// State machine of party involved in round-based protocol
pub trait StateMachine {
    /// Body of transmitting messages
    ///
    /// Actual type of transmitting messages will be `Msg<SM::MessageBody>` (see [Msg struct](Msg))
    type MessageBody;
    /// Error type used by StateMachine
    ///
    /// Errors are divided on critical and not critical to follow different error-handling strategies
    /// on appearing one of them. For more details, see method returning `Result`s, e.g.
    /// [handle_incoming](Self::handle_incoming) or [proceed](Self::proceed)
    type Err: IsCritical;
    /// Output of the protocol if it successfully terminates
    type Output;

    /// Process received message
    ///
    /// ## Returns
    /// Handling message might result in error, but it doesn't mean that computation should
    /// be aborted. Returned error needs to be examined whether it critical or not (by calling
    /// [is_critical](IsCritical::is_critical) method).
    ///
    /// If occurs:
    /// * Critical error: protocol must be aborted
    /// * Non-critical error: it should be reported, but protocol must continue
    ///
    /// Example of non-critical error is receiving message which we didn't expect to see. It could
    /// be either network lag or bug in implementation or attempt to sabotage the protocol, but
    /// protocol might be resistant to this, so it still has a chance to successfully complete.
    ///
    /// ## Blocking
    /// This method should not block or perform expensive computation. E.g. it might do
    /// deserialization (if needed) or cheap checks.
    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err>;

    /// Queue of messages to be sent
    ///
    /// New messages can be appended to queue only as result of calling
    /// [proceed](StateMachine::proceed) or [handle_incoming](StateMachine::handle_incoming) methods.
    ///
    /// Messages can be sent in any order. After message is sent, it should be deleted from the queue.
    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>>;

    /// Indicates whether StateMachine wants to perform some expensive computation
    fn wants_to_proceed(&self) -> bool;

    /// Performs some expensive computation
    ///
    /// If [`StateMachine`] is executed at green thread (in async environment), it will be typically
    /// moved to dedicated thread at thread pool before calling `.proceed()` method.
    ///
    /// ## Returns
    /// Returns `Ok(())` if either computation successfully completes or computation was not
    /// required (i.e. `self.wants_to_proceed() == false`).
    ///
    /// If it returns `Err(err)`, then `err` is examined whether it's critical or not (by
    /// calling [is_critical](IsCritical::is_critical) method).
    ///
    /// If occurs:
    /// * Critical error: protocol must be aborted
    /// * Non-critical error: it should be reported, but protocol must continue
    ///
    /// For example, in `.proceed()` at verification stage we could find some party trying to
    /// sabotage the protocol, but protocol might be designed to be resistant to such attack, so
    /// it's not a critical error, but obviously it should be reported.
    fn proceed(&mut self) -> Result<(), Self::Err>;

    /// Deadline for a particular round
    ///
    /// After reaching deadline (if set) [round_timeout_reached](Self::round_timeout_reached)
    /// will be called.
    ///
    /// After proceeding on the next round (increasing [current_round](Self::current_round)),
    /// timer will be reset, new timeout will be requested (by calling this method), and new
    /// deadline will be set.
    fn round_timeout(&self) -> Option<Duration>;

    /// Method is triggered after reaching [round_timeout](Self::round_timeout)
    ///
    /// Reaching timeout always aborts computation, no matter what error is returned: critical or not.
    fn round_timeout_reached(&mut self) -> Self::Err;

    /// Indicates whether protocol is finished and output can be obtained by calling
    /// [pick_output](Self::pick_output) method.
    fn is_finished(&self) -> bool;

    /// Obtains protocol output
    ///
    /// ## Returns
    /// * `None`, if protocol is not finished yet
    ///   i.e. `protocol.is_finished() == false`
    /// * `Some(Err(_))`, if protocol terminated with error
    /// * `Some(Ok(_))`, if protocol successfully terminated
    ///
    /// After `Some(_)` has been obtained via this method, StateMachine must be utilized (dropped).
    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>>;

    /// Sequential number of current round
    ///
    /// Can be increased by 1 as result of calling either [proceed](StateMachine::proceed) or
    /// [handle_incoming](StateMachine::handle_incoming) methods. Changing round number in any other way
    /// (or in any other method) might cause strange behaviour.
    fn current_round(&self) -> u16;

    /// Total amount of rounds (if known)
    fn total_rounds(&self) -> Option<u16>;

    /// Index of this party
    ///
    /// Must be in interval `[1; n]` where `n = self.parties()`
    fn party_ind(&self) -> u16;
    /// Number of parties involved in computation
    fn parties(&self) -> u16;
}

/// Represent a message transmitting between parties on wire
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Msg<B> {
    /// Index of the sender
    ///
    /// Lies in range `[1; n]` where `n` is number of parties involved in computation
    pub sender: u16,
    /// Index of receiver
    ///
    /// `None` indicates that it's broadcast message. Receiver index, if set, lies in range `[1; n]`
    /// where `n` is number of parties involved in computation
    pub receiver: Option<u16>,
    /// Message body
    pub body: B,
}

impl<B> Msg<B> {
    /// Applies closure to message body
    pub fn map_body<T, F>(self, f: F) -> Msg<T>
    where
        F: FnOnce(B) -> T,
    {
        Msg {
            sender: self.sender,
            receiver: self.receiver,
            body: f(self.body),
        }
    }
}

/// Distinguish a critical error from not critical
///
/// For semantic, see [StateMachine trait](StateMachine) (in particular,
/// [handle_incoming](StateMachine::handle_incoming) and [proceed](StateMachine::proceed)
/// methods)
pub trait IsCritical {
    /// Indicates whether an error critical or not
    fn is_critical(&self) -> bool;
}
