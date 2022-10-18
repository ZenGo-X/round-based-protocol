//! Simple implementation of `MessagesStore`

use std::iter;

use thiserror::Error;

use crate::{Incoming, MessageType, MsgId, PartyIndex};

use super::MessagesStore;

/// Simple implementation of [MessagesStore] that waits for all parties to send a message
///
/// Round is considered complete when the store received a message from every party. Note that the
/// store will ignore all the messages such as `msg.sender == local_party_index`.
///
/// Once round is complete, it outputs [`RoundMsgs`].
///
/// ## Example
/// ```rust
/// # use round_based::rounds::{MessagesStore, simple_store::RoundInput};
/// # use round_based::{Incoming, MessageType};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut input = RoundInput::<&'static str>::broadcast(1, 3);
/// input.add_message(Incoming{
///     id: 0,
///     sender: 0,
///     msg_type: MessageType::Broadcast{ reliable: false },
///     msg: "first party message",
/// })?;
/// input.add_message(Incoming{
///     id: 1,
///     sender: 2,
///     msg_type: MessageType::Broadcast{ reliable: false },
///     msg: "third party message",
/// })?;
/// assert!(!input.wants_more());
///
/// let output = input.output().unwrap();
/// assert_eq!(output.clone().into_vec_without_me(), ["first party message", "third party message"]);
/// assert_eq!(
///     output.clone().into_vec_including_me("my msg"),
///     ["first party message", "my msg", "third party message"]
/// );
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct RoundInput<M> {
    i: PartyIndex,
    n: u16,
    messages_ids: Vec<MsgId>,
    messages: Vec<Option<M>>,
    left_messages: u16,
    expected_msg_type: MessageType,
}

/// List of received messages
#[derive(Debug, Clone)]
pub struct RoundMsgs<M> {
    i: PartyIndex,
    ids: Vec<MsgId>,
    messages: Vec<M>,
}

impl<M> RoundInput<M> {
    /// Constructs new messages store
    ///
    /// Takes index of local party `i` and amount of parties `n`
    ///
    /// ## Panics
    /// Panics if `n` is less than 2 or `i` is not in the range `[0; n)`.
    pub fn new(i: PartyIndex, n: u16, msg_type: MessageType) -> Self {
        assert!(n >= 2);
        assert!(i < n);

        Self {
            i,
            n,
            messages_ids: vec![0; usize::from(n) - 1],
            messages: iter::repeat_with(|| None)
                .take(usize::from(n) - 1)
                .collect(),
            left_messages: n - 1,
            expected_msg_type: msg_type,
        }
    }

    /// Construct a new store for broadcast messages
    ///
    /// The same as `RoundInput::new(i, n, MessageType::Broadcast{ reliable: false })`
    pub fn broadcast(i: PartyIndex, n: u16) -> Self {
        Self::new(i, n, MessageType::Broadcast { reliable: false })
    }

    /// Construct a new store for broadcast messages that must be sent over reliable channel
    ///
    /// The same as `RoundInput::new(i, n, MessageType::Broadcast{ reliable: true })`
    pub fn reliable_broadcast(i: PartyIndex, n: u16) -> Self {
        Self::new(i, n, MessageType::Broadcast { reliable: true })
    }

    /// Construct a new store for p2p messages
    ///
    /// The same as `RoundInput::new(i, n, MessageType::P2P)`
    pub fn p2p(i: PartyIndex, n: u16) -> Self {
        Self::new(i, n, MessageType::P2P)
    }
}

impl<M> MessagesStore for RoundInput<M>
where
    M: 'static,
{
    type Msg = M;
    type Output = RoundMsgs<M>;
    type Error = RoundInputError;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if msg.msg_type != self.expected_msg_type {
            return Err(RoundInputError::MismatchedMessageType {
                msg_id: msg.id,
                expected: self.expected_msg_type,
                actual: msg.msg_type,
            }
            .into());
        }
        if msg.sender == self.i {
            // Ignore own messages
            return Ok(());
        }

        let index = usize::from(if msg.sender < self.i {
            msg.sender
        } else {
            msg.sender - 1
        });

        match self.messages.get_mut(index) {
            Some(vacant @ None) => {
                *vacant = Some(msg.msg);
                self.messages_ids[index] = msg.id;
                self.left_messages -= 1;
                Ok(())
            }
            Some(Some(_)) => Err(RoundInputError::AttemptToOverwriteReceivedMsg {
                msgs_ids: [self.messages_ids[index], msg.id],
                sender: msg.sender,
            }
            .into()),
            None => Err(RoundInputError::SenderIndexOutOfRange {
                msg_id: msg.id,
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
                ids: self.messages_ids,
                messages: self.messages.into_iter().flatten().collect(),
            })
        }
    }
}

impl<M> RoundMsgs<M> {
    /// Returns vec of `n-1` received messages
    ///
    /// Messages appear in the list in ascending order of sender index. E.g. for n=4 and local party index i=2,
    /// the list would look like: `[{msg from i=0}, {msg from i=1}, {msg from i=3}]`.
    pub fn into_vec_without_me(self) -> Vec<M> {
        self.messages
    }

    /// Returns vec of received messages plus party's own message
    ///
    /// Similar to `into_vec_without_me`, but inserts `my_msg` at position `i` in resulting list. Thus, i-th
    /// message in the list was received from i-th party.
    pub fn into_vec_including_me(mut self, my_msg: M) -> Vec<M> {
        self.messages.insert(usize::from(self.i), my_msg);
        self.messages
    }

    /// Returns iterator over messages with sender indexes
    ///
    /// Iterator yields `(msg_id, sender_index, message)`
    pub fn into_iter_indexed(self) -> impl Iterator<Item = (MsgId, PartyIndex, M)> {
        let indexes = (0..self.i).chain(self.i + 1..);
        self.ids
            .into_iter()
            .zip(indexes)
            .zip(self.messages)
            .map(|((id, party_ind), msg)| (id, party_ind, msg))
    }

    /// Returns iterator over messages with sender indexes
    ///
    /// Iterator yields `(msg_id, sender_index, &message)`
    pub fn iter_indexed(&self) -> impl Iterator<Item = (MsgId, PartyIndex, &M)> {
        let indexes = (0..self.i).chain(self.i + 1..);
        self.ids
            .iter()
            .zip(indexes)
            .zip(&self.messages)
            .map(|((id, party_ind), msg)| (*id, party_ind, msg))
    }
}

/// Error explaining why `RoundInput` wasn't able to process a message
#[derive(Debug, Error)]
pub enum RoundInputError {
    /// Party sent two messages in one round
    ///
    /// `msgs_ids` are ids of conflicting messages
    #[error("party {sender} tried to overwrite message")]
    AttemptToOverwriteReceivedMsg {
        msgs_ids: [MsgId; 2],
        sender: PartyIndex,
    },
    /// Unknown sender
    ///
    /// This error is thrown when index of sender is not in `[0; n)` where `n` is number of
    /// parties involved in the protocol (provided in [`RoundInput::new`])
    #[error("sender index is out of range: sender={sender}, n={n}")]
    SenderIndexOutOfRange {
        msg_id: MsgId,
        sender: PartyIndex,
        n: u16,
    },
    /// Received message type doesn't match expectations
    ///
    /// For instance, this error is returned when it's expected to receive broadcast message,
    /// but party sent p2p message instead (which is rough protocol violation).
    #[error("expected message {expected:?}, got {actual:?}")]
    MismatchedMessageType {
        msg_id: MsgId,
        expected: MessageType,
        actual: MessageType,
    },
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;

    use crate::rounds::store::MessagesStore;
    use crate::{Incoming, MessageType};

    use super::{RoundInput, RoundInputError};

    #[derive(Debug, Clone, PartialEq)]
    pub struct Msg(u16);

    #[test]
    fn store_outputs_received_messages() {
        let mut store = RoundInput::<Msg>::new(3, 5, MessageType::P2P);

        let msgs = (0..5)
            .map(|s| Incoming {
                id: s.into(),
                sender: s,
                msg_type: MessageType::P2P,
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
        let mut store = RoundInput::new(3, 5, MessageType::P2P);
        let error = store
            .add_message(Incoming {
                id: 0,
                sender: 5,
                msg_type: MessageType::P2P,
                msg: Msg(123),
            })
            .unwrap_err();
        assert_matches!(
            error,
            RoundInputError::SenderIndexOutOfRange { msg_id, sender, n } if msg_id == 0 && sender == 5 && n == 5
        );
    }

    #[test]
    fn store_returns_error_if_incoming_msg_overwrites_already_received_one() {
        let mut store = RoundInput::new(0, 3, MessageType::P2P);
        store
            .add_message(Incoming {
                id: 0,
                sender: 1,
                msg_type: MessageType::P2P,
                msg: Msg(11),
            })
            .unwrap();
        let error = store
            .add_message(Incoming {
                id: 1,
                sender: 1,
                msg_type: MessageType::P2P,
                msg: Msg(112),
            })
            .unwrap_err();
        assert_matches!(error, RoundInputError::AttemptToOverwriteReceivedMsg { msgs_ids, sender } if msgs_ids[0] == 0 && msgs_ids[1] == 1 && sender == 1);
        store
            .add_message(Incoming {
                id: 2,
                sender: 2,
                msg_type: MessageType::P2P,
                msg: Msg(22),
            })
            .unwrap();

        let output = store.output().unwrap().into_vec_without_me();
        assert_eq!(output, [Msg(11), Msg(22)]);
    }

    #[test]
    fn store_returns_error_if_tried_to_output_before_receiving_enough_messages() {
        let mut store = RoundInput::<Msg>::new(3, 5, MessageType::P2P);

        let msgs = (0..5)
            .map(|s| Incoming {
                id: s.into(),
                sender: s,
                msg_type: MessageType::P2P,
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

    #[test]
    fn store_returns_error_if_message_type_mismatched() {
        let mut store = RoundInput::<Msg>::p2p(3, 5);
        let err = store
            .add_message(Incoming {
                id: 0,
                sender: 0,
                msg_type: MessageType::Broadcast { reliable: false },
                msg: Msg(1),
            })
            .unwrap_err();
        assert_matches!(
            err,
            RoundInputError::MismatchedMessageType {
                msg_id: 0,
                expected: MessageType::P2P,
                actual: MessageType::Broadcast { reliable: false }
            }
        );

        let mut store = RoundInput::<Msg>::broadcast(3, 5);
        let err = store
            .add_message(Incoming {
                id: 0,
                sender: 0,
                msg_type: MessageType::P2P,
                msg: Msg(1),
            })
            .unwrap_err();
        assert_matches!(
            err,
            RoundInputError::MismatchedMessageType {
                msg_id: 0,
                expected: MessageType::Broadcast { reliable: false },
                actual: MessageType::P2P,
            }
        );
        store
            .add_message(Incoming {
                id: 0,
                sender: 0,
                msg_type: MessageType::Broadcast { reliable: true },
                msg: Msg(1),
            })
            .unwrap();

        let mut store = RoundInput::<Msg>::reliable_broadcast(3, 5);
        let err = store
            .add_message(Incoming {
                id: 0,
                sender: 0,
                msg_type: MessageType::Broadcast { reliable: false },
                msg: Msg(1),
            })
            .unwrap_err();
        assert_matches!(
            err,
            RoundInputError::MismatchedMessageType {
                msg_id: 0,
                expected: MessageType::Broadcast { reliable: false },
                actual: MessageType::P2P,
            }
        );
        store
            .add_message(Incoming {
                id: 0,
                sender: 0,
                msg_type: MessageType::Broadcast { reliable: true },
                msg: Msg(1),
            })
            .unwrap();
    }
}
