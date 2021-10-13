use std::iter;

use thiserror::Error;

use crate::delivery::Incoming;
use crate::rounds::MessagesStore;

#[derive(Debug, Clone)]
pub struct RoundInput<M> {
    received: Vec<Option<M>>,
    local_msg: Option<M>,
    /// Local party index
    i: u16,
    /// Number of parties
    n: u16,
    /// Number of messages we need to receive
    left: u16,
}

impl<M> RoundInput<M> {
    pub fn new(i: u16, n: u16) -> Self {
        assert!(n >= 2, "number of parties is zero");
        assert!(i < n, "party index is not in range [0; n)");
        Self {
            received: iter::repeat_with(|| None).take(usize::from(n)).collect(),
            local_msg: None,
            i,
            n,
            left: n - 1,
        }
    }

    fn add_message(place: &mut Option<M>, msg: Incoming<M>) -> Result<(), RoundInputError> {
        match place {
            vacant @ None => {
                *vacant = Some(msg.msg);
                Ok(())
            }
            Some(_) => Err(RoundInputError::AttemptToOverwriteReceivedMsg { sender: msg.sender }),
        }
    }
}

impl<M> MessagesStore for RoundInput<M> {
    type Msg = M;
    type Error = RoundInputError;
    type Output = RoundMsgs<M>;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if msg.sender == self.i {
            Self::add_message(&mut self.local_msg, msg)
        } else {
            let sender = msg.sender;
            self.received
                .get_mut(usize::from(msg.sender))
                .map(move |place| Self::add_message(place, msg))
                .ok_or(RoundInputError::SenderIndexOutOfRange { sender, n: self.n })??;
            self.left -= 1;
            Ok(())
        }
    }

    fn wants_more(&self) -> bool {
        self.left > 0
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        if self.wants_more() {
            return Err(RoundInputError::NotEnoughMessages {
                number_of_received_msgs: self.n - 1 - self.left,
                received_own_message: self.local_msg.is_some(),
                parties_who_didnt_send_messages: (0..)
                    .zip(&self.received)
                    .filter(|(i, _)| *i != self.i)
                    .filter_map(|(i, m)| if m.is_none() { Some(i) } else { None })
                    .collect(),
            });
        }
        Ok(RoundMsgs {
            i: self.i,
            local_msg: self.local_msg,
            received: self.received,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RoundMsgs<M> {
    i: u16,
    local_msg: Option<M>,
    received: Vec<Option<M>>,
}

impl<M: PartialEq> RoundMsgs<M> {
    pub fn including_me(mut self, msg: M) -> Result<Self, RoundInputError> {
        if self.local_msg.is_some() && self.local_msg.as_ref() != Some(&msg) {
            return Err(RoundInputError::MismatchedLocalMsg);
        }
        self.received[usize::from(self.i)] = Some(msg);
        Ok(self)
    }
}

impl<M> RoundMsgs<M> {
    pub fn into_vec(self) -> Vec<M> {
        self.received.into_iter().flatten().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
#[non_exhaustive]
pub enum RoundInputError {
    #[error("party {sender} attempts to overwrite already received message")]
    AttemptToOverwriteReceivedMsg { sender: u16 },
    #[error("sender index is out of range: sender={sender}, n={n}")]
    SenderIndexOutOfRange { sender: u16, n: u16 },
    #[error("not enough messages to finish the round: waiting messages from parties {parties_who_didnt_send_messages:?}")]
    NotEnoughMessages {
        number_of_received_msgs: u16,
        received_own_message: bool,
        parties_who_didnt_send_messages: Vec<u16>,
    },
    #[error("received message sent by this party, but message doesn't match what it sent")]
    MismatchedLocalMsg,
}

#[cfg(test)]
mod tests {
    use crate::delivery::Incoming;
    use crate::rounds::MessagesStore;

    use super::{RoundInput, RoundInputError};

    #[derive(Debug, Clone, PartialEq)]
    pub struct Msg(u16);

    #[test]
    fn store_outputs_received_messages() {
        let mut store = RoundInput::<Msg>::new(3, 5);

        let msgs = (0..=4)
            .map(|s| Incoming {
                sender: s,
                msg: Msg(10 + s),
            })
            .collect::<Vec<_>>();

        for msg in &msgs {
            assert!(store.wants_more());
            store.add_message(msg.clone()).unwrap();
        }

        assert!(!store.wants_more());
        let received = store.finish().unwrap();

        // without me
        let expected = msgs
            .iter()
            .filter(|m| m.sender != 3)
            .map(|msg| msg.msg.clone())
            .collect::<Vec<_>>();
        assert_eq!(received.clone().into_vec(), expected);

        // including me
        let received = received.including_me(Msg(13)).unwrap().into_vec();
        let expected = msgs.into_iter().map(|msg| msg.msg).collect::<Vec<_>>();
        assert_eq!(received, expected);
    }

    #[test]
    fn store_returns_error_if_local_msg_doesnt_match() {
        let mut store = RoundInput::<Msg>::new(3, 5);

        let msgs = (0..=4)
            .map(|s| Incoming {
                sender: s,
                msg: Msg(10 + s),
            })
            .collect::<Vec<_>>();

        for msg in &msgs {
            assert!(store.wants_more());
            store.add_message(msg.clone()).unwrap();
        }

        assert!(!store.wants_more());
        let received = store.finish().unwrap();

        assert_eq!(
            received.including_me(Msg(13 + 1)).unwrap_err(),
            RoundInputError::MismatchedLocalMsg
        );
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
        assert_eq!(
            error,
            RoundInputError::SenderIndexOutOfRange { sender: 5, n: 5 }
        );
    }

    #[test]
    fn store_returns_error_if_incoming_msg_overwrites_already_handled_one() {
        let mut store = RoundInput::new(3, 5);
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
        assert_eq!(
            error,
            RoundInputError::AttemptToOverwriteReceivedMsg { sender: 1 }
        );
    }

    #[test]
    fn store_returns_error_if_tried_to_finish_before_receiving_enough_messages() {
        let mut store = RoundInput::<Msg>::new(3, 5);

        let msgs = (0..=3)
            .map(|s| Incoming {
                sender: s,
                msg: Msg(10 + s),
            })
            .collect::<Vec<_>>();

        let parties = vec![0, 1, 2, 4];
        for (n, msg) in (0..).zip(&msgs) {
            let error = store.clone().finish().unwrap_err();
            assert_eq!(
                error,
                RoundInputError::NotEnoughMessages {
                    number_of_received_msgs: n,
                    received_own_message: false,
                    parties_who_didnt_send_messages: parties[usize::from(n)..].to_vec(),
                }
            );

            store.add_message(msg.clone()).unwrap();
        }

        assert!(store.wants_more());
        let error = store.finish().unwrap_err();
        assert_eq!(
            error,
            RoundInputError::NotEnoughMessages {
                number_of_received_msgs: 3,
                received_own_message: true,
                parties_who_didnt_send_messages: vec![4]
            }
        );
    }
}
