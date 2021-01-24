use std::cmp::Ordering;
use std::ops;

use crate::sm::Msg;

use super::store_err::StoreErr;
use super::traits::{MessageContainer, MessageStore};

/// Received broadcast messages from every protocol participant
#[derive(Debug)]
pub struct BroadcastMsgs<B> {
    my_ind: u16,
    msgs: Vec<B>,
}

impl<B> BroadcastMsgs<B>
where
    B: 'static,
{
    /// Turns a container into iterator of messages with parties indexes (1 <= i <= n)
    pub fn into_iter_indexed(self) -> impl Iterator<Item = (u16, B)> {
        let my_ind = usize::from(self.my_ind);
        let ind = move |i| {
            if i < my_ind - 1 {
                i as u16 + 1
            } else {
                i as u16 + 2
            }
        };
        self.msgs
            .into_iter()
            .enumerate()
            .map(move |(i, m)| (ind(i), m))
    }

    /// Turns container into vec of `n-1` messages
    pub fn into_vec(self) -> Vec<B> {
        self.msgs
    }

    /// Turns container into vec of `n` messages (where given message lies at index `party_i-1`)
    pub fn into_vec_including_me(mut self, me: B) -> Vec<B> {
        self.msgs.insert(self.my_ind as usize - 1, me);
        self.msgs
    }
}

impl<B> ops::Index<u16> for BroadcastMsgs<B> {
    type Output = B;

    /// Takes party index i and returns received message (1 <= i <= n)
    ///
    /// ## Panics
    /// Panics if there's no party with index i (or it's your party index)
    fn index(&self, index: u16) -> &Self::Output {
        match Ord::cmp(&index, &(self.my_ind - 1)) {
            Ordering::Less => &self.msgs[usize::from(index)],
            Ordering::Greater => &self.msgs[usize::from(index - 1)],
            Ordering::Equal => panic!("accessing own broadcasted msg"),
        }
    }
}

impl<B> IntoIterator for BroadcastMsgs<B> {
    type Item = B;
    type IntoIter = <Vec<B> as IntoIterator>::IntoIter;

    /// Returns messages in ascending party's index order
    fn into_iter(self) -> Self::IntoIter {
        self.msgs.into_iter()
    }
}

impl<M> MessageContainer for BroadcastMsgs<M> {
    type Store = BroadcastMsgsStore<M>;
}

/// Receives broadcast messages from every protocol participant
pub struct BroadcastMsgsStore<M> {
    party_i: u16,
    msgs: Vec<Option<M>>,
    msgs_left: usize,
}

impl<M> BroadcastMsgsStore<M> {
    /// Constructs store. Takes this party index and total number of parties.
    pub fn new(party_i: u16, parties_n: u16) -> Self {
        let parties_n = usize::from(parties_n);
        Self {
            party_i,
            msgs: std::iter::repeat_with(|| None)
                .take(parties_n - 1)
                .collect(),
            msgs_left: parties_n - 1,
        }
    }

    /// Amount of received messages so far
    pub fn messages_received(&self) -> usize {
        self.msgs.len() - self.msgs_left
    }
    /// Total amount of wanted messages (n-1)
    pub fn messages_total(&self) -> usize {
        self.msgs.len()
    }
}

impl<M> MessageStore for BroadcastMsgsStore<M> {
    type M = M;
    type Err = StoreErr;
    type Output = BroadcastMsgs<M>;

    fn push_msg(&mut self, msg: Msg<Self::M>) -> Result<(), Self::Err> {
        if msg.sender == 0 {
            return Err(StoreErr::UnknownSender { sender: msg.sender });
        }
        if msg.receiver.is_some() {
            return Err(StoreErr::ExpectedBroadcast);
        }
        let party_j = match Ord::cmp(&msg.sender, &self.party_i) {
            Ordering::Less => usize::from(msg.sender),
            Ordering::Greater => usize::from(msg.sender) - 1,
            Ordering::Equal => return Err(StoreErr::ItsFromMe),
        };
        let slot = self
            .msgs
            .get_mut(party_j - 1)
            .ok_or(StoreErr::UnknownSender { sender: msg.sender })?;
        if slot.is_some() {
            return Err(StoreErr::MsgOverwrite);
        }
        *slot = Some(msg.body);
        self.msgs_left -= 1;

        Ok(())
    }

    fn contains_msg_from(&self, sender: u16) -> bool {
        let party_j = match Ord::cmp(&sender, &self.party_i) {
            Ordering::Less => usize::from(sender),
            Ordering::Greater => usize::from(sender) - 1,
            Ordering::Equal => return false,
        };
        match self.msgs.get(party_j - 1) {
            None => false,
            Some(None) => false,
            Some(Some(_)) => true,
        }
    }

    fn wants_more(&self) -> bool {
        self.msgs_left > 0
    }

    fn finish(self) -> Result<Self::Output, Self::Err> {
        if self.msgs_left > 0 {
            return Err(StoreErr::WantsMoreMessages);
        }
        Ok(BroadcastMsgs {
            my_ind: self.party_i,
            msgs: self.msgs.into_iter().map(Option::unwrap).collect(),
        })
    }

    fn blame(&self) -> (u16, Vec<u16>) {
        let ind = |i: u16| -> u16 {
            if i < self.party_i - 1 {
                i + 1
            } else {
                i + 2
            }
        };
        let guilty_parties = self
            .msgs
            .iter()
            .enumerate()
            .flat_map(|(i, m)| {
                if m.is_none() {
                    Some(ind(i as u16))
                } else {
                    None
                }
            })
            .collect();
        (self.msgs_left as u16, guilty_parties)
    }
}
