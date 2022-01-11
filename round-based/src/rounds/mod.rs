use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::TryStream;

use crate::delivery::Incoming;

use self::process_incoming as internal;

mod process_incoming;
pub mod store;

pub trait ProtocolMessage {
    fn variant_id(&self) -> u16;
}

pub trait RoundMessage<M>: ProtocolMessage {
    const VARIANT_ID: u16;

    fn into_round_message(self) -> Option<M>;
    fn from_round_message(msg: M) -> Self;
}

pub trait MessagesStore {
    type Msg;
    type Error;
    type Output;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error>;
    fn wants_more(&self) -> bool;
    fn finish(self) -> Result<Self::Output, Self::Error>;
}

pub trait SupersedingStore<S>: MessagesStore
where
    S: MessagesStore<
        Msg = <Self as MessagesStore>::Msg,
        Error = <Self as MessagesStore>::Error,
        Output = <Self as MessagesStore>::Output,
    >,
{
    type SupersedeError;
    fn supersede(
        &mut self,
        prior_store: S,
    ) -> Result<(), <Self as SupersedingStore<S>>::SupersedeError>;
}

pub struct Rounds<P, I: TryStream<Ok = Incoming<P>>> {
    incoming: I,
    rounds: HashMap<u16, internal::StoreInput<P, I::Error>>,
}

impl<I, P> Rounds<P, I>
where
    I: TryStream<Ok = Incoming<P>> + Send + Unpin,
    I::Error: Send + 'static,
    P: ProtocolMessage,
{
    pub fn listen(incoming: I) -> Self {
        Self {
            incoming,
            rounds: HashMap::new(),
        }
    }

    /// Panics if this type of message is already registered
    pub fn add_round<S>(&mut self, store: S) -> Round<P, S, I>
    where
        P: RoundMessage<S::Msg> + Send + 'static,
        S: MessagesStore + Send + 'static,
        S::Output: Send + 'static,
        S::Error: Send + 'static,
    {
        let (round, round_input, round_output, round_supersede) =
            internal::RoundIncoming::with_store(store);
        let previous = self
            .rounds
            .insert(<P as RoundMessage<S::Msg>>::VARIANT_ID, round_input);
        if previous.is_some() {
            panic!("This type of message is already registered");
        }
        let handle = tokio::spawn(round.start_processing());
        Round {
            _handle: handle,
            output: round_output,
            supersede: round_supersede,
        }
    }

    pub async fn start(self) {
        internal::ProtocolIncoming::<P, I::Error>::new(self.rounds)
            .start_processing(self.incoming)
            .await
    }
}

pub struct Round<P, S, I>
where
    S: MessagesStore,
    I: TryStream<Ok = Incoming<P>>,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    _handle: tokio::task::JoinHandle<()>,
    output: internal::StoreOutput<S::Output, S::Error, I::Error>,
    supersede: internal::StoreSupersede<P, S, I::Error>,
}

impl<P, S, I> Round<P, S, I>
where
    S: MessagesStore,
    I: TryStream<Ok = Incoming<P>>,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    pub fn with_timeout<T>(self, timeout: T) -> RoundWithTimeout<T, P, S, I>
    where
        T: Future<Output = ()>,
    {
        RoundWithTimeout {
            round: self,
            timeout: Some(timeout),
        }
    }

    pub async fn supersede<R>(
        self,
        superseding_store: R,
    ) -> Result<Round<P, R, I>, internal::SupersedeError<R, R::SupersedeError>>
    where
        P: 'static,
        R: MessagesStore<Msg = S::Msg, Output = S::Output, Error = S::Error>
            + SupersedingStore<S>
            + Send
            + 'static,
        I::Ok: Send + 'static,
        I::Error: Send + 'static,
        S::Output: Send,
        S::Error: Send,
    {
        let (round, supersede) =
            internal::RoundIncoming::supersede(superseding_store, self.supersede).await?;
        let handle = tokio::spawn(round.start_processing());
        Ok(Round {
            _handle: handle,
            output: self.output,
            supersede,
        })
    }
}

impl<P, S, I> Future for Round<P, S, I>
where
    S: MessagesStore,
    I: TryStream<Ok = Incoming<P>>,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    type Output = Result<S::Output, ReceiveError<S::Error, I::Error>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.output).poll(cx)
    }
}

pub struct RoundWithTimeout<F, P, S, I>
where
    S: MessagesStore,
    I: TryStream<Ok = Incoming<P>>,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    timeout: Option<F>,
    round: Round<P, S, I>,
}

impl<F, P, S, I> Future for RoundWithTimeout<F, P, S, I>
where
    F: Future<Output = ()> + Unpin,
    S: MessagesStore,
    I: TryStream<Ok = Incoming<P>>,
    P: ProtocolMessage + RoundMessage<S::Msg>,
{
    type Output = Result<S::Output, ReceiveError<S::Error, I::Error>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(mut timeout) = self.timeout.take() {
            match Pin::new(&mut timeout).poll(cx) {
                Poll::Ready(()) => {
                    self.round.output.force();
                }
                Poll::Pending => self.timeout = Some(timeout),
            }
        }

        Pin::new(&mut self.round).poll(cx)
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ReceiveError<StoreErr, IncomingErr> {
    /// Receiving next incoming message resulted into error
    ///
    /// `receive_error` is an error that caused incoming channel to be closed, if present
    ///
    /// `store_error` is an error produced by message store that should explain that received messages
    /// are not enough to proceed to the next round
    #[error("receiving next incoming message resulted into error")]
    IncomingChannelBroken {
        receive_error: Option<IncomingErr>,
        store_error: StoreErr,
    },

    /// Incoming channel is closed (EOF reached)
    ///
    /// `store_error` is an error produced by message store that should explain that received messages
    /// are not enough to proceed to the next round
    #[error("receiving next incoming message resulted into error: eof reached")]
    IncomingChannelClosed { store_error: StoreErr },

    /// Messages store misbehaved
    ///
    /// This error means that message store refused to return output after telling that
    /// it received enough messages. This is a bug of message store.
    #[error("buggy MessageStore: it didn't return output after receiving enough messages")]
    MessageStoreDidntOutputAfterReceivingEnoughMessages { store_error: StoreErr },

    /// Round was forced to proceed, but it has not received enough messages
    #[error("round was forced to proceed, but it has not received enough messages")]
    NotEnoughMessages { store_error: StoreErr },

    /// The task that was processing incoming messages is gone
    ///
    /// The error that caused this unexpected behaviour must be logged
    #[error("the task processing incoming messages is gone")]
    Gone,
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use futures::stream::{self, TryStream};
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;

    use crate::delivery::Incoming;
    use crate::rounds::store::{RoundInput, RoundInputError};
    use crate::rounds::{ProtocolMessage, ReceiveError, RoundMessage, Rounds};

    #[derive(Debug, Clone, PartialEq)]
    enum Msg {
        R1(MsgA),
        R2(MsgB),
    }
    #[derive(Debug, Clone, PartialEq)]
    struct MsgA(u16);
    #[derive(Debug, Clone, PartialEq)]
    struct MsgB(u16);
    impl ProtocolMessage for Msg {
        fn variant_id(&self) -> u16 {
            match self {
                Msg::R1(_) => 1,
                Msg::R2(_) => 2,
            }
        }
    }
    impl RoundMessage<MsgA> for Msg {
        const VARIANT_ID: u16 = 1;

        fn into_round_message(self) -> Option<MsgA> {
            match self {
                Msg::R1(m) => Some(m),
                _ => None,
            }
        }

        fn from_round_message(msg: MsgA) -> Self {
            Msg::R1(msg)
        }
    }
    impl RoundMessage<MsgB> for Msg {
        const VARIANT_ID: u16 = 2;

        fn into_round_message(self) -> Option<MsgB> {
            match self {
                Msg::R2(m) => Some(m),
                _ => None,
            }
        }

        fn from_round_message(msg: MsgB) -> Self {
            Msg::R2(msg)
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum ProtocolError<E> {
        Round1Receive(ReceiveError<RoundInputError, E>),
        Round2Receive(ReceiveError<RoundInputError, E>),
        MismatchedOwnMessage { error: RoundInputError, round: u16 },
    }

    async fn test_protocol_listener<I>(
        incoming: I,
        a: u16,
        b: u16,
    ) -> Result<u64, ProtocolError<I::Error>>
    where
        I: TryStream<Ok = Incoming<Msg>> + Send + Unpin + 'static,
        I::Error: Send + 'static,
    {
        let mut rounds = Rounds::listen(incoming);
        let round1 = rounds.add_round(RoundInput::<MsgA>::new(1, 3));
        let round2 = rounds.add_round(RoundInput::<MsgB>::new(1, 3));
        tokio::spawn(rounds.start());

        // Round 1
        let msgs = round1
            .await
            .map_err(ProtocolError::Round1Receive)?
            .including_me(MsgA(a))
            .map_err(|error| ProtocolError::MismatchedOwnMessage { error, round: 1 })?;
        let a_sum: u16 = msgs.into_vec().into_iter().map(|m| m.0).sum();

        // Round 2
        let msgs = round2
            .await
            .map_err(ProtocolError::Round2Receive)?
            .including_me(MsgB(b))
            .map_err(|error| ProtocolError::MismatchedOwnMessage { error, round: 2 })?;
        let b_sum: u16 = msgs.into_vec().into_iter().map(|m| m.0).sum();

        // Protocol output
        Ok(u64::from(a_sum) * u64::from(b_sum))
    }

    #[tokio::test]
    async fn protocol_terminates() {
        let a1 = 37;
        let a2 = 71;
        let a3 = 50;

        let b1 = 21;
        let b2 = 85;
        let b3 = 35;

        #[rustfmt::skip]
        let mut msgs = vec![
            Incoming{ sender: 0, msg: Msg::R1(MsgA(a1)) },
            Incoming{ sender: 1, msg: Msg::R1(MsgA(a2)) },
            Incoming{ sender: 2, msg: Msg::R1(MsgA(a3)) },
            Incoming{ sender: 0, msg: Msg::R2(MsgB(b1)) },
            Incoming{ sender: 1, msg: Msg::R2(MsgB(b2)) },
            Incoming{ sender: 2, msg: Msg::R2(MsgB(b3)) },
        ];
        msgs.shuffle(&mut OsRng); // order doesn't matter

        let output = test_protocol_listener(
            stream::iter(msgs.into_iter().map(Ok::<_, Infallible>)),
            a2,
            b2,
        )
        .await
        .unwrap();

        assert_eq!(output, u64::from(a1 + a2 + a3) * u64::from(b1 + b2 + b3));
    }
}
