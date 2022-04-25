use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::mem;

use delivery_core::Incoming;
use futures::{Stream, StreamExt};
use never::Never;
use phantom_type::PhantomType;
use thiserror::Error;
use tracing::{debug, error, trace, trace_span, warn, Span};

use crate::rounds::MessagesStore;

pub use delivery_core::round_store::*;

pub struct Rounds<M, S = ()> {
    incomings: S,
    rounds: HashMap<u16, Option<Box<dyn ProcessRoundMessage<Msg = M>>>>,
}

impl<M: ProtocolMessage + 'static> Rounds<M> {
    pub fn builder() -> RoundsBuilder<M> {
        RoundsBuilder::new()
    }
}

impl<M, S, E> Rounds<M, S>
where
    M: ProtocolMessage,
    S: Stream<Item = Result<Incoming<M>, E>> + Unpin,
{
    #[inline(always)]
    pub async fn complete<R>(
        &mut self,
        _round: Round<R>,
    ) -> Result<R::Output, CompleteRoundError<R::Error, E>>
    where
        R: MessagesStore,
        M: RoundMessage<R::Msg>,
    {
        let round_number = <M as RoundMessage<R::Msg>>::ROUND;
        let span = trace_span!("Round", n = round_number);
        debug!(parent: &span, "pending round to complete");

        match self.complete_with_span::<R>(&span).await {
            Ok(output) => {
                trace!(parent: &span, "round successfully completed");
                Ok(output)
            }
            Err(err) => {
                error!(parent: &span, %err, "round terminated with error");
                Err(err)
            }
        }
    }

    async fn complete_with_span<R>(
        &mut self,
        span: &Span,
    ) -> Result<R::Output, CompleteRoundError<R::Error, E>>
    where
        R: MessagesStore,
        M: RoundMessage<R::Msg>,
    {
        let pending_round = <M as RoundMessage<R::Msg>>::ROUND;
        if let Some(output) = self.retrieve_round_output_if_its_completed::<R>() {
            return output;
        }

        loop {
            let incoming = match self.incomings.next().await {
                Some(Ok(msg)) => msg,
                Some(Err(err)) => return Err(CompleteRoundError::Io(err)),
                None => return Err(CompleteRoundError::UnexpectedEof),
            };
            let message_round_n = incoming.msg.round();

            let message_round = match self.rounds.get_mut(&message_round_n) {
                Some(Some(round)) => round,
                Some(None) => {
                    warn!(
                        parent: span,
                        n = message_round_n,
                        "got message for the round that was already completed, ignoring it"
                    );
                    continue;
                }
                None => return Err(CompleteRoundError::UnregisteredRound { n: message_round_n }),
            };
            if message_round.needs_more_messages().no() {
                warn!(
                    parent: span,
                    n = message_round_n,
                    "received message for the round that was already completed, ignoring it"
                );
                continue;
            }
            message_round.process_message(incoming);

            if pending_round == message_round_n {
                if let Some(output) = self.retrieve_round_output_if_its_completed::<R>() {
                    return output;
                }
            }
        }
    }

    fn retrieve_round_output_if_its_completed<R>(
        &mut self,
    ) -> Option<Result<R::Output, CompleteRoundError<R::Error, E>>>
    where
        R: MessagesStore,
        M: RoundMessage<R::Msg>,
    {
        let round_number = <M as RoundMessage<R::Msg>>::ROUND;
        let round_slot = match self
            .rounds
            .get_mut(&round_number)
            .ok_or(CompleteRoundError::UnregisteredRound { n: round_number })
        {
            Ok(slot) => slot,
            Err(err) => return Some(Err(err)),
        };
        let round = match round_slot
            .as_mut()
            .ok_or(CompleteRoundError::RoundAlreadyCompleted)
        {
            Ok(round) => round,
            Err(err) => return Some(Err(err)),
        };
        if round.needs_more_messages().no() {
            Some(Self::retrieve_round_output::<R>(round_slot))
        } else {
            None
        }
    }

    fn retrieve_round_output<R>(
        slot: &mut Option<Box<dyn ProcessRoundMessage<Msg = M>>>,
    ) -> Result<R::Output, CompleteRoundError<R::Error, E>>
    where
        R: MessagesStore,
        M: RoundMessage<R::Msg>,
    {
        let mut round = slot.take().ok_or(CompleteRoundError::UnregisteredRound {
            n: <M as RoundMessage<R::Msg>>::ROUND,
        })?;
        match round.take_output() {
            Ok(Ok(any)) => Ok(*any
                .downcast::<R::Output>()
                .or(Err(CompleteRoundError::from(
                    BugReason::MismatchedOutputType,
                )))?),
            Ok(Err(any)) => Err(any
                .downcast::<CompleteRoundError<R::Error, Never>>()
                .or(Err(CompleteRoundError::from(
                    BugReason::MismatchedErrorType,
                )))?
                .map_io_err(|e| e.into_any())),
            Err(err) => Err(BugReason::TakeRoundResult(err).into()),
        }
    }
}

pub struct RoundsBuilder<M> {
    rounds: HashMap<u16, Option<Box<dyn ProcessRoundMessage<Msg = M>>>>,
}

impl<M> RoundsBuilder<M>
where
    M: ProtocolMessage + 'static,
{
    pub fn new() -> Self {
        Self {
            rounds: HashMap::new(),
        }
    }

    pub fn add_round<R>(&mut self, message_store: R) -> Round<R>
    where
        R: MessagesStore + 'static,
        M: RoundMessage<R::Msg>,
    {
        let overridden_round = self.rounds.insert(
            M::ROUND,
            Some(Box::new(ProcessRoundMessageImpl::InProgress {
                store: message_store,
                _ph: PhantomType::new(),
            })),
        );
        if overridden_round.is_some() {
            panic!("round {} is overridden", M::ROUND);
        }
        Round {
            _ph: PhantomType::new(),
        }
    }

    pub fn listen<S, E>(self, incomings: S) -> Rounds<M, S>
    where
        S: Stream<Item = Result<Incoming<M>, E>>,
    {
        Rounds {
            incomings,
            rounds: self.rounds,
        }
    }
}

pub struct Round<S: MessagesStore> {
    _ph: PhantomType<S>,
}

trait ProcessRoundMessage {
    type Msg;

    /// Processes round message
    ///
    /// Before calling this method you must ensure that `.needs_more_messages()` returns `Yes`,
    /// otherwise calling this method is unexpected.
    fn process_message(&mut self, msg: Incoming<Self::Msg>);

    /// Indicated whether the store needs more messages
    ///
    /// If it returns `Yes`, then you need to collect more messages to complete round. If it's `No`
    /// then you need to take the round output by calling `.take_output()`.
    fn needs_more_messages(&self) -> NeedsMoreMessages;

    /// Tries to obtain round output
    ///
    /// Can be called once `process_message()` returned `NeedMoreMessages::No`.
    ///
    /// Returns:
    /// * `Ok(Ok(any))` — round is successfully completed, `any` needs to be downcasted to `MessageStore::Output`
    /// * `Ok(Err(any))` — round has terminated with an error, `any` needs to be downcasted to `CompleteRoundError<MessageStore::Error>`
    /// * `Err(err)` — couldn't retrieve the output, see [`TakeOutputError`]
    fn take_output(&mut self) -> Result<Result<Box<dyn Any>, Box<dyn Any>>, TakeOutputError>;
}

#[derive(Debug, Error)]
enum TakeOutputError {
    #[error("output is already taken")]
    AlreadyTaken,
    #[error("output is not ready yet, more messages are needed")]
    NotReady,
}

enum ProcessRoundMessageImpl<S: MessagesStore, M: ProtocolMessage + RoundMessage<S::Msg>> {
    InProgress { store: S, _ph: PhantomType<fn(M)> },
    Completed(Result<S::Output, CompleteRoundError<S::Error, Never>>),
    Gone,
}

impl<S, M> ProcessRoundMessageImpl<S, M>
where
    S: MessagesStore,
    M: ProtocolMessage + RoundMessage<S::Msg>,
{
    fn _process_message(
        store: &mut S,
        msg: Incoming<M>,
    ) -> Result<(), CompleteRoundError<S::Error, Never>> {
        let msg = Incoming {
            sender: msg.sender,
            msg: M::from_protocol_message(msg.msg).map_err(|msg| {
                BugReason::MessageFromAnotherRound {
                    actual_number: msg.round(),
                    expected_round: M::ROUND,
                }
            })?,
        };

        store
            .add_message(msg)
            .map_err(CompleteRoundError::ProcessMessage)?;
        Ok(())
    }
}

impl<S, M> ProcessRoundMessage for ProcessRoundMessageImpl<S, M>
where
    S: MessagesStore,
    M: ProtocolMessage + RoundMessage<S::Msg>,
{
    type Msg = M;

    fn process_message(&mut self, msg: Incoming<Self::Msg>) {
        let store = match self {
            Self::InProgress { store, .. } => store,
            _ => {
                return;
            }
        };

        match Self::_process_message(store, msg) {
            Ok(()) => {
                if store.wants_more() {
                    return;
                }

                let store = match mem::replace(self, Self::Gone) {
                    Self::InProgress { store, .. } => store,
                    _ => {
                        *self = Self::Completed(Err(BugReason::IncoherentState {
                            expected: "InProgress",
                            justification:
                                "we checked at beginning of the function that `state` is InProgress",
                        }
                        .into()));
                        return;
                    }
                };

                match store.output() {
                    Ok(output) => *self = Self::Completed(Ok(output)),
                    Err(_err) => *self = Self::Completed(Err(CompleteRoundError::StoreDidntOutput)),
                }
            }
            Err(err) => {
                *self = Self::Completed(Err(err));
            }
        }
    }

    fn needs_more_messages(&self) -> NeedsMoreMessages {
        match self {
            Self::InProgress { .. } => NeedsMoreMessages::Yes,
            _ => NeedsMoreMessages::No,
        }
    }

    fn take_output(&mut self) -> Result<Result<Box<dyn Any>, Box<dyn Any>>, TakeOutputError> {
        match self {
            Self::InProgress { .. } => return Err(TakeOutputError::NotReady),
            Self::Gone => return Err(TakeOutputError::AlreadyTaken),
            _ => (),
        }
        match mem::replace(self, Self::Gone) {
            Self::Completed(Ok(output)) => Ok(Ok(Box::new(output))),
            Self::Completed(Err(err)) => Ok(Err(Box::new(err))),
            _ => unreachable!("it's checked to be completed"),
        }
    }
}

enum NeedsMoreMessages {
    Yes,
    No,
}

#[allow(dead_code)]
impl NeedsMoreMessages {
    pub fn yes(&self) -> bool {
        matches!(self, Self::Yes)
    }
    pub fn no(&self) -> bool {
        matches!(self, Self::No)
    }
}

#[derive(Debug, Error)]
pub enum CompleteRoundError<ProcessErr, IoErr> {
    /// [`MessageStore`] failed to process this message
    #[error("failed to process the message")]
    ProcessMessage(#[source] ProcessErr),
    /// Store indicated that it received enough messages but didn't output
    ///
    /// I.e. [`store.wants_more()`] returned `false`, but `store.output()` returned `Err(_)`.
    /// Practically it means that there's a bug in [`MessageStore`] implementation.
    #[error("store didn't output")]
    StoreDidntOutput,
    #[error("round is already completed")]
    RoundAlreadyCompleted,
    #[error("receiving next message resulted into error")]
    Io(#[source] IoErr),
    #[error("receiving next message failed: unexpected eof")]
    UnexpectedEof,
    #[error("round {n} is not registered")]
    UnregisteredRound { n: u16 },
    /// Indicates a bug in [`Rounds`] implementation
    #[error("bug occurred")]
    Bug(#[source] CompleteRoundBug),
}

impl<ProcessErr, IoErr> CompleteRoundError<ProcessErr, IoErr> {
    fn map_io_err<E, F>(self, f: F) -> CompleteRoundError<ProcessErr, E>
    where
        F: FnOnce(IoErr) -> E,
    {
        match self {
            CompleteRoundError::Io(err) => CompleteRoundError::Io(f(err)),
            CompleteRoundError::ProcessMessage(err) => CompleteRoundError::ProcessMessage(err),
            CompleteRoundError::StoreDidntOutput => CompleteRoundError::StoreDidntOutput,
            CompleteRoundError::RoundAlreadyCompleted => CompleteRoundError::RoundAlreadyCompleted,
            CompleteRoundError::UnexpectedEof => CompleteRoundError::UnexpectedEof,
            CompleteRoundError::Bug(err) => CompleteRoundError::Bug(err),
            CompleteRoundError::UnregisteredRound { n } => {
                CompleteRoundError::UnregisteredRound { n }
            }
        }
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct CompleteRoundBug(BugReason);

#[derive(Debug, Error)]
enum BugReason {
    #[error(
        "message originates from another round: we process messages from round \
        {expected_round}, got message from round {actual_number}"
    )]
    MessageFromAnotherRound {
        expected_round: u16,
        actual_number: u16,
    },
    #[error("state is incoherent, it's expected to be {expected}: {justification}")]
    IncoherentState {
        expected: &'static str,
        justification: &'static str,
    },
    #[error("mismatched output type")]
    MismatchedOutputType,
    #[error("mismatched error type")]
    MismatchedErrorType,
    #[error("take round result")]
    TakeRoundResult(#[source] TakeOutputError),
}

impl<E1, E2> From<BugReason> for CompleteRoundError<E1, E2> {
    fn from(err: BugReason) -> Self {
        CompleteRoundError::Bug(CompleteRoundBug(err))
    }
}
