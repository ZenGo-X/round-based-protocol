use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use delivery_core::Incoming;
use futures::{ready, TryStream, TryStreamExt};
use phantom_type::PhantomType;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{event, span, Level};

use crate::rounds::MessagesStore;

pub use delivery_core::round_store::*;

pub struct Rounds<M, S>
where
    S: TryStream<Ok = Incoming<M>>,
{
    incomings: S,
    rounds: HashMap<
        u16,
        Option<Box<dyn ProcessRoundMessage<Msg = M, ReceiveError = Arc<S::Error>> + Send>>,
    >,
    not_completed_rounds: u16,
}

impl<M, S> Rounds<M, S>
where
    S: TryStream<Ok = Incoming<M>> + Send + Unpin + 'static,
    S::Error: Display + Send + Sync + 'static,
    M: ProtocolMessage + 'static,
{
    pub fn listen(incomings: S) -> Self {
        Self {
            incomings,
            rounds: HashMap::new(),
            not_completed_rounds: 0,
        }
    }

    pub fn add_round<R>(&mut self, message_store: R) -> Round<R::Output, R::Error, S::Error>
    where
        R: MessagesStore + Send,
        R::Output: Send,
        R::Error: Send,
        M: RoundMessage<R::Msg> + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let overridden_round = self.rounds.insert(
            M::ROUND,
            Some(Box::new(ProcessRoundMessageImpl {
                store: Some(message_store),
                channel: Some(tx),
                _msg: PhantomType::new(),
            })),
        );
        if overridden_round.is_some() {
            panic!("round {} is overridden", M::ROUND);
        }
        self.not_completed_rounds = self.not_completed_rounds.checked_add(1).unwrap();
        Round { channel: rx }
    }

    /// Starts listening to incoming messages in the background
    ///
    /// Returns a handle that will abort background task on drop
    pub fn start_in_background(self) -> RoundsHandle {
        RoundsHandle(tokio::spawn(self.start()))
    }

    pub async fn start(mut self) {
        let span = span!(Level::TRACE, "Rounds::listen");

        while self.not_completed_rounds > 0 {
            let msg = match self.incomings.try_next().await {
                Ok(Some(msg)) => msg,
                Ok(None) => return self.finish_with_io_error(&span, None),
                Err(err) => return self.finish_with_io_error(&span, Some(err)),
            };

            let round = msg.msg.round();
            let span = span!(
                parent: &span,
                Level::TRACE,
                "Processing received message",
                round,
                sender = msg.sender,
            );
            event!(parent: &span, Level::TRACE, "Message received");

            let round_processor = match self.rounds.get_mut(&round) {
                Some(Some(p)) => p,
                Some(None) => {
                    event!(
                        parent: &span,
                        Level::WARN,
                        "Message originates from round that's completed by now, ignoring it"
                    );
                    continue;
                }
                None => {
                    event!(
                        parent: &span,
                        Level::WARN,
                        "Message originates from round that's not registered, ignoring it"
                    );
                    continue;
                }
            };

            match round_processor.process_message(msg) {
                Ok(NeedsMoreMessages::Yes) => {
                    event!(parent: &span, Level::TRACE, "Message is processed");
                    continue;
                }
                Ok(NeedsMoreMessages::No) => {
                    event!(parent: &span, Level::TRACE, "Message is processed");
                    event!(parent: &span, Level::TRACE, "Round is completed");
                    let _ = self.rounds.insert(round, None);
                    self.not_completed_rounds -= 1;
                    continue;
                }
                Err(err) => {
                    event!(parent: &span, Level::ERROR, %err, "Failed to process the message");
                    continue;
                }
            }
        }

        if self.not_completed_rounds > 0 {
            return self.finish_with_io_error(&span, None);
        }

        event!(parent: &span, Level::TRACE, "Completed");
    }

    fn finish_with_io_error(&mut self, span: &tracing::Span, err: Option<S::Error>) {
        if self.not_completed_rounds == 0 {
            return;
        }

        // Find out what rounds are not completed
        let not_completed_rounds = self
            .rounds
            .iter()
            .filter_map(|(round, processor)| {
                if processor.is_some() {
                    Some(*round)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Log error
        match &err {
            Some(err) => {
                event!(parent: span, Level::ERROR, %err, ?not_completed_rounds, "Stream of incoming messages yielded error");
            }
            None => {
                event!(
                    parent: span,
                    Level::ERROR,
                    ?not_completed_rounds,
                    "Stream of incoming message is unexpectedly terminated"
                );
            }
        }

        // Propagate error to rounds
        let err = err.map(Arc::new);

        for round_processor in self.rounds.values_mut() {
            if let Some(round_processor) = round_processor {
                round_processor.receive_next_message_error(err.clone())
            }
            *round_processor = None
        }
    }
}

/// Handle to [`Rounds`] working in background
///
/// Background task will be automatically canceled when handle is dropped
pub struct RoundsHandle(tokio::task::JoinHandle<()>);

impl RoundsHandle {
    /// Aborts `Rounds` task working in background.
    ///
    /// Equivalent of dropping the handle.
    ///
    /// If any rounds are happened to be not completed at the time of calling this method, they will
    /// terminate with error [`ReceiveMessageError::Aborted`]
    pub fn abort(self) {}
}

impl Drop for RoundsHandle {
    fn drop(&mut self) {
        self.0.abort()
    }
}

pub struct Round<R, StoreErr, IoErr> {
    channel: oneshot::Receiver<Result<R, ReceiveMessageError<StoreErr, IoErr>>>,
}

impl<R, StoreErr, IoErr> Future for Round<R, StoreErr, IoErr> {
    type Output = Result<R, ReceiveMessageError<StoreErr, IoErr>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.channel).poll(cx)) {
            Ok(result) => Poll::Ready(result),
            Err(_sender_is_gone) => Poll::Ready(Err(ReceiveMessageError::Aborted)),
        }
    }
}

trait ProcessRoundMessage {
    type Msg;
    type ReceiveError;

    /// Processes round message
    ///
    /// Returns:
    /// * `Ok(NeedsMoreMessages::No)` — enough messages are received, no more messages are expected to come
    /// * `Ok(NeedsMoreMessages::Yes)` — message is correctly handled, more messages are expected to come
    /// * `Err(_)` — error happened, see [`ProcessRoundMessageError`]
    ///
    /// Once `process_message` returned `Ok(NeedsMoreMessages::No)` or `Err(_)`, round is considered
    /// to be completed (or terminated with error).
    fn process_message(
        &mut self,
        msg: Incoming<Self::Msg>,
    ) -> Result<NeedsMoreMessages, ProcessRoundMessageError>;

    /// Signals that round cannot be completed because of i/o error
    ///
    /// `err` is occurred error. `err` is `None` if unexpected eof is reached.
    ///
    /// Once this method is called, round is assumed to be terminated with i/o error.
    fn receive_next_message_error(&mut self, err: Option<Self::ReceiveError>);
}

struct ProcessRoundMessageImpl<S: MessagesStore, M: ProtocolMessage + RoundMessage<S::Msg>, IoErr> {
    store: Option<S>,
    channel: Option<oneshot::Sender<Result<S::Output, ReceiveMessageError<S::Error, IoErr>>>>,
    _msg: PhantomType<M>,
}

impl<S, M, IoErr> ProcessRoundMessage for ProcessRoundMessageImpl<S, M, IoErr>
where
    S: MessagesStore,
    M: ProtocolMessage + RoundMessage<S::Msg>,
{
    type Msg = M;
    type ReceiveError = Arc<IoErr>;

    fn process_message(
        &mut self,
        msg: Incoming<Self::Msg>,
    ) -> Result<NeedsMoreMessages, ProcessRoundMessageError> {
        if self.channel.is_none() || self.store.is_none() {
            return Err(ProcessRoundMessageError::Gone);
        }

        let msg = Incoming {
            sender: msg.sender,
            msg: M::from_protocol_message(msg.msg).map_err(|msg| {
                ProcessRoundMessageError::MismatchedRoundNumber {
                    round: msg.round(),
                    expected_round: M::ROUND,
                }
            })?,
        };

        let store = self.store.as_mut().expect("store is checked to be present");
        if let Err(err) = store.add_message(msg) {
            let _ = self
                .channel
                .take()
                .expect("channel is checked to be present")
                .send(Err(ReceiveMessageError::ProcessMessageError(err)));
            return Err(ProcessRoundMessageError::InvalidMessage);
        }

        if !store.wants_more() {
            let output = self
                .store
                .take()
                .expect("store is checked to be present")
                .output()
                .or(Err(ProcessRoundMessageError::StoreDidntOutput))?;
            let _ = self
                .channel
                .take()
                .expect("channel is checked to be present")
                .send(Ok(output));
            return Ok(NeedsMoreMessages::No);
        }

        Ok(NeedsMoreMessages::Yes)
    }

    fn receive_next_message_error(&mut self, err: Option<Self::ReceiveError>) {
        if let Some(channel) = self.channel.take() {
            let _ = channel.send(Err(err
                .map(ReceiveMessageError::ReceiveMessageError)
                .unwrap_or(ReceiveMessageError::UnexpectedEof)));
        }
    }
}

enum NeedsMoreMessages {
    Yes,
    No,
}

#[derive(Debug, Error)]
enum ProcessRoundMessageError {
    /// Received message is invalid
    #[error("received message is invalid")]
    InvalidMessage,
    /// `process_message` previously returned either `Ok(NeedsMoreMessages::No)` or `Err(_)`
    #[error("gone")]
    Gone,
    /// Message originates from another round.
    ///
    /// Practically it means there's a bug in [`Rounds`] implementation.
    #[error("message originates from another round (message round is {round}, expected {expected_round})")]
    MismatchedRoundNumber { round: u16, expected_round: u16 },
    /// Store indicated that it needs no more messages but didn't output
    ///
    /// I.e. [`store.wants_more()`] returned `false`, but `store.output()` returned `Err(_)`.
    /// Practically it means that there's a bug in [`MessageStore`] implementation.
    #[error("store didn't output")]
    StoreDidntOutput,
}

#[derive(Debug, Error)]
pub enum ReceiveMessageError<StoreErr, IoErr> {
    #[error("processing received message resulted into error")]
    ProcessMessageError(#[source] StoreErr),
    #[error("receiving next incoming message resulted into error")]
    ReceiveMessageError(#[source] Arc<IoErr>),
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("task receiving messages was aborted")]
    Aborted,
}
