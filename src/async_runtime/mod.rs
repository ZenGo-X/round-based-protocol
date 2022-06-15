//! Instruments for executing protocol in async environment

use std::fmt::{self, Debug};
use std::future::Future;

use futures::future::{Either, FutureExt};
use futures::sink::Sink;
use futures::stream::{self, FusedStream, Stream, StreamExt};
use futures::SinkExt;
use tokio::time::{self, timeout_at};

use crate::{IsCritical, Msg, StateMachine};
use watcher::{BlindWatcher, ProtocolWatcher, When};

pub mod watcher;

/// Executes protocol in async environment using [tokio] backend
///
/// In the most simple setting, you just provide protocol initial state, stream of incoming
/// messages, and sink for outgoing messages, and you're able to easily execute it:
/// ```no_run
/// # use futures::stream::{self, Stream, FusedStream};
/// # use futures::sink::{self, Sink, SinkExt};
/// # use round_based::{Msg, StateMachine, AsyncProtocol};
/// # struct M;
/// # #[derive(Debug)] struct Error;
/// # impl From<std::convert::Infallible> for Error {
/// #    fn from(_: std::convert::Infallible) -> Error { Error }
/// # }
/// # trait Constructable { fn initial() -> Self; }
/// fn incoming() -> impl Stream<Item=Result<Msg<M>, Error>> + FusedStream + Unpin {
///     // ...
/// # stream::pending()
/// }
/// fn outgoing() -> impl Sink<Msg<M>, Error=Error> + Unpin {
///     // ...
/// # sink::drain().with(|x| futures::future::ok(x))
/// }
/// # async fn execute_protocol<State>() -> Result<(), round_based::async_runtime::Error<State::Err, Error, Error>>
/// # where State: StateMachine<MessageBody = M, Err = Error> + Constructable + Send + 'static
/// # {
/// let output: State::Output = AsyncProtocol::new(State::initial(), incoming(), outgoing())
///     .run().await?;
/// // ...
/// # let _ = output; Ok(())
/// # }
/// ```
///
/// Note that if the protocol has some cryptographical assumptions on transport channel (e.g. messages
/// should be encrypted, authenticated), then stream and sink must meet these assumptions (e.g. encrypt,
/// authenticate messages)
pub struct AsyncProtocol<SM, I, O, W = BlindWatcher> {
    state: Option<SM>,
    incoming: I,
    outgoing: O,
    deadline: Option<time::Instant>,
    current_round: Option<u16>,
    watcher: W,
}

impl<SM, I, O> AsyncProtocol<SM, I, O, BlindWatcher> {
    /// Constructs new protocol executor from initial state, channels of incoming and outgoing
    /// messages
    pub fn new(state: SM, incoming: I, outgoing: O) -> Self {
        Self {
            state: Some(state),
            incoming,
            outgoing,
            deadline: None,
            current_round: None,
            watcher: BlindWatcher,
        }
    }
}

impl<SM, I, O, W> AsyncProtocol<SM, I, O, W> {
    /// Sets new protocol watcher
    ///
    /// Protocol watcher looks after protocol execution. See list of observable events in
    /// [ProtocolWatcher] trait.
    ///
    /// Default watcher: [BlindWatcher] that does nothing with received events. For development
    /// purposes it's convenient to pick [StderrWatcher](watcher::StderrWatcher).
    pub fn set_watcher<WR>(self, watcher: WR) -> AsyncProtocol<SM, I, O, WR> {
        AsyncProtocol {
            state: self.state,
            incoming: self.incoming,
            outgoing: self.outgoing,
            deadline: self.deadline,
            current_round: self.current_round,
            watcher,
        }
    }
}

impl<SM, I, O, IErr, W> AsyncProtocol<SM, I, O, W>
where
    SM: StateMachine,
    SM::Err: Send,
    SM: Send + 'static,
    I: Stream<Item = Result<Msg<SM::MessageBody>, IErr>> + FusedStream + Unpin,
    O: Sink<Msg<SM::MessageBody>> + Unpin,
    W: ProtocolWatcher<SM>,
{
    /// Get a reference to the inner state machine.
    ///
    /// This is useful in case where you want to call any of the state machine's methods.
    ///
    /// Note that this could return an error if the state machine is missing, and that could
    /// only happen if the task/thread that is running the proceed call panicked.
    pub fn state_machine_ref(&self) -> Result<&SM, Error<SM::Err, IErr, O::Error>> {
        self.state
            .as_ref()
            .ok_or_else(|| BadStateMachineReason::MissingStateMachine.into())
    }

    /// Try to convert the protocol into the inner state machine.
    ///
    /// Same as [`Self::state_machine_ref`], but instead of returning a reference, it will
    /// take ownership of `self` and return the state machine, this useful in case when
    /// the protocol has been executed and you want to get the state machine back.
    pub fn into_state_machine(self) -> Result<SM, Error<SM::Err, IErr, O::Error>> {
        self.state
            .ok_or_else(|| BadStateMachineReason::MissingStateMachine.into())
    }

    /// Executes the protocol
    ///
    /// Returns protocol output or first occurred critical error
    pub async fn run(&mut self) -> Result<SM::Output, Error<SM::Err, IErr, O::Error>> {
        if self.current_round.is_some() {
            return Err(Error::Exhausted);
        }

        self.refresh_timer()?;
        self.proceed_if_needed().await?;
        self.send_outgoing().await?;
        self.refresh_timer()?;

        if let Some(result) = self.finish_if_possible() {
            return result;
        }

        loop {
            self.handle_incoming().await?;
            self.send_outgoing().await?;
            self.refresh_timer()?;

            self.proceed_if_needed().await?;
            self.send_outgoing().await?;
            self.refresh_timer()?;

            if let Some(result) = self.finish_if_possible() {
                return result;
            }
        }
    }

    async fn handle_incoming(&mut self) -> Result<(), Error<SM::Err, IErr, O::Error>> {
        let state = self.state.as_mut().ok_or(InternalError::MissingState)?;
        match Self::enforce_timeout(self.deadline, self.incoming.next()).await {
            Ok(Some(Ok(msg))) => match state.handle_incoming(msg) {
                Ok(()) => (),
                Err(err) if err.is_critical() => return Err(Error::HandleIncoming(err)),
                Err(err) => self
                    .watcher
                    .caught_non_critical_error(When::HandleIncoming, err),
            },
            Ok(Some(Err(err))) => return Err(Error::Recv(err)),
            Ok(None) => return Err(Error::RecvEof),
            Err(_) => {
                let err = state.round_timeout_reached();
                return Err(Error::HandleIncomingTimeout(err));
            }
        }
        Ok(())
    }

    async fn proceed_if_needed(&mut self) -> Result<(), Error<SM::Err, IErr, O::Error>> {
        let mut state = self.state.take().ok_or(InternalError::MissingState)?;
        if state.wants_to_proceed() {
            let (result, s) = tokio::task::spawn_blocking(move || (state.proceed(), state))
                .await
                .map_err(Error::ProceedPanicked)?;
            state = s;

            match result {
                Ok(()) => (),
                Err(err) if err.is_critical() => return Err(Error::Proceed(err)),
                Err(err) => self.watcher.caught_non_critical_error(When::Proceed, err),
            }
        }
        self.state = Some(state);
        Ok(())
    }

    async fn send_outgoing(&mut self) -> Result<(), Error<SM::Err, IErr, O::Error>> {
        let state = self.state.as_mut().ok_or(InternalError::MissingState)?;

        if !state.message_queue().is_empty() {
            let mut msgs = stream::iter(state.message_queue().drain(..).map(Ok));
            self.outgoing
                .send_all(&mut msgs)
                .await
                .map_err(Error::Send)?;
        }

        Ok(())
    }

    fn finish_if_possible(&mut self) -> Option<Result<SM::Output, Error<SM::Err, IErr, O::Error>>> {
        let state = match self.state.as_mut() {
            Some(s) => s,
            None => return Some(Err(InternalError::MissingState.into())),
        };
        if !state.is_finished() {
            None
        } else {
            match state.pick_output() {
                Some(Ok(result)) => Some(Ok(result)),
                Some(Err(err)) => Some(Err(Error::Finish(err))),
                None => Some(Err(
                    BadStateMachineReason::ProtocolFinishedButNoResult.into()
                )),
            }
        }
    }

    fn refresh_timer(&mut self) -> Result<(), Error<SM::Err, IErr, O::Error>> {
        let state = self.state.as_mut().ok_or(InternalError::MissingState)?;
        let round_n = state.current_round();
        if self.current_round != Some(round_n) {
            self.current_round = Some(round_n);
            self.deadline = match state.round_timeout() {
                Some(timeout) => Some(time::Instant::now() + timeout),
                None => None,
            }
        }

        Ok(())
    }
    fn enforce_timeout<F>(
        deadline: Option<time::Instant>,
        f: F,
    ) -> impl Future<Output = Result<F::Output, time::error::Elapsed>>
    where
        F: Future,
    {
        match deadline {
            Some(deadline) => Either::Right(timeout_at(deadline, f)),
            None => Either::Left(f.map(Ok)),
        }
    }
}

/// Represents error that can occur while executing protocol
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E, RE, SE> {
    /// Receiving next incoming message returned error
    Recv(RE),
    /// Incoming channel closed (got EOF)
    RecvEof,
    /// Sending outgoing message resulted in error
    Send(SE),
    /// [Handling incoming](crate::StateMachine::handle_incoming) message produced critical error
    HandleIncoming(E),
    /// Round timeout exceed when executor was waiting for new messages from other parties
    HandleIncomingTimeout(E),
    /// [Proceed method](crate::StateMachine::proceed) panicked
    ProceedPanicked(tokio::task::JoinError),
    /// State machine [proceeding](crate::StateMachine::proceed) produced critical error
    Proceed(E),
    /// StateMachine's [pick_output](crate::StateMachine::pick_output) method return error
    Finish(E),
    /// AsyncProtocol already executed protocol (or at least, tried to) and tired. You need to
    /// construct new executor!
    Exhausted,
    /// Buggy StateMachine implementation
    BadStateMachine(BadStateMachineReason),
    /// Buggy AsyncProtocol implementation!
    ///
    /// If you've got this error, please, report bug.
    InternalError(InternalError),
}

impl<E, RE, SE> From<BadStateMachineReason> for Error<E, RE, SE> {
    fn from(reason: BadStateMachineReason) -> Self {
        Error::BadStateMachine(reason)
    }
}

impl<E, RE, SE> From<InternalError> for Error<E, RE, SE> {
    fn from(err: InternalError) -> Self {
        Error::InternalError(err)
    }
}

impl<E, RE, SE> fmt::Display for Error<E, RE, SE>
where
    E: fmt::Display,
    RE: fmt::Display,
    SE: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recv(err) => {
                write!(f, "receive next message: {}", err)
            }
            Self::RecvEof => {
                write!(f, "receive next message: unexpected eof")
            }
            Self::Send(err) => {
                write!(f, "send a message: {}", err)
            }
            Self::HandleIncoming(err) => {
                write!(f, "handle received message: {}", err)
            }
            Self::HandleIncomingTimeout(err) => {
                write!(f, "round timeout reached: {}", err)
            }
            Self::ProceedPanicked(err) => {
                write!(f, "proceed round panicked: {}", err)
            }
            Self::Proceed(err) => {
                write!(f, "round proceed error: {}", err)
            }
            Self::Finish(err) => {
                write!(f, "couldn't finish protocol: {}", err)
            }
            Self::Exhausted => {
                write!(f, "async runtime is exhausted")
            }
            Self::BadStateMachine(err) => {
                write!(f, "buggy state machine implementation: {}", err)
            }
            Self::InternalError(err) => {
                write!(f, "internal error: {:?}", err)
            }
        }
    }
}

impl<E, RE, SE> std::error::Error for Error<E, RE, SE>
where
    E: std::error::Error + 'static,
    RE: std::error::Error + 'static,
    SE: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recv(err) => Some(err),
            Self::Send(err) => Some(err),
            Self::HandleIncoming(err) => Some(err),
            Self::HandleIncomingTimeout(err) => Some(err),
            Self::ProceedPanicked(err) => Some(err),
            Self::Proceed(err) => Some(err),
            Self::Finish(err) => Some(err),
            Self::RecvEof => None,
            Self::Exhausted => None,
            Self::BadStateMachine(_) => None,
            Self::InternalError(_) => None,
        }
    }
}

/// Reason why StateMachine implementation looks buggy
#[derive(Debug)]
#[non_exhaustive]
pub enum BadStateMachineReason {
    /// [StateMachine::is_finished](crate::StateMachine::is_finished) returned `true`,
    /// but [StateMachine::pick_output](crate::StateMachine::pick_output) returned `None`
    ProtocolFinishedButNoResult,
    /// StateMachine is missing, probably because the Proceed method panicked.
    MissingStateMachine,
}

impl fmt::Display for BadStateMachineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolFinishedButNoResult => write!(
                f,
                "couldn't obtain protocol output although it is completed"
            ),
            Self::MissingStateMachine => write!(f, "state machine is missing"),
        }
    }
}

/// Describes internal errors that could occur
#[derive(Debug)]
#[non_exhaustive]
pub enum InternalError {
    MissingState,
}
