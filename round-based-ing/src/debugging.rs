use std::fmt;
use std::time::Duration;

use tracing::{span, trace, Level, Span};

use ecdsa_mpc::protocol::{InputMessage, OutputMessage};
use ecdsa_mpc::state_machine::{State, Transition};

use crate::generic::StateMachineTraits;

/// Wraps [state machine](State) and logs every usage of it
pub struct Debugging<S> {
    state: S,
    span: Span,
}

impl<S> Debugging<S> {
    /// Wraps state machine
    pub fn new(state: S) -> Self {
        Self {
            state,
            span: span!(Level::TRACE, "State machine execution"),
        }
    }

    /// Sets logging [`Span`]
    ///
    /// Default span is `span!(Level::TRACE, "State machine execution")`
    pub fn set_span(self, span: Span) -> Self {
        Self { span, ..self }
    }
}

impl<S, T> State<T> for Debugging<S>
where
    S: State<T>,
    T: StateMachineTraits + 'static,
    T::Msg: fmt::Debug,
    T::FinalState: fmt::Debug,
    T::ErrorState: fmt::Debug,
{
    fn start(&mut self) -> Option<Vec<OutputMessage<T::Msg>>> {
        trace!(parent: &self.span, "State::start");
        let msgs = self.state.start();
        trace!(
            parent: &self.span,
            n = msgs.as_ref().map(Vec::len).unwrap_or_default(),
            "State::start enqueued `n` messages to be sent"
        );
        for msg in msgs.iter().flatten() {
            trace!(
                parent: &self.span,
                recipient = ?msg.recipient,
                msg = ?msg.body,
                "Enqueued outgoing message"
            )
        }
        msgs
    }

    fn is_message_expected(
        &self,
        msg: &InputMessage<T::Msg>,
        current_msg_set: &[InputMessage<T::Msg>],
    ) -> bool {
        trace!(
            parent: &self.span,
            sender = ?msg.sender,
            msg = ?msg.body,
            "State::is_message_expected"
        );
        let is_expected = self.state.is_message_expected(msg, current_msg_set);
        trace!(parent: &self.span, is_expected, "State::is_message_expected returned");

        is_expected
    }

    fn is_input_complete(&self, current_msg_set: &[InputMessage<T::Msg>]) -> bool {
        trace!(parent: &self.span, "State::is_input_complete");
        let is_complete = self.state.is_input_complete(current_msg_set);
        trace!(parent: &self.span, is_complete, "State::is_input_complete returned");
        is_complete
    }

    fn consume(&self, current_msg_set: Vec<InputMessage<T::Msg>>) -> Transition<T> {
        trace!(parent: &self.span, "State::consume");
        match self.state.consume(current_msg_set) {
            Transition::NewState(new_state) => {
                trace!(parent: &self.span, "State is proceeded");
                Transition::NewState(Box::new(Debugging {
                    state: BoxedState::from(new_state),
                    span: self.span.clone(),
                }))
            }
            Transition::FinalState(Ok(output)) => {
                trace!(parent: &self.span, ?output, "Protocol terminated");
                Transition::FinalState(Ok(output))
            }
            Transition::FinalState(Err(err)) => {
                trace!(parent: &self.span, ?err, "Protocol terminated");
                Transition::FinalState(Err(err))
            }
        }
    }

    fn timeout(&self) -> Option<Duration> {
        trace!(parent: &self.span, "State::timeout");
        let timeout = self.state.timeout();
        trace!(parent: &self.span, ?timeout, "State::timeout returned");
        timeout
    }

    fn timeout_outcome(
        &self,
        current_msg_set: Vec<InputMessage<T::Msg>>,
    ) -> Result<T::FinalState, T::ErrorState> {
        trace!(parent: &self.span, "State::timeout_outcome");
        match self.state.timeout_outcome(current_msg_set) {
            Ok(output) => {
                trace!(parent: &self.span, ?output, "Protocol terminated due to timeout outcome");
                Ok(output)
            }
            Err(err) => {
                trace!(parent: &self.span, ?err, "Protocol terminated due to timeout outcome");
                Err(err)
            }
        }
    }
}

struct BoxedState<T: ecdsa_mpc::state_machine::StateMachineTraits>(Box<dyn State<T> + Send>);

impl<T: ecdsa_mpc::state_machine::StateMachineTraits> From<Box<dyn State<T> + Send>>
    for BoxedState<T>
{
    fn from(state: Box<dyn State<T> + Send>) -> Self {
        BoxedState(state)
    }
}

impl<T: ecdsa_mpc::state_machine::StateMachineTraits> State<T> for BoxedState<T> {
    #[inline(always)]
    fn start(&mut self) -> Option<Vec<T::OutMsg>> {
        self.0.start()
    }

    #[inline(always)]
    fn is_message_expected(&self, msg: &T::InMsg, current_msg_set: &[T::InMsg]) -> bool {
        self.0.is_message_expected(msg, current_msg_set)
    }

    #[inline(always)]
    fn is_input_complete(&self, current_msg_set: &[T::InMsg]) -> bool {
        self.0.is_input_complete(current_msg_set)
    }

    #[inline(always)]
    fn consume(&self, current_msg_set: Vec<T::InMsg>) -> Transition<T> {
        self.0.consume(current_msg_set)
    }

    #[inline(always)]
    fn timeout(&self) -> Option<Duration> {
        self.0.timeout()
    }

    #[inline(always)]
    fn timeout_outcome(
        &self,
        current_msg_set: Vec<T::InMsg>,
    ) -> Result<T::FinalState, T::ErrorState> {
        self.0.timeout_outcome(current_msg_set)
    }
}
