//! Mechanism for tracking protocol execution

use std::fmt::Debug;

use crate::StateMachine;

/// Looks after protocol execution in [AsyncProtocol](super::AsyncProtocol)
///
/// Currently it's only able to see caught non critical errors, API will be expanded (see [#1][issue]).
/// It will be able to track incoming messages, changing round number, etc.
///
/// [issue]: https://github.com/ZenGo-X/round-based-protocol/issues/1
pub trait ProtocolWatcher<SM: StateMachine> {
    /// StateMachine produced a not critical error. Execution continues.
    fn caught_non_critical_error(&mut self, when: When, err: SM::Err);
}

/// Claims at which stage event occurred
#[derive(Debug)]
pub enum When {
    HandleIncoming,
    Proceed,
}

/// Watcher that doesn't do anything when event happens
pub struct BlindWatcher;

impl<SM> ProtocolWatcher<SM> for BlindWatcher
where
    SM: StateMachine,
{
    fn caught_non_critical_error(&mut self, _when: When, _err: SM::Err) {}
}

/// Watcher that logs non critical error to stderr
pub struct StderrWatcher;

impl<SM> ProtocolWatcher<SM> for StderrWatcher
where
    SM: StateMachine,
    SM::Err: Debug,
{
    fn caught_non_critical_error(&mut self, when: When, err: SM::Err) {
        eprintln!("Caught non critical error at {:?}: {:?}", when, err);
    }
}
