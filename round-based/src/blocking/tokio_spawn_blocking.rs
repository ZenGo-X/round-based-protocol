use crate::blocking::{SpawnBlocking, TaskResult};
use tokio::task::{spawn_blocking, JoinError, JoinHandle};

/// Default implementation of [`SpawnBlocking`] that spawns tasks via [tokio::task::spawn_blocking]
#[derive(Debug, Clone, Default)]
pub struct TokioSpawnBlocking;

impl SpawnBlocking for TokioSpawnBlocking {
    type Task = JoinHandle<TaskResult>;
    type Error = JoinError;

    fn spawn<F>(&self, task: F) -> Self::Task
    where
        F: FnOnce() -> TaskResult + Send + 'static,
    {
        spawn_blocking(task)
    }
}
