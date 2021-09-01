use crate::blocking::SpawnBlocking;
use tokio::task::{spawn_blocking, JoinError, JoinHandle};

/// Spawns blocking tasks via [tokio::task::spawn_blocking]
pub struct TokioSpawnBlocking;

impl SpawnBlocking for TokioSpawnBlocking {
    type Task = JoinHandle<()>;
    type Error = JoinError;

    fn spawn<F>(&self, task: F) -> Self::Task
    where
        F: FnOnce() + Send + 'static,
    {
        spawn_blocking(task)
    }
}
