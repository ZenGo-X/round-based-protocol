//! Computationally-heavy tasks
//!
//! In MPC protocols we often need to do some heavy computation (e.g. sample a large random prime).
//! Computationally heavy code should be carefully treated in async environment: async code that
//! takes a lot of time to compute without yielding a result may prevent the async runtime from
//! driving other futures.
//!
//! [`Blocking<B>`](Blocking) provides async-friendly API for executing computationally-heavy tasks
//! in non-harmful way.  
//!
//! `Blocking<TokioSpawnBlocking>` executes tasks via [spawn_blocking](tokio::task::spawn_blocking).
//! You can define another `B` (by implementing [`SpawnBlocking`]) that, for instance, sends tasks
//! to a thread pool.

use std::future::Future;

use tokio::sync::oneshot;

mod tokio_spawn_blocking;

pub use self::tokio_spawn_blocking::TokioSpawnBlocking;

//TODO: Once GATs are stabilized, replace SpawnBlocking+Blocking with single trait:
// trait Blocking {
//     type Task<R>: Future<Output = Result<R, Self::Error>>;
//     type Error;
//     fn spawn<F, R>(&self, task: F) -> Self::Task<R>
//     where
//         F: FnOnce() -> R + Send + 'static,
//         R: Send + 'static;
// }

/// Defines the way heavy computational tasks are executed
///
/// Not intended to be used directly, use [`Blocking<B>`](Blocking) instead.
pub trait SpawnBlocking {
    /// Future returned by [`spawn`](Self::spawn)
    type Task: Future<Output = Result<TaskResult, Self::Error>> + Send + 'static;
    /// Error returned if failed to execute a task
    type Error;

    /// Executes computationally-heavy task in non-harmful way
    ///
    /// Returns a future that results into either task output `Ok(output)` or `Err(err)` if any error
    /// happened (e.g. task panicked).
    fn spawn<F>(&self, task: F) -> Self::Task
    where
        F: FnOnce() -> TaskResult + Send + 'static;
}

/// Executes computationally heavy tasks without blocking async runtime
#[derive(Debug)]
pub struct Blocking<B>(B);

impl<B> Blocking<B>
where
    B: SpawnBlocking,
{
    /// Wraps [`SpawnBlocking`]
    pub fn new(spawner: B) -> Self {
        Self(spawner)
    }

    /// Executes heavy task without blocking async runtime
    ///
    /// Returns task output or error if something went wrong (e.g. task panicked).
    pub async fn spawn<F, R>(&self, task: F) -> Result<R, B::Error>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (send, recv) = oneshot::channel();
        let _witness: TaskResult = self
            .0
            .spawn(move || {
                let result = task();
                let _ = send.send(result);
                TaskResult { _private: () }
            })
            .await?;

        Ok(recv
            .await
            .expect("_witness guarantees that task was executed"))
    }
}

/// A marker witnessing that blocking task was executed
pub struct TaskResult {
    _private: (),
}
