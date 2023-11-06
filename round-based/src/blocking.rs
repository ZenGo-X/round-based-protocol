//! Computationally-heavy tasks
//!
//! In MPC protocols we often need to do some heavy computation (e.g. sample a large random prime).
//! Computationally heavy code should be carefully treated in async environment: async code that
//! takes a lot of time to compute without yielding a result may prevent the async runtime from
//! driving other futures.
//!
//! [`SpawnBlocking`] provides async-friendly API for executing computationally-heavy tasks
//! in non-harmful way. Its implementation depends on a runtime being used. Use feature
//! `runtime-tokio` to [enable tokio-specific runtime](SpawnOnTokio).

use std::future::Future;

/// Defines the way heavy computational tasks are executed
pub trait SpawnBlocking {
    /// A future returned by [`.spawn()`](Self::spawn)
    type Task<R>: Future<Output = Result<R, Self::Error>>;
    /// An error type
    type Error;
    /// Executes computationally-heavy task in non-harmful way
    ///
    /// Returns a future that results into either task output `Ok(output)` or `Err(err)` if any error
    /// happened (e.g. task panicked).
    fn spawn<R, F>(&self, task: F) -> Self::Task<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static;
}

/// Default implementation of [`SpawnBlocking`]
#[cfg(feature = "runtime-tokio")]
pub type DefaultSpawner = SpawnOnTokio;
/// Default implementation of [`SpawnBlocking`]
#[cfg(not(feature = "runtime-tokio"))]
pub type DefaultSpawner = ExecuteInPlace;

/// Executes a task in place, on a greenthread
///
/// It's discouraged to use that. It may noticeable slow down the runtime if a greenthread
/// is blocked by a heavy computation.
#[derive(Debug, Clone, Default)]
pub struct ExecuteInPlace;

impl SpawnBlocking for ExecuteInPlace {
    type Task<R> = std::future::Ready<Result<R, Self::Error>>;
    type Error = std::convert::Infallible;

    fn spawn<R, F>(&self, task: F) -> Self::Task<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        tracing::warn!("A computationally-heavy task is being executed in async runtime. Please provide a proper `SpawnBlocking` implementation to improve performance.");
        std::future::ready(Ok(task()))
    }
}

#[cfg(feature = "runtime-tokio")]
pub use tokio_backend::SpawnOnTokio;

#[cfg(feature = "runtime-tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
mod tokio_backend {
    use tokio::task::{JoinError, JoinHandle};

    /// Spawns a computationally-heavy task on tokio blocking pool using
    /// [`tokio::task::spawn_blocking`]
    #[derive(Debug, Clone, Default)]
    pub struct SpawnOnTokio;

    impl super::SpawnBlocking for SpawnOnTokio {
        type Task<T> = JoinHandle<T>;
        type Error = JoinError;

        fn spawn<R, F>(&self, task: F) -> Self::Task<R>
        where
            F: FnOnce() -> R + Send + 'static,
            R: Send + 'static,
        {
            tokio::task::spawn_blocking(task)
        }
    }
}
