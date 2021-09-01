use std::future::Future;

use tokio::sync::oneshot;

mod tokio_spawn_blocking;

pub use self::tokio_spawn_blocking::TokioSpawnBlocking;

//TODO: Once GATs are stabilized, replace SpawnBlocking+Blocking+CarryingOutError with single
// trait:
// trait Blocking {
//     type Task<R>: Future<Output = Result<R, Self::Error>>;
//     type Error;
//     fn spawn<F, R>(&self, task: F) -> Self::Task<R>
//     where
//         F: FnOnce() -> R + Send + 'static,
//         R: Send + 'static;
// }
// It would allow us to avoid having awkward CarryingOutError::NoResult and extra wrapper structure

pub trait SpawnBlocking {
    type Task: Future<Output = Result<(), Self::Error>> + Send + 'static;
    type Error;
    fn spawn<F>(&self, task: F) -> Self::Task
    where
        F: FnOnce() + Send + 'static;
}

pub struct Blocking<B>(B);

impl<B> Blocking<B>
where
    B: SpawnBlocking,
{
    pub fn new(spawner: B) -> Self {
        Self(spawner)
    }

    pub async fn spawn<F, R>(&self, task: F) -> Result<R, CarryingOutError<B::Error>>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (send, recv) = oneshot::channel();
        let result = self
            .0
            .spawn(move || {
                let result = task();
                let _ = send.send(result);
            })
            .await;
        if let Err(e) = result {
            Err(CarryingOutError::Terminated(e))
        } else {
            recv.await.map_err(|_| CarryingOutError::NoResult)
        }
    }
}

pub enum CarryingOutError<E> {
    /// Running blocking task was unexpectedly terminated
    ///
    /// The reason might be that the task has panicked, or execution was aborted. Attached error
    /// should explain what happened.
    Terminated(E),
    /// Blocking task was carried out successfully, but result hasn't been yielded
    ///
    /// That basically means that underlying [SpawnBlocking] implementation behaved incorrectly
    /// by dropping the task instead of carrying out it.
    NoResult,
}
