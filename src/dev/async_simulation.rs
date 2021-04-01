use std::fmt::Debug;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::ready;
use futures::sink::Sink;
use futures::stream::{FusedStream, StreamExt};
use tokio::sync::broadcast;

use crate::async_runtime::{self, watcher::StderrWatcher, AsyncProtocol};
use crate::{Msg, StateMachine};

/// Emulates running protocol between local parties using [AsyncProtocol](crate::AsyncProtocol)
///
/// Takes parties (every party is instance of [StateMachine](crate::sm::StateMachine)) and
/// executes protocol between them.
///
/// Compared to [Simulation], AsyncSimulation requires [tokio] runtime and introduces parallelism,
/// so it's more suitable for writing tests (whereas [Simulation] is more suitable for writing
/// benchmarks).
///
/// [Simulation]: super::Simulation
///
/// ## Limitations
/// * Doesn't log process of protocol execution (except for occurring non critical errors). Limited
///   by [ProtocolWatcher](crate::async_runtime::watcher::ProtocolWatcher) API (to be expanded).
///
/// ## Example
/// ```no_run
/// # use round_based::StateMachine;
/// # use round_based::dev::{AsyncSimulation, AsyncSimulationError};
/// # trait Builder { fn new(party_i: u16, party_n: u16) -> Self; }
/// # async fn async_simulation<Party>()
/// # where Party: StateMachine + Builder + Send + 'static,
/// #       Party::MessageBody: Send + Clone + Unpin + 'static,
/// #       Party::Err: Send + std::fmt::Debug,
/// #       Party::Output: Send,
/// # {
/// let results: Vec<Result<Party::Output, _>> = AsyncSimulation::new()
///     .add_party(Party::new(1, 3))
///     .add_party(Party::new(2, 3))
///     .add_party(Party::new(3, 3))
///     .run()
///     .await;
/// # }
/// ```
pub struct AsyncSimulation<SM: StateMachine> {
    tx: broadcast::Sender<Msg<SM::MessageBody>>,
    parties: Vec<
        Option<
            AsyncProtocol<SM, Incoming<SM::MessageBody>, Outgoing<SM::MessageBody>, StderrWatcher>,
        >,
    >,
    exhausted: bool,
}

impl<SM> AsyncSimulation<SM>
where
    SM: StateMachine + Send + 'static,
    SM::MessageBody: Send + Clone + Unpin + 'static,
    SM::Err: Send + Debug,
    SM::Output: Send,
{
    /// Creates new simulation
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(20);
        Self {
            tx,
            parties: vec![],
            exhausted: false,
        }
    }

    /// Adds protocol participant
    pub fn add_party(&mut self, party: SM) -> &mut Self {
        let rx = self.tx.subscribe();

        let incoming = incoming(rx, party.party_ind());
        let outgoing = Outgoing {
            sender: self.tx.clone(),
        };
        let party = AsyncProtocol::new(party, incoming, outgoing).set_watcher(StderrWatcher);
        self.parties.push(Some(party));
        self
    }

    /// Runs a simulation
    ///
    /// ## Returns
    /// Returns Vec of execution results. Every party is executed independently, simulation
    /// will continue until each party finish protocol (either with success or error).
    ///
    /// It's an error to call this method twice. In this case,
    /// `vec![Err(AsyncSimulationError::Exhausted); n]` is returned
    pub async fn run(&mut self) -> Vec<Result<SM::Output, AsyncSimulationError<SM>>> {
        if self.exhausted {
            return iter::repeat_with(|| Err(AsyncSimulationError::SimulationExhausted))
                .take(self.parties.len())
                .collect();
        }
        self.exhausted = true;

        let mut parties = vec![];
        for party in self.parties.drain(..) {
            let mut party = party.expect("guaranteed as simulation is not exhausted");
            let h = tokio::spawn(async { (party.run().await, party) });
            parties.push(h)
        }

        let mut results = vec![];
        for party in parties {
            let (r, party) = match party.await {
                Ok((Ok(output), party)) => (Ok(output), Some(party)),
                Ok((Err(err), party)) => (
                    Err(AsyncSimulationError::ProtocolExecution(err)),
                    Some(party),
                ),
                Err(err) => (
                    Err(AsyncSimulationError::ProtocolExecutionPanicked(err)),
                    None,
                ),
            };
            self.parties.push(party);
            results.push(r);
        }
        results
    }
}

type Incoming<M> =
    Pin<Box<dyn FusedStream<Item = Result<Msg<M>, broadcast::error::RecvError>> + Send>>;

fn incoming<M: Clone + Send + Unpin + 'static>(
    mut rx: broadcast::Receiver<Msg<M>>,
    me: u16,
) -> Incoming<M> {
    let stream = async_stream::stream! {
        loop {
            let item = rx.recv().await;
            yield item
        }
    };
    let stream = StreamExt::filter(stream, move |m| {
        ready(match m {
            Ok(m) => m.sender != me && (m.receiver.is_none() || m.receiver == Some(me)),
            Err(_) => true,
        })
    });
    Box::pin(stream)
}

struct Outgoing<M> {
    sender: broadcast::Sender<Msg<M>>,
}

impl<M> Sink<Msg<M>> for Outgoing<M> {
    type Error = broadcast::error::SendError<Msg<M>>;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Msg<M>) -> Result<(), Self::Error> {
        self.sender.send(item).map(|_| ())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Possible errors that async simulation can be resulted in
#[non_exhaustive]
#[derive(Debug)]
pub enum AsyncSimulationError<SM: StateMachine> {
    /// Protocol execution error
    ProtocolExecution(
        async_runtime::Error<
            SM::Err,
            broadcast::error::RecvError,
            broadcast::error::SendError<Msg<SM::MessageBody>>,
        >,
    ),
    /// Protocol execution produced a panic
    ProtocolExecutionPanicked(tokio::task::JoinError),
    /// Simulation ran twice
    SimulationExhausted,
}
