use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Sink, Stream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};

use crate::delivery::{Delivery, Incoming, Outgoing};
use crate::{MessageDestination, MpcParty};

pub struct Simulation<M> {
    channel: broadcast::Sender<Outgoing<Incoming<M>>>,
    next_party_idx: u16,
}

impl<M> Simulation<M>
where
    M: Clone + Send + Unpin + 'static,
{
    pub fn new() -> Self {
        Self {
            channel: broadcast::channel(10).0,
            next_party_idx: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            channel: broadcast::channel(capacity).0,
            next_party_idx: 0,
        }
    }

    pub fn connect_new_party(&mut self) -> SimulationDelivery<M> {
        let local_party_idx = self.next_party_idx;
        self.next_party_idx += 1;

        SimulationDelivery {
            incoming: SimulationIncoming {
                local_party_idx,
                receiver: BroadcastStream::new(self.channel.subscribe()),
            },
            outgoing: SimulationOutgoing {
                local_party_idx,
                sender: self.channel.clone(),
            },
        }
    }

    pub fn add_party(&mut self) -> MpcParty<M, SimulationDelivery<M>> {
        let local_party_idx = self.next_party_idx;
        self.next_party_idx += 1;

        MpcParty::connected(SimulationDelivery {
            incoming: SimulationIncoming {
                local_party_idx,
                receiver: BroadcastStream::new(self.channel.subscribe()),
            },
            outgoing: SimulationOutgoing {
                local_party_idx,
                sender: self.channel.clone(),
            },
        })
    }
}

impl<M> Default for Simulation<M>
where
    M: Clone + Send + Unpin + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct SimulationDelivery<M> {
    incoming: SimulationIncoming<M>,
    outgoing: SimulationOutgoing<M>,
}

impl<M> Delivery<M> for SimulationDelivery<M>
where
    M: Clone + Send + Unpin + 'static,
{
    type Send = SimulationOutgoing<M>;
    type Receive = SimulationIncoming<M>;
    type SendError = broadcast::error::SendError<()>;
    type ReceiveError = BroadcastStreamRecvError;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.incoming, self.outgoing)
    }
}

pub struct SimulationIncoming<M> {
    local_party_idx: u16,
    receiver: BroadcastStream<Outgoing<Incoming<M>>>,
}

impl<M> Stream for SimulationIncoming<M>
where
    M: Clone + Send + 'static,
{
    type Item = Result<Incoming<M>, BroadcastStreamRecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let msg = match ready!(Pin::new(&mut self.receiver).poll_next(cx)) {
                Some(Ok(m)) => m,
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => return Poll::Ready(None),
            };
            if msg.recipient.is_p2p()
                && msg.recipient != MessageDestination::OneParty(self.local_party_idx)
            {
                continue;
            }
            return Poll::Ready(Some(Ok(msg.msg)));
        }
    }
}

pub struct SimulationOutgoing<M> {
    local_party_idx: u16,
    sender: broadcast::Sender<Outgoing<Incoming<M>>>,
}

impl<M> Sink<Outgoing<M>> for SimulationOutgoing<M> {
    type Error = broadcast::error::SendError<()>;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, msg: Outgoing<M>) -> Result<(), Self::Error> {
        self.sender
            .send(msg.map(|m| Incoming {
                sender: self.local_party_idx,
                msg: m,
            }))
            .map_err(|_| broadcast::error::SendError(()))?;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
