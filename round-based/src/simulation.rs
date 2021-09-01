use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};

use crate::delivery::{DeliverOutgoing, Delivery, Incoming, Outgoing};
use crate::rounds::ProtocolMessage;
use crate::MpcParty;

pub struct Simulation<M> {
    channel: broadcast::Sender<Outgoing<Incoming<M>>>,
    next_party_idx: u16,
}

impl<M> Simulation<M>
where
    M: ProtocolMessage + Clone + Send + Unpin + 'static,
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

    pub fn add_party(&mut self) -> MpcParty<M, SimulationDelivery<M>> {
        let local_party_idx = self.next_party_idx;
        self.next_party_idx += 1;

        MpcParty::connect(SimulationDelivery {
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
            if msg.recipient.is_some() && msg.recipient != Some(self.local_party_idx) {
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

// impl<M> BroadcastOutgoing<M> {
//     pub fn new(sender: broadcast::Sender<M>) -> Self {
//         Self { sender }
//     }
//
//     pub fn into_inner(self) -> broadcast::Sender<M> {
//         self.sender
//     }
// }

impl<M> DeliverOutgoing<M> for SimulationOutgoing<M>
where
    M: Clone + Unpin,
{
    type Prepared = Outgoing<Incoming<M>>;
    type Error = broadcast::error::SendError<()>;

    fn prepare(self: Pin<&Self>, msg: Outgoing<&M>) -> Result<Self::Prepared, Self::Error> {
        Ok(Outgoing {
            recipient: msg.recipient,
            msg: Incoming {
                sender: self.local_party_idx,
                msg: msg.msg.clone(),
            },
        })
    }

    fn poll_start_send(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        msg: &Self::Prepared,
    ) -> Poll<Result<(), Self::Error>> {
        self.sender
            .send(msg.clone())
            .map_err(|_| broadcast::error::SendError(()))?;
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
