use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use phantom_type::PhantomType;

pub mod two_party;

pub trait Delivery<M> {
    type Send: DeliverOutgoing<M> + Send + Unpin;
    type Receive: Stream<Item = Result<Incoming<M>, Self::ReceiveError>> + Send + Unpin + 'static;
    type ReceiveError: Send + 'static;
    fn split(self) -> (Self::Receive, Self::Send);
}

pub trait DeliverOutgoing<M> {
    type Prepared: Unpin;
    type Error;

    //TODO: open issue - prepare should return `Self::Prepared<'m>`, it must be updated once GATs
    // are stabilized
    fn prepare(self: Pin<&Self>, msg: Outgoing<&M>) -> Result<Self::Prepared, Self::Error>;
    fn poll_start_send(
        self: Pin<&mut Self>,
        cx: &mut Context,
        msg: &Self::Prepared,
    ) -> Poll<Result<(), Self::Error>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>>;
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Incoming<M> {
    pub sender: u16,
    pub msg: M,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing<M> {
    pub recipient: Option<u16>,
    pub msg: M,
}

pub trait DeliverOutgoingExt<M>: DeliverOutgoing<M> {
    fn send_all<'d, 'm, I>(&'d mut self, messages: I) -> SendAll<'d, 'm, M, Self, I::IntoIter>
    where
        Self: Unpin,
        Self::Prepared: Unpin,
        I: IntoIterator<Item = Outgoing<&'m M>>,
        I::IntoIter: Unpin,
        M: 'm,
    {
        SendAll::new(self, messages.into_iter())
    }

    fn send<'d, 'm>(
        &'d mut self,
        message: Outgoing<&'m M>,
    ) -> SendAll<'d, 'm, M, Self, iter::Once<Outgoing<&'m M>>>
    where
        Self: Unpin,
        Self::Prepared: Unpin,
        M: 'm,
    {
        self.send_all(iter::once(message))
    }

    fn shutdown(&mut self) -> Shutdown<M, Self>
    where
        Self: Unpin,
    {
        Shutdown::new(self)
    }
}

impl<M, D> DeliverOutgoingExt<M> for D where D: DeliverOutgoing<M> {}

pub struct SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<&'m M>>,
    D: DeliverOutgoing<M> + ?Sized,
    M: 'm,
{
    delivery: &'d mut D,
    messages: iter::Fuse<I>,
    next_message: Option<D::Prepared>,
}

impl<'d, 'm, M, D, I> SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<&'m M>> + Unpin,
    D: DeliverOutgoing<M> + Unpin + ?Sized,
    D::Prepared: Unpin,
{
    fn new(delivery: &'d mut D, messages: I) -> Self {
        Self {
            delivery,
            messages: messages.fuse(),
            next_message: None,
        }
    }

    fn try_start_send(&mut self, cx: &mut Context, msg: D::Prepared) -> Poll<Result<(), D::Error>> {
        match Pin::new(&mut *self.delivery).poll_start_send(cx, &msg) {
            Poll::Pending => {
                self.next_message = Some(msg);
                Poll::Pending
            }
            result => result,
        }
    }
}

impl<'d, 'm, M, D, I> Future for SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<&'m M>> + Unpin,
    D: DeliverOutgoing<M> + Unpin + ?Sized,
    D::Prepared: Unpin,
{
    type Output = Result<(), D::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Some(msg_to_send) = self.next_message.take() {
            // We have buffered message, need to send it first
            ready!(self.try_start_send(cx, msg_to_send))?
        }

        loop {
            match self.messages.next() {
                Some(msg) => {
                    let msg = Pin::new(&*self.delivery).prepare(msg)?;
                    ready!(self.try_start_send(cx, msg))?
                }
                None => {
                    ready!(Pin::new(&mut *self.delivery).poll_flush(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

pub struct Shutdown<'d, M, D>
where
    D: DeliverOutgoing<M> + Unpin + ?Sized,
{
    link: &'d mut D,
    _ph: PhantomType<M>,
}

impl<'d, M, D> Shutdown<'d, M, D>
where
    D: DeliverOutgoing<M> + Unpin + ?Sized,
{
    fn new(link: &'d mut D) -> Self {
        Self {
            link,
            _ph: PhantomType::new(),
        }
    }
}

impl<'d, M, D> Future for Shutdown<'d, M, D>
where
    D: DeliverOutgoing<M> + Unpin + ?Sized,
{
    type Output = Result<(), D::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut link = Pin::new(&mut *self.link);
        ready!(link.as_mut().poll_flush(cx))?;
        link.poll_close(cx)
    }
}
