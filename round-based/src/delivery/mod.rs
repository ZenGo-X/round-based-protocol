//! # Messages sending/receiving
//!
//! In this module we provide traits determining a way of exchanging messages between parties. Prior to
//! carrying out any protocol, you typically need to obtain an instance of [`Delivery`] trait, basically
//! it's a pair of delivery channels of incoming and outgoing messages.
//!
//! Receiving channel (or channel of incoming messages) is a [`Stream`], quite popular asynchronous
//! abstraction. Sending channel (or channel of outgoing messages) is defined with [`DeliverOutgoing`]
//! trait that's introduced in this module, it gives us more control on sending messages and fits
//! library needs nicely than similar traits like `Sink`.
//!
//! We provide several delivery implementations for most common cases. See [two_party] module.

use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};

// #[cfg(feature = "trusted-delivery")]
// #[cfg_attr(docsrs, doc(cfg(feature = "trusted-delivery")))]
// pub mod trusted_delivery;
pub mod two_party;
pub mod utils;

/// A pair of incoming and outgoing delivery channels
pub trait Delivery<M> {
    /// Outgoing delivery channel
    type Send: OutgoingDelivery<M> + Send + Unpin;
    /// Incoming delivery channel
    type Receive: Stream<Item = Result<Incoming<M>, Self::ReceiveError>> + Send + Unpin + 'static;
    /// Error of incoming delivery channel
    type ReceiveError: Send + 'static;
    /// Returns a pair of incoming and outgoing delivery channels
    fn split(self) -> (Self::Receive, Self::Send);
}

/// Manages outgoing delivery channel
pub trait OutgoingChannel {
    /// Delivery error
    type Error;

    /// Flushes the underlying I/O
    ///
    /// After it returned `Poll::Ready(Ok(()))`, all the queued messages prior the call are sent.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>>;

    /// Closes the underlying I/O
    ///
    /// Flushes and closes the channel
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>>;
}

/// Delivers outgoing messages, asynchronously
///
/// The trait defines all the logic related to delivery of outgoing messages. Specifically, given the
/// message which needs to be sent and an index of recipient party, it finds the way to reach that
/// party and sends the message. Also, the trait should authenticate and encrypt messages as
/// most of the protocols expect it to be done at network layer.
///
/// [DeliverOutgoingExt] trait extends this trait and defines convenient `.await`-friendly methods, like
/// [send_all] or [shutdown].
///
/// [send_all]: DeliverOutgoingExt::send_all
/// [shutdown]: DeliverOutgoingExt::shutdown
pub trait OutgoingDelivery<M>: OutgoingChannel {
    /// Size of the message
    type MessageSize: Unpin;

    /// Returns size of the message that's required by [`poll_start_send`](Self::poll_start_send)
    ///
    /// The method returns a error if message size cannot be evaluated
    fn message_size(self: Pin<&Self>, msg: Outgoing<&M>) -> Result<Self::MessageSize, Self::Error>;

    /// Attempts to prepare channel for sending a message of given `msg_size`
    ///
    /// Once it returned `Poll::Ready(Ok(()))`, you can call [`start_send`](Self::start_send) with
    /// message of given size. Note that in order to actually send the message, you need to flush
    /// the channel via [poll_flush](Self::poll_flush).
    ///
    /// If this method results in error, it typically means that the message of that size cannot be
    /// sent.
    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        msg_size: &Self::MessageSize,
    ) -> Poll<Result<(), Self::Error>>;

    /// Queues sending the message
    ///
    /// Before calling this method, you need to ensure that channel is ready to process it by
    /// calling [`poll_ready`](Self::poll_ready), otherwise it returns error.
    fn start_send(self: Pin<&mut Self>, msg: Outgoing<&M>) -> Result<(), Self::Error>;
}

/// Incoming message
///
/// Contains a received message and index of party who sent the message
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Incoming<M> {
    /// Index of a party who sent the message
    pub sender: u16,
    /// Received message
    pub msg: M,
}

// impl<M> Incoming<M> {
//     pub fn map<M2, F>(self, f: F) -> Incoming<M2>
//     where
//         F: FnOnce(M) -> M2,
//     {
//         Incoming {
//             sender: self.sender,
//             msg: f(self.msg),
//         }
//     }
//
//     pub fn as_ref(&self) -> Incoming<&M> {
//         Incoming {
//             sender: self.sender,
//             msg: &self.msg,
//         }
//     }
// }

/// Outgoing message
///
/// Contains a message that local party needs to send, and index of recipient party (`None` if it's
/// broadcast message)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Outgoing<M> {
    /// Index of recipient
    ///
    /// `None` if the message is meant to be received by all the parties (ie. it's broadcast message)
    pub recipient: Option<u16>,
    /// Message being sent
    pub msg: M,
}

impl<M> Outgoing<M> {
    pub fn as_ref(&self) -> Outgoing<&M> {
        Outgoing {
            recipient: self.recipient,
            msg: &self.msg,
        }
    }

    pub fn map<M2, F>(self, f: F) -> Outgoing<M2>
    where
        F: FnOnce(M) -> M2,
    {
        Outgoing {
            recipient: self.recipient,
            msg: f(self.msg),
        }
    }
}

/// An extension trait for [DeliverOutgoing] that provides a variety of convenient functions
pub trait OutgoingDeliveryExt<M>: OutgoingDelivery<M> {
    /// Sends a sequence of messages
    ///
    /// Method signature is similar to:
    /// ```rust,ignore
    /// async fn send_all(&mut self, messages: impl IntoIterator<Item = Outgoing<&M>>) -> Result<()>;
    /// ```
    ///
    /// Method sends messages one-by-one and then flushes the channel.
    ///
    /// ## Example
    /// ```rust,no_run
    /// # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut outgoing: round_based::simulation::SimulationOutgoing<&'static str> = unimplemented!();
    /// use round_based::{OutgoingDeliveryExt, Outgoing};
    /// let msgs = vec!["Hello", "Goodbye"];
    /// outgoing.send_all(msgs.iter().map(|msg| Outgoing{ recipient: Some(1), msg })).await?;
    /// # Ok(()) }
    /// ```
    fn send_all<'m, I>(&mut self, messages: I) -> SendAll<'_, 'm, M, Self, I::IntoIter>
    where
        Self: Unpin,
        I: IntoIterator<Item = Outgoing<&'m M>>,
        I::IntoIter: Unpin,
    {
        SendAll::<M, Self, I::IntoIter>::new(self, messages.into_iter())
    }

    /// Sends one message
    ///
    /// Method signature is similar to:
    /// ```rust,ignore
    /// async fn send(&mut self, messages: Outgoing<&M>) -> Result<()>;
    /// ```
    ///
    /// Method sends one message and flushes the channel.
    ///
    /// ## Example
    /// ```rust,no_run
    /// # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut outgoing: round_based::simulation::SimulationOutgoing<&'static str> = unimplemented!();
    /// use round_based::{OutgoingDeliveryExt, Outgoing};
    /// outgoing.send(Outgoing{ recipient: Some(1), msg: &"Ping" }).await?;
    /// # Ok(()) }
    /// ```
    fn send<'m>(
        &mut self,
        message: Outgoing<&'m M>,
    ) -> SendAll<'_, 'm, M, Self, iter::Once<Outgoing<&'m M>>>
    where
        Self: Unpin,
    {
        self.send_all(iter::once(message))
    }
}

pub trait OutgoingChannelExt: OutgoingChannel {
    /// Shuts down the outgoing channel
    ///
    /// Method signature is similar to:
    /// ```rust,ignore
    /// async fn shutdown(&mut self) -> Result<()>;
    /// ```
    ///
    /// Once there is nothing else to send, the channel must be utilized by calling this method which
    /// flushes and closes underlying I/O.
    fn shutdown(&mut self) -> Shutdown<Self>
    where
        Self: Unpin,
    {
        Shutdown::new(self)
    }
}

impl<M, D> OutgoingDeliveryExt<M> for D where D: OutgoingDelivery<M> {}
impl<D> OutgoingChannelExt for D where D: OutgoingChannel {}

/// A future for [`send_all`](DeliverOutgoingExt::send_all) method
pub struct SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<&'m M>>,
    D: OutgoingDelivery<M> + ?Sized,
{
    delivery: &'d mut D,
    messages: iter::Fuse<I>,
    next_message: Option<(Outgoing<&'m M>, D::MessageSize)>,
}

impl<'d, 'm, M, D, I> SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<&'m M>> + Unpin,
    D: OutgoingDelivery<M> + Unpin + ?Sized,
{
    fn new(delivery: &'d mut D, messages: I) -> Self {
        Self {
            delivery,
            messages: messages.fuse(),
            next_message: None,
        }
    }

    fn try_start_send(
        &mut self,
        cx: &mut Context,
        msg: Outgoing<&'m M>,
        msg_size: D::MessageSize,
    ) -> Poll<Result<(), D::Error>> {
        match Pin::new(&mut *self.delivery).poll_ready(cx, &msg_size) {
            Poll::Pending => {
                self.next_message = Some((msg, msg_size));
                Poll::Pending
            }
            Poll::Ready(Ok(())) => Poll::Ready(Pin::new(&mut *self.delivery).start_send(msg)),
            result => result,
        }
    }
}

impl<'d, 'm, M, D, I> Future for SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<&'m M>> + Unpin,
    D: OutgoingDelivery<M> + Unpin + ?Sized,
{
    type Output = Result<(), D::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Some((msg, msg_size)) = self.next_message.take() {
            // We have buffered message, need to send it first
            ready!(self.try_start_send(cx, msg, msg_size))?
        }

        loop {
            match self.messages.next() {
                Some(msg) => {
                    let msg_size = Pin::new(&*self.delivery).message_size(msg)?;
                    ready!(self.try_start_send(cx, msg, msg_size))?
                }
                None => {
                    ready!(Pin::new(&mut *self.delivery).poll_flush(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

/// A future for [`shutdown`](DeliverOutgoingExt::shutdown) method
pub struct Shutdown<'d, D>
where
    D: OutgoingChannel + Unpin + ?Sized,
{
    link: &'d mut D,
}

impl<'d, D> Shutdown<'d, D>
where
    D: OutgoingChannel + Unpin + ?Sized,
{
    fn new(link: &'d mut D) -> Self {
        Self { link }
    }
}

impl<'d, D> Future for Shutdown<'d, D>
where
    D: OutgoingChannel + Unpin + ?Sized,
{
    type Output = Result<(), D::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut link = Pin::new(&mut *self.link);
        ready!(link.as_mut().poll_flush(cx))?;
        link.poll_close(cx)
    }
}
