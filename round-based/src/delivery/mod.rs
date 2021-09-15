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
use phantom_type::PhantomType;

// #[cfg(feature = "trusted-delivery")]
// #[cfg_attr(docsrs, doc(cfg(feature = "trusted-delivery")))]
// pub mod trusted_delivery;
// pub mod two_party;
// pub mod utils;

/// A pair of incoming and outgoing delivery channels
pub trait Delivery<M> {
    /// Outgoing delivery channel
    type Send: for<'m> DeliverOutgoing<'m, &'m M> + Send + Unpin;
    /// Incoming delivery channel
    type Receive: Stream<Item = Result<Incoming<M>, Self::ReceiveError>> + Send + Unpin + 'static;
    /// Error of incoming delivery channel
    type ReceiveError: Send + 'static;
    /// Returns a pair of incoming and outgoing delivery channels
    fn split(self) -> (Self::Receive, Self::Send);
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
pub trait DeliverOutgoing<'m, M: 'm> {
    /// Message prepared to be sent
    type Prepared: Unpin + 'm;
    /// Delivery error
    type Error;

    //TODO: open issue - prepare should return `Self::Prepared<'m>`, it must be updated once GATs
    // are stabilized
    /// Prepares the message to be sent
    ///
    /// Performs one-time calculation on sending message. For instance, it can estimate size of
    /// serialized message to know how much space it needs to claim in a socket buffer.
    fn prepare(self: Pin<&Self>, msg: Outgoing<M>) -> Result<Self::Prepared, Self::Error>;
    /// Queues sending the message
    ///
    /// Once it returned `Poll::Ready(Ok(()))`, the message is queued. In order to actually send the
    /// message, you need to flush it via [poll_flush](Self::poll_flush).
    fn poll_start_send(
        self: Pin<&mut Self>,
        cx: &mut Context,
        msg: &mut Self::Prepared,
    ) -> Poll<Result<(), Self::Error>>;
    /// Flushes the underlying I/O
    ///
    /// After it returned `Poll::Ready(Ok(()))`, all the queued messages prior the call are sent.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>>;
    /// Closes the underlying I/O
    ///
    /// Flushes and closes the channel
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>>;
}

/// Incoming message
///
/// Contains a received message and index of party who sent the message
#[derive(Debug, Clone, PartialEq)]
pub struct Incoming<M> {
    /// Index of a party who sent the message
    pub sender: u16,
    /// Received message
    pub msg: M,
}

/// Outgoing message
///
/// Contains a message that local party needs to send, and index of recipient party (`None` if it's
/// broadcast message)
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing<M> {
    /// Index of recipient
    ///
    /// `None` if the message is meant to be received by all the parties (ie. it's broadcast message)
    pub recipient: Option<u16>,
    /// Message being sent
    pub msg: M,
}

/// An extension trait for [DeliverOutgoing] that provides a variety of convenient functions
pub trait DeliverOutgoingExt<'m, M: 'm>: DeliverOutgoing<'m, M> {
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
    /// use round_based::{DeliverOutgoingExt, Outgoing};
    /// let msgs = vec!["Hello", "Goodbye"];
    /// outgoing.send_all(msgs.iter().map(|msg| Outgoing{ recipient: Some(1), msg })).await?;
    /// # Ok(()) }
    /// ```
    fn send_all<'d, I>(&'d mut self, messages: I) -> SendAll<'d, 'm, M, Self, I::IntoIter>
    where
        Self: Unpin,
        I: IntoIterator<Item = Outgoing<M>>,
        I::IntoIter: Unpin,
    {
        SendAll::new(self, messages.into_iter())
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
    /// use round_based::{DeliverOutgoingExt, Outgoing};
    /// outgoing.send(Outgoing{ recipient: Some(1), msg: &"Ping" }).await?;
    /// # Ok(()) }
    /// ```
    fn send<'d>(
        &'d mut self,
        message: Outgoing<M>,
    ) -> SendAll<'d, 'm, M, Self, iter::Once<Outgoing<M>>>
    where
        Self: Unpin,
        M: Unpin,
    {
        self.send_all(iter::once(message))
    }

    /// Shuts down the outgoing channel
    ///
    /// Method signature is similar to:
    /// ```rust,ignore
    /// async fn shutdown(&mut self) -> Result<()>;
    /// ```
    ///
    /// Once there is nothing else to send, the channel must be utilized by calling this method which
    /// flushes and closes underlying I/O.
    fn shutdown<'d>(&'d mut self) -> Shutdown<'d, 'm, M, Self>
    where
        Self: Unpin,
    {
        Shutdown::new(self)
    }
}

impl<'m, M: 'm, D> DeliverOutgoingExt<'m, M> for D where D: DeliverOutgoing<'m, M> {}

/// A future for [`send_all`](DeliverOutgoingExt::send_all) method
pub struct SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<M>>,
    D: DeliverOutgoing<'m, M> + ?Sized,
    // M: 'm,
{
    delivery: &'d mut D,
    messages: iter::Fuse<I>,
    next_message: Option<D::Prepared>,
}

impl<'d, 'm, M, D, I> SendAll<'d, 'm, M, D, I>
where
    I: Iterator<Item = Outgoing<M>> + Unpin,
    D: DeliverOutgoing<'m, M> + Unpin + ?Sized,
    D::Prepared: Unpin,
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
        mut msg: D::Prepared,
    ) -> Poll<Result<(), D::Error>> {
        match Pin::new(&mut *self.delivery).poll_start_send(cx, &mut msg) {
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
    I: Iterator<Item = Outgoing<M>> + Unpin,
    D: DeliverOutgoing<'m, M> + Unpin + ?Sized,
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

/// A future for [`shutdown`](DeliverOutgoingExt::shutdown) method
pub struct Shutdown<'d, 'm, M, D>
where
    D: DeliverOutgoing<'m, M> + Unpin + ?Sized,
{
    link: &'d mut D,
    _ph: PhantomType<fn(&'m M)>,
}

impl<'d, 'm, M, D> Shutdown<'d, 'm, M, D>
where
    D: DeliverOutgoing<'m, M> + Unpin + ?Sized,
{
    fn new(link: &'d mut D) -> Self {
        Self {
            link,
            _ph: PhantomType::new(),
        }
    }
}

impl<'d, 'm, M, D> Future for Shutdown<'d, 'm, M, D>
where
    D: DeliverOutgoing<'m, M> + Unpin + ?Sized,
{
    type Output = Result<(), D::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut link = Pin::new(&mut *self.link);
        ready!(link.as_mut().poll_flush(cx))?;
        link.poll_close(cx)
    }
}
