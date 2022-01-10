//! Delivery implementation for two party protocols
//!
//! Two party delivery can be natively implemented as a server/client communication.
//!
//! This module contains [TwoParty] primitive that can be used to build a two party delivery on top
//! of any network protocol (TCP, TCP+TLS, QUIC, etc.). There are ready-to-use implementations on
//! top of most popular network protocols: TCP+TLS (see [tls module](tls)), and plain TCP (for
//! development purposes, see [insecure module](insecure))

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{self, AsyncRead, AsyncWrite};
use futures::{ready, Sink, Stream};

use phantom_type::PhantomType;
use thiserror::Error;

use delivery_core::{Delivery, Incoming, Outgoing};
use delivery_core::serialization_backend::{
    Bincode, DeserializationBackend, SerializationBackend,
};

/// A connection established between two parties that can be used to exchange messages `M`
///
/// ## Example: TCP client
/// In this example we have a client connecting to TCP server. Once connection is established, TwoParty
/// can be constructed:
/// ```rust,no_run
/// use tokio::net::TcpStream;
/// use round_based::delivery::two_party::{TwoParty, Side};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize, Clone)]
/// pub enum Msg {
///     Ping(u16),
///     Pong(u16),
/// }
///
/// # async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
/// #
/// let conn = TcpStream::connect("10.0.0.1:9090").await?;
/// let (read, write) = conn.into_split();
///
/// let delivery = TwoParty::<Msg, _, _>::new(Side::Client, read, write, 4096, 10_000);
/// # let _ = delivery;
/// #
/// # Ok(()) }
/// ```
///
/// _Note:_ if you indeed need to construct TwoParty over plain TCP, we've got it for you: see [insecure module](insecure)
pub struct TwoParty<M, R, W, S = Bincode, D = Bincode> {
    pub recv: RecvLink<M, R, D>,
    pub send: SendLink<W, S>,
}

impl<M, R, W> TwoParty<M, R, W> {
    /// Constructs a two party link from raw byte channels
    ///
    /// * `read_link` is an [`AsyncRead`] that reads bytes sent by counterparty
    /// * `write_link` is an [`AsyncWrite`] that sends bytes to the counterparty
    /// * `capacity` is an initial capacity of internal buffers. Buffers grow on sending/receiving
    ///   larger messages
    /// * `message_size_limit` limits length of serialized message. Sending/receiving larger messages
    ///   results into error that closes a channel
    /// * `side` determines whether this party is a server or a client.
    pub fn new(side: Side, read_link: R, write_link: W) -> Self {
        Self {
            recv: RecvLink::new(read_link, side),
            send: SendLink::new(write_link, side),
        }
    }

    pub fn with_limit(side: Side, read_link: R, write_link: W, message_size_limit: usize) -> Self {
        Self {
            recv: RecvLink::with_limit(read_link, side, message_size_limit),
            send: SendLink::with_limit(write_link, side, message_size_limit),
        }
    }
}

impl<M, R, W, S, D> TwoParty<M, R, W, S, D> {
    pub fn set_serialization_backend<B>(self, backend: B) -> TwoParty<M, R, W, B, D> {
        TwoParty {
            recv: self.recv,
            send: self.send.set_serialization_backend(backend),
        }
    }

    pub fn set_deserialization_backend<B>(self, backend: B) -> TwoParty<M, R, W, S, B> {
        TwoParty {
            recv: self.recv.set_deserialization_backend(backend),
            send: self.send,
        }
    }
}

impl<M, R, W, S, D> Delivery<M> for TwoParty<M, R, W, S, D>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin,
    S: SerializationBackend<M> + Send + Unpin,
    D: DeserializationBackend<M> + Send + Unpin + 'static,
    M: 'static,
{
    type Send = SendLink<W, S>;
    type Receive = RecvLink<M, R, D>;
    type SendError = io::Error;
    type ReceiveError = io::Error;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.recv, self.send)
    }
}

/// Determines the side of TwoParty channel: server/client
#[derive(Debug, Copy, Clone)]
pub enum Side {
    Server,
    Client,
}

impl Side {
    pub const fn party_index(&self) -> u16 {
        match self {
            Side::Server => 0,
            Side::Client => 1,
        }
    }

    pub const fn counterparty_index(&self) -> u16 {
        1 - self.party_index()
    }
}

/// An outgoing link to the party
///
/// Wraps AsyncWrite that delivers bytes to the party, and implements [DeliverOutgoing].
pub struct SendLink<L, S = Bincode> {
    link: L,
    serializer: S,

    message_is_being_written: bool,
    bytes_written: usize,
    message_size: usize,
    buffer: Box<[u8]>,

    side: Side,
}

impl<L> SendLink<L> {
    pub fn new(link: L, side: Side) -> Self {
        Self::with_limit(link, side, 10_000)
    }

    pub fn with_limit(link: L, side: Side, message_size_limit: usize) -> Self {
        Self {
            link,
            serializer: Bincode::default(),
            message_is_being_written: false,
            bytes_written: 0,
            message_size: 0,
            buffer: vec![0; message_size_limit].into_boxed_slice(),
            side,
        }
    }
}

impl<L, S> SendLink<L, S> {
    pub fn set_serialization_backend<B>(self, backend: B) -> SendLink<L, B> {
        SendLink {
            serializer: backend,

            link: self.link,
            message_is_being_written: self.message_is_being_written,
            bytes_written: self.bytes_written,
            message_size: self.message_size,
            buffer: self.buffer,
            side: self.side,
        }
    }
}

impl<L, S, M> Sink<Outgoing<M>> for SendLink<L, S>
where
    L: AsyncWrite + Unpin,
    S: SerializationBackend<M> + Unpin,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;

        if !this.message_is_being_written {
            return Poll::Ready(Ok(()));
        }

        while this.bytes_written < 2 {
            this.bytes_written += ready!(Pin::new(&mut this.link).poll_write_vectored(
                cx,
                &[
                    io::IoSlice::new(&this.message_size.to_be_bytes()),
                    io::IoSlice::new(&this.buffer[..this.message_size])
                ]
            ))?;
        }

        while this.bytes_written < 2 + this.message_size {
            this.bytes_written += ready!(Pin::new(&mut this.link)
                .poll_write(cx, &this.buffer[this.bytes_written - 2..this.message_size]))?;
        }

        this.message_is_being_written = false;

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, msg: Outgoing<M>) -> Result<(), Self::Error> {
        let this = &mut *self;

        if this.message_is_being_written {
            return Err(io::Error::new(io::ErrorKind::Other, MissingPollReady));
        }

        if let Some(recipient) = msg.recipient {
            if recipient != this.side.counterparty_index() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    InvalidReceiverIndex {
                        expected: this.side.counterparty_index(),
                        actual: recipient,
                    },
                ));
            }
        }

        let mut buffer = std::io::Cursor::new(&mut this.buffer[..]);
        this.serializer
            .serialize_into(&msg.msg, &mut buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, SerializeMessageError(e)))?;

        this.message_size = buffer
            .position()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, MessageSizeOverflowsUsize))?;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(<Self as Sink<Outgoing<M>>>::poll_ready(self.as_mut(), cx))?;
        ready!(Pin::new(&mut self.link).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(<Self as Sink<Outgoing<M>>>::poll_ready(self.as_mut(), cx))?;
        ready!(Pin::new(&mut self.link).poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

/// An incoming link from the party
///
/// Wraps AsyncRead that receives bytes from the party, and implements [`Stream<Item=Incoming<M>>`](Stream).
pub struct RecvLink<M, R, D = Bincode> {
    link: R,
    deserializer: D,
    side: Side,

    buffer: Box<[u8]>,
    buffer_filled: usize,

    _ph: PhantomType<M>,
}

impl<M, L> RecvLink<M, L> {
    /// Constructs a new receive link
    ///
    /// `link` is a `AsyncRead` that receives bytes from counterparty. `capacity` is a maximum length
    /// of serialized message (receiving bigger message results into error).
    pub fn new(link: L, side: Side) -> Self {
        Self::with_limit(link, side, 10_000)
    }

    pub fn with_limit(link: L, side: Side, message_size_limit: usize) -> Self {
        RecvLink {
            link,
            deserializer: Bincode::default(),
            side,

            buffer: vec![0; message_size_limit + 2].into_boxed_slice(),
            buffer_filled: 0,

            _ph: PhantomType::new(),
        }
    }
}

impl<M, L, D> RecvLink<M, L, D> {
    pub fn set_deserialization_backend<B>(self, backend: B) -> RecvLink<M, L, B> {
        RecvLink {
            deserializer: backend,

            link: self.link,
            side: self.side,
            buffer: self.buffer,
            buffer_filled: self.buffer_filled,
            _ph: PhantomType::new(),
        }
    }

    fn parse_message_size(&self) -> Option<u16> {
        if self.buffer_filled < 2 {
            return None;
        }
        let message_size: [u8; 2] = self.buffer[..2]
            .try_into()
            .expect("slice of two elements always converts into array of two elements");
        let message_size = u16::from_be_bytes(message_size);
        Some(message_size)
    }
}

impl<M, R, D> Stream for RecvLink<M, R, D>
where
    R: AsyncRead + Unpin,
    D: DeserializationBackend<M> + Unpin,
{
    type Item = io::Result<Incoming<M>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        let message_size = loop {
            if let Some(message_size) = this.parse_message_size().map(usize::from) {
                if message_size + 2 <= this.buffer_filled {
                    break message_size;
                }
            }

            let received_bytes = ready!(
                Pin::new(&mut this.link).poll_read(cx, &mut this.buffer[this.buffer_filled..])
            )?;

            if received_bytes == 0 && this.buffer_filled == 0 {
                return Poll::Ready(None);
            } else if received_bytes == 0 {
                return Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())));
            } else {
                this.buffer_filled += received_bytes;
            }
        };

        let parsed_message: io::Result<M> = this
            .deserializer
            .deserialize(&this.buffer[2..2 + message_size])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, DeserializeMessageError(e)));

        this.buffer.copy_within(2 + message_size.., 0);
        this.buffer_filled -= 2 + message_size;

        Poll::Ready(Some(Ok(Incoming {
            sender: this.side.counterparty_index(),
            msg: parsed_message?,
        })))
    }
}

#[derive(Debug, Error)]
#[error("invalid recipient index: expected={expected} got={actual}")]
struct InvalidReceiverIndex {
    expected: u16,
    actual: u16,
}

#[derive(Debug, Error)]
#[error("could not serialize message")]
struct SerializeMessageError<E>(#[source] E);

#[derive(Debug, Error)]
#[error("could not deserialize message")]
struct DeserializeMessageError<E>(#[source] E);

#[derive(Debug, Error)]
#[error("message is too large (overflows usize)")]
struct MessageSizeOverflowsUsize;

#[derive(Debug, Error)]
#[error("missing prior `poll_ready` call")]
struct MissingPollReady;

#[cfg(test)]
mod tests {
    use std::cmp::min;
    use std::io::Write;
    use std::num::NonZeroU32;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::{AsyncRead, TryStreamExt};
    use tokio::io;

    use delivery_core::Incoming;
    use delivery_core::serialization_backend::{DeserializationBackend, SerializationBackend};

    use super::{RecvLink, Side};

    #[tokio::test]
    async fn receives_two_messages() {
        let raw = &[
            0x00, 0x04, 0xfa, 0xbe, 0x82, 0x6c, // 1st message
            0x00, 0x04, 0x7f, 0x58, 0x12, 0x1d, // 2nd message
        ];

        let should_receive: &[Incoming<NonZeroU32>] = &[
            Incoming {
                sender: 1,
                msg: NonZeroU32::new(0xfabe826c).unwrap(),
            },
            Incoming {
                sender: 1,
                msg: NonZeroU32::new(0x7f58121d).unwrap(),
            },
        ];

        let chunk_sizes = [1, 3, 6, 9, 12];
        for chunk_size in chunk_sizes {
            let stream =
                RecvLink::with_limit(ReadChunkByChunk::new(chunk_size, raw), Side::Server, 8)
                    .set_deserialization_backend(NonZeroU32Encoding);
            assert_eq!(
                stream.try_collect::<Vec<_>>().await.unwrap(),
                should_receive
            )
        }
    }

    struct ReadChunkByChunk<'b> {
        bytes: &'b [u8],
        chunk_size: usize,
        is_ready: bool,
    }

    impl<'b> ReadChunkByChunk<'b> {
        pub fn new(chunk_size: usize, bytes: &'b [u8]) -> Self {
            Self {
                bytes,
                chunk_size,
                is_ready: true,
            }
        }
    }

    impl<'b> AsyncRead for ReadChunkByChunk<'b> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            if !self.is_ready {
                self.is_ready = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if self.bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }

            let size = min(self.chunk_size, buf.len());
            let size = min(size, self.bytes.len());
            buf[..size].copy_from_slice(&self.bytes[..size]);
            self.bytes = &self.bytes[size..];
            self.is_ready = false;

            Poll::Ready(Ok(size))
        }
    }

    struct NonZeroU32Encoding;
    #[derive(Debug, thiserror::Error)]
    enum InvalidInteger {
        #[error("mismatched size of the message: expected 4 bytes, got {length} bytes")]
        MismatchedSize { length: usize },
        #[error("integer is zero")]
        Zero,
    }

    impl SerializationBackend<NonZeroU32> for NonZeroU32Encoding {
        type Error = io::Error;

        fn serialize_into<W: Write>(
            &self,
            value: &NonZeroU32,
            mut buffer: W,
        ) -> Result<(), Self::Error> {
            buffer.write_all(&value.get().to_be_bytes())
        }
    }
    impl DeserializationBackend<NonZeroU32> for NonZeroU32Encoding {
        type Error = InvalidInteger;

        fn deserialize(&self, bytes: &[u8]) -> Result<NonZeroU32, Self::Error> {
            let bytes: [u8; 4] = bytes
                .try_into()
                .map_err(|_| InvalidInteger::MismatchedSize {
                    length: bytes.len(),
                })?;
            let integer = u32::from_be_bytes(bytes);
            integer.try_into().map_err(|_| InvalidInteger::Zero)
        }
    }
}
