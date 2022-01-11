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

use delivery_core::serialization_backend::{Bincode, DeserializationBackend, SerializationBackend};
use delivery_core::{Delivery, Incoming, Outgoing};

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
pub struct Connection<M, R, W, S = Bincode, D = Bincode> {
    pub recv: Incomings<M, R, D>,
    pub send: Outgoings<W, S>,
}

impl<M, R, W> Connection<M, R, W> {
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
            recv: Incomings::new(read_link, side),
            send: Outgoings::new(write_link, side),
        }
    }

    pub fn with_limit(side: Side, read_link: R, write_link: W, message_size_limit: usize) -> Self {
        Self {
            recv: Incomings::with_limit(read_link, side, message_size_limit),
            send: Outgoings::with_limit(write_link, side, message_size_limit),
        }
    }
}

impl<M, R, W, S, D> Connection<M, R, W, S, D> {
    pub fn set_serialization_backend<B>(self, backend: B) -> Connection<M, R, W, B, D> {
        Connection {
            recv: self.recv,
            send: self.send.set_serialization_backend(backend),
        }
    }

    pub fn set_deserialization_backend<B>(self, backend: B) -> Connection<M, R, W, S, B> {
        Connection {
            recv: self.recv.set_deserialization_backend(backend),
            send: self.send,
        }
    }
}

impl<M, R, W, S, D> Delivery<M> for Connection<M, R, W, S, D>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin,
    S: SerializationBackend<M> + Send + Unpin,
    D: DeserializationBackend<M> + Send + Unpin + 'static,
    M: 'static,
{
    type Send = Outgoings<W, S>;
    type Receive = Incomings<M, R, D>;
    type SendError = SendError<S::Error>;
    type ReceiveError = RecvError<D::Error>;

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
pub struct Outgoings<L, S = Bincode> {
    link: L,
    serializer: S,

    message_is_being_written: bool,
    bytes_written: usize,
    message_size: u16,
    buffer: Box<[u8]>,

    side: Side,
}

impl<L> Outgoings<L> {
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

impl<L, S> Outgoings<L, S> {
    pub fn set_serialization_backend<B>(self, backend: B) -> Outgoings<L, B> {
        Outgoings {
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

impl<L, S, M> Sink<Outgoing<M>> for Outgoings<L, S>
where
    L: AsyncWrite + Unpin,
    S: SerializationBackend<M> + Unpin,
{
    type Error = SendError<S::Error>;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;

        if !this.message_is_being_written {
            return Poll::Ready(Ok(()));
        }

        while this.bytes_written < 2 {
            let bytes_written = ready!(Pin::new(&mut this.link).poll_write_vectored(
                cx,
                &[
                    io::IoSlice::new(&this.message_size.to_be_bytes()[this.bytes_written..]),
                    io::IoSlice::new(&this.buffer[..usize::from(this.message_size)])
                ]
            ))?;

            if bytes_written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into()));
            }

            this.bytes_written += bytes_written;
        }

        while this.bytes_written < 2 + usize::from(this.message_size) {
            let bytes_written = ready!(Pin::new(&mut this.link).poll_write(
                cx,
                &this.buffer[this.bytes_written - 2..usize::from(this.message_size)]
            ))?;

            if bytes_written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into()));
            }

            this.bytes_written += bytes_written;
        }

        this.bytes_written = 0;
        this.message_is_being_written = false;

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, msg: Outgoing<M>) -> Result<(), Self::Error> {
        let this = &mut *self;

        if this.message_is_being_written {
            return Err(SendErrorReason::MissingPollReady.into());
        }

        if let Some(recipient) = msg.recipient {
            if recipient != this.side.counterparty_index() {
                return Err(SendErrorReason::InvalidReceiverIndex {
                    expected: this.side.counterparty_index(),
                    actual: recipient,
                }
                .into());
            }
        }

        let mut buffer = std::io::Cursor::new(&mut this.buffer[..]);
        this.serializer
            .serialize_into(&msg.msg, &mut buffer)
            .map_err(SendErrorReason::SerializeMessage)?;

        this.message_size = buffer
            .position()
            .try_into()
            .or(Err(SendErrorReason::MessageSizeOverflowsUsize))?;

        this.message_is_being_written = true;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(<Self as Sink<Outgoing<M>>>::poll_ready(self.as_mut(), cx))?;
        ready!(Pin::new(&mut self.link).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(<Self as Sink<Outgoing<M>>>::poll_ready(self.as_mut(), cx))?;
        ready!(Pin::new(&mut self.link).poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

/// An incoming link from the party
///
/// Wraps AsyncRead that receives bytes from the party, and implements [`Stream<Item=Incoming<M>>`](Stream).
pub struct Incomings<M, R, D = Bincode> {
    link: R,
    deserializer: D,
    side: Side,

    buffer: Box<[u8]>,
    buffer_filled: usize,

    _ph: PhantomType<M>,
}

impl<M, L> Incomings<M, L> {
    /// Constructs a new receive link
    ///
    /// `link` is a `AsyncRead` that receives bytes from counterparty. `capacity` is a maximum length
    /// of serialized message (receiving bigger message results into error).
    pub fn new(link: L, side: Side) -> Self {
        Self::with_limit(link, side, 10_000)
    }

    pub fn with_limit(link: L, side: Side, message_size_limit: usize) -> Self {
        Incomings {
            link,
            deserializer: Bincode::default(),
            side,

            buffer: vec![0; message_size_limit + 2].into_boxed_slice(),
            buffer_filled: 0,

            _ph: PhantomType::new(),
        }
    }
}

impl<M, L, D> Incomings<M, L, D> {
    pub fn set_deserialization_backend<B>(self, backend: B) -> Incomings<M, L, B> {
        Incomings {
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

impl<M, R, D> Stream for Incomings<M, R, D>
where
    R: AsyncRead + Unpin,
    D: DeserializationBackend<M> + Unpin,
{
    type Item = Result<Incoming<M>, RecvError<D::Error>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        let message_size = loop {
            if let Some(message_size) = this.parse_message_size().map(usize::from) {
                if message_size > this.buffer.len() - 2 {
                    return Poll::Ready(Some(Err(RecvErrorReason::MessageTooLarge {
                        message_size,
                        limit: this.buffer.len() - 2,
                    }
                    .into())));
                }
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
                return Poll::Ready(Some(Err(
                    io::Error::from(io::ErrorKind::UnexpectedEof).into()
                )));
            } else {
                this.buffer_filled += received_bytes;
            }
        };

        let parsed_message: Result<M, _> = this
            .deserializer
            .deserialize(&this.buffer[2..2 + message_size])
            .map_err(RecvErrorReason::DeserializeMessage);

        this.buffer.copy_within(2 + message_size.., 0);
        this.buffer_filled -= 2 + message_size;

        Poll::Ready(Some(Ok(Incoming {
            sender: this.side.counterparty_index(),
            msg: parsed_message?,
        })))
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct SendError<S>(#[from] SendErrorReason<S>);

#[derive(Debug, Error)]
pub enum SendErrorReason<S> {
    #[error("invalid recipient index: expected={expected} got={actual}")]
    InvalidReceiverIndex { expected: u16, actual: u16 },
    #[error("could not serialize message")]
    SerializeMessage(#[source] S),
    #[error("message is too large (overflows usize)")]
    MessageSizeOverflowsUsize,
    #[error("missing prior `poll_ready` call")]
    MissingPollReady,
    #[error(transparent)]
    Io(io::Error),
}

impl<S> From<io::Error> for SendError<S> {
    fn from(err: io::Error) -> Self {
        SendError(SendErrorReason::Io(err))
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct RecvError<S>(#[from] RecvErrorReason<S>);

#[derive(Debug, Error)]
pub enum RecvErrorReason<S> {
    #[error("message is too large: size={message_size}bytes, limit={limit}bytes")]
    MessageTooLarge { message_size: usize, limit: usize },
    #[error("could not deserialize message")]
    DeserializeMessage(#[source] S),
    #[error(transparent)]
    Io(io::Error),
}

impl<S> From<io::Error> for RecvError<S> {
    fn from(err: io::Error) -> Self {
        RecvError(RecvErrorReason::Io(err))
    }
}

#[derive(Debug, Error)]
#[error("could not deserialize message")]
struct DeserializeMessageError<E>(#[source] E);

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::num::NonZeroU32;
    use std::pin::Pin;

    use futures::{Sink, SinkExt, StreamExt, TryStreamExt};
    use futures_test::{io::*, test};
    use matches::assert_matches;

    use delivery_core::serialization_backend::{DeserializationBackend, SerializationBackend};
    use delivery_core::{Incoming, Outgoing};

    use super::{
        Incomings, Outgoings, RecvError, RecvErrorReason, SendError, SendErrorReason, Side,
    };

    #[test]
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
            let channel = raw.as_ref().interleave_pending().limited(chunk_size);
            let stream = Incomings::with_limit(channel, Side::Server, 6)
                .set_deserialization_backend(NonZeroU32Encoding);
            assert_eq!(
                stream.try_collect::<Vec<_>>().await.unwrap(),
                should_receive
            )
        }
    }

    #[test]
    async fn deserialization_error_doesnt_prevent_from_receiving_next_message() {
        let raw = &[
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // invalid message: integer = 0
            0x00, 0x03, 0x7f, 0x58, 0x12, // invalid message: mismatched size
            0x00, 0x04, 0x7f, 0x58, 0x12, 0x1d, // 2nd message
        ];

        let mut stream = Incomings::with_limit(raw.as_ref(), Side::Server, 4)
            .set_deserialization_backend(NonZeroU32Encoding);

        assert_matches!(
            stream.next().await,
            Some(Err(RecvError(RecvErrorReason::DeserializeMessage(
                DecodeError::Zero
            ))))
        );
        assert_matches!(
            stream.next().await,
            Some(Err(RecvError(RecvErrorReason::DeserializeMessage(
                DecodeError::MismatchedSize { length: 3 }
            ))))
        );
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Incoming {
                sender: 1,
                msg: NonZeroU32::try_from(0x7f58121d).unwrap(),
            }
        );
        assert!(stream.next().await.is_none());
    }

    #[test]
    async fn propagates_unexpected_eof_error() {
        let raw = &[
            0x00, 0x04, 0xfa, 0xbe, 0x82, 0x6c, // 1st message
            0x00, 0x04, 0x7f, 0x58, 0x12, // incomplete 2nd message
        ];

        let mut stream = Incomings::with_limit(raw.as_ref(), Side::Server, 4)
            .set_deserialization_backend(NonZeroU32Encoding);

        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Incoming {
                sender: 1,
                msg: NonZeroU32::try_from(0xfabe826c).unwrap(),
            }
        );
        assert_matches!(
            stream.next().await, Some(Err(RecvError(RecvErrorReason::Io(err)))) if err.kind() == io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    async fn sends_two_messages() {
        let messages = &[
            Outgoing {
                recipient: Some(1),
                msg: 0xfabe826c,
            },
            Outgoing {
                recipient: Some(1),
                msg: 0x7f58121d,
            },
        ];

        let should_be_sent = &[
            0x00, 0x04, 0xfa, 0xbe, 0x82, 0x6c, // 1st message
            0x00, 0x04, 0x7f, 0x58, 0x12, 0x1d, // 2nd message
        ];

        let chunk_sizes = [1, 3, 6, 9, 12];

        for chunk_size in chunk_sizes {
            let mut buffer = [0u8; 12];
            let channel = futures::io::Cursor::new(buffer.as_mut())
                .interleave_pending_write()
                .limited_write(chunk_size)
                .track_closed();
            let mut sink = Outgoings::with_limit(channel, Side::Server, 6)
                .set_serialization_backend(NonZeroU32Encoding);

            sink.feed(messages[0]).await.unwrap();
            sink.feed(messages[1]).await.unwrap();
            sink.close().await.unwrap();

            assert_eq!(&buffer, should_be_sent);
        }
    }

    #[test]
    async fn dont_send_malformed_message() {
        let mut buffer = [0u8; 12];

        let channel = futures::io::Cursor::new(buffer.as_mut());
        let mut sink =
            Outgoings::new(channel, Side::Server).set_serialization_backend(NonZeroU32Encoding);

        // sending message to ourselves is invalid behaviour
        assert_matches!(sink.feed(Outgoing {
            recipient: Some(0), 
            msg: 0x11223344
        }).await, Err(SendError(SendErrorReason::InvalidReceiverIndex { expected, actual})) if expected == 1 && actual == 0);
        // sending zero causes encoding error
        assert_matches!(
            sink.feed(Outgoing {
                recipient: Some(1),
                msg: 0x00000000,
            })
            .await,
            Err(SendError(SendErrorReason::SerializeMessage(
                EncodeError::Zero
            )))
        );
        // Sending a valid message
        sink.feed(Outgoing {
            recipient: Some(1),
            msg: 0x11112222,
        })
        .await
        .unwrap();
        // Calling `start_send` without prior `poll_ready` call is an error
        assert_matches!(
            Pin::new(&mut sink).start_send(Outgoing {
                recipient: Some(1),
                msg: 0x11223344,
            }),
            Err(SendError(SendErrorReason::MissingPollReady))
        );
        // Sending another valid message
        sink.feed(Outgoing {
            recipient: Some(1),
            msg: 0x33334444,
        })
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let buffer_should_be = [
            0x00, 0x04, 0x11, 0x11, 0x22, 0x22, // 1st message
            0x00, 0x04, 0x33, 0x33, 0x44, 0x44, // 2nd message
        ];

        assert_eq!(buffer, buffer_should_be);
    }

    #[test]
    async fn receiving_too_large_message_results_in_error() {
        let raw = &[0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut stream = Incomings::with_limit(raw.as_ref(), Side::Server, 4)
            .set_deserialization_backend(NonZeroU32Encoding);
        let result = stream.next().await;
        assert_matches!(
            result,
            Some(Err(RecvError(RecvErrorReason::MessageTooLarge {
                message_size: 5,
                limit: 4,
            })))
        );
    }

    struct NonZeroU32Encoding;
    #[derive(Debug, thiserror::Error)]
    enum DecodeError {
        #[error("mismatched size of the message: expected 4 bytes, got {length} bytes")]
        MismatchedSize { length: usize },
        #[error("integer is zero")]
        Zero,
    }
    #[derive(Debug, thiserror::Error)]
    enum EncodeError {
        #[error("integer is zero")]
        Zero,
        #[error(transparent)]
        Io(#[from] io::Error),
    }

    impl SerializationBackend<u32> for NonZeroU32Encoding {
        type Error = EncodeError;

        fn serialize_into<W: Write>(&self, value: &u32, mut buffer: W) -> Result<(), Self::Error> {
            if *value == 0 {
                return Err(EncodeError::Zero);
            }
            buffer.write_all(&value.to_be_bytes())?;
            Ok(())
        }
    }
    impl DeserializationBackend<NonZeroU32> for NonZeroU32Encoding {
        type Error = DecodeError;

        fn deserialize(&self, bytes: &[u8]) -> Result<NonZeroU32, Self::Error> {
            let bytes: [u8; 4] = bytes.try_into().map_err(|_| DecodeError::MismatchedSize {
                length: bytes.len(),
            })?;
            let integer = u32::from_be_bytes(bytes);
            integer.try_into().map_err(|_| DecodeError::Zero)
        }
    }
}
