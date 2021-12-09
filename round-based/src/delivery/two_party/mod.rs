//! Delivery implementation for two party protocols
//!
//! Two party delivery can be natively implemented as a server/client communication.
//!
//! This module contains [TwoParty] primitive that can be used to build a two party delivery on top
//! of any network protocol (TCP, TCP+TLS, QUIC, etc.). There are ready-to-use implementations on
//! top of most popular network protocols: TCP+TLS (see [tls module](tls)), and plain TCP (for
//! development purposes, see [insecure module](insecure))

use std::convert::{TryFrom, TryInto};
use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

use phantom_type::PhantomType;
use pin_project_lite::pin_project;
use serde::{de::DeserializeOwned, Serialize};

use crate::delivery::OutgoingChannel;
use crate::{Delivery, Incoming, Outgoing, OutgoingDelivery};

pub mod insecure;
#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub mod tls;

/// Index of party who runs a server
pub const SERVER_IDX: u16 = 0;
/// Index of party who connects to the server
pub const CLIENT_IDX: u16 = 1;

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
pub struct TwoParty<M, R, W> {
    recv: RecvLink<M, R>,
    send: SendLink<W>,
}

impl<M, R, W> TwoParty<M, R, W>
where
    M: Serialize + DeserializeOwned + Clone,
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    /// Constructs a two party link from raw byte channels
    ///
    /// * `read_link` is an [`AsyncRead`] that reads bytes sent by counterparty
    /// * `write_link` is an [`AsyncWrite`] that sends bytes to the counterparty
    /// * `capacity` is an initial capacity of internal buffers. Buffers grow on sending/receiving
    ///   larger messages
    /// * `message_size_limit` limits length of serialized message. Sending/receiving larger messages
    ///   results into error that closes a channel
    /// * `side` determines whether this party is a server or a client. \
    ///   Basically, it affects only counterparty index, ie. `Side::Server` incoming messages will
    ///   have `sender = 1`, and `Side::Client` incoming messages will have `sender = 0`
    pub fn new(
        side: Side,
        read_link: R,
        write_link: W,
        capacity: usize,
        message_size_limit: usize,
    ) -> Self {
        let counterparty_id = match side {
            Side::Server => CLIENT_IDX,
            Side::Client => SERVER_IDX,
        };
        Self {
            recv: RecvLink::new(read_link, capacity, message_size_limit, counterparty_id),
            send: SendLink::new(write_link, capacity, message_size_limit, counterparty_id),
        }
    }
}

impl<M, R, W> Delivery<M> for TwoParty<M, R, W>
where
    M: Serialize + DeserializeOwned + Clone + Unpin + 'static,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin,
{
    type Send = SendLink<W>;
    type Receive = RecvLink<M, R>;
    type ReceiveError = io::Error;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.recv, self.send)
    }
}

/// Determines the side of TwoParty channel: server/client
pub enum Side {
    Server,
    Client,
}

pin_project! {
    /// An outgoing link to the party
    ///
    /// Wraps AsyncWrite that delivers bytes to the party, and implements [DeliverOutgoing].
    pub struct SendLink<S> {
        #[pin]
        link: S,
        buffer: Vec<u8>,
        buffer_filled: usize,
        buffer_sent: usize,
        msg_len_limit: usize,

        counterparty_id: u16,
    }
}

impl<L> SendLink<L> {
    pub fn new(link: L, capacity: usize, msg_len_limit: usize, counterparty_id: u16) -> Self {
        Self {
            link,
            buffer: vec![0; capacity],
            buffer_filled: 0,
            buffer_sent: 0,
            msg_len_limit,
            counterparty_id,
        }
    }
}

impl<L> SendLink<L> {
    fn buffer_capacity(self: Pin<&Self>) -> usize {
        let me = self.project_ref();
        me.buffer.len() - me.buffer_filled
    }
}

impl<S: AsyncWrite> OutgoingChannel for SendLink<S> {
    type MessageSize = SerializedMsgSize;
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        &SerializedMsgSize(msg_size): &Self::MessageSize,
    ) -> Poll<Result<(), Self::Error>> {
        let me = self.as_mut().project();

        // Check whether message is not too long
        if usize::from(msg_size) > *me.msg_len_limit {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message is too large to fit into the intermediate buffer",
            )));
        }

        // Check if the buffer is able to fit the message
        if usize::from(msg_size) + 2 > me.buffer.len() {
            // if it does not, we need to grow the buffer
            me.buffer.resize(usize::from(msg_size) + 2, 0);
        }

        // Check if we have enough capacity in the buffer
        while usize::from(msg_size) + 2 > self.as_ref().buffer_capacity() {
            // Not enough capacity - need to flush the buffer
            match Self::poll_flush(self.as_mut(), cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
        }

        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let me = self.as_mut().project();

        if *me.buffer_filled == 0 {
            // Have nothing to send
            Poll::Ready(Ok(()))
        } else if *me.buffer_sent < *me.buffer_filled {
            // We have more data to write
            match me
                .link
                .poll_write(cx, &me.buffer[*me.buffer_sent..*me.buffer_filled])
            {
                Poll::Ready(Ok(written)) => {
                    *me.buffer_sent += written;
                    // Need to repeat flush
                    Self::poll_flush(self, cx)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            // We've wrote all the data to the I/O, need to flush it
            ready!(me.link.poll_flush(cx))?;
            *me.buffer_filled = 0;
            *me.buffer_sent = 0;
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(Self::poll_flush(self.as_mut(), cx))?;
        let me = self.project();
        me.link.poll_shutdown(cx)
    }
}

impl<'m, M, S> OutgoingDelivery<M> for SendLink<S>
where
    M: Serialize + Unpin,
    S: AsyncWrite,
{
    fn message_size(self: Pin<&Self>, msg: Outgoing<&M>) -> Result<Self::MessageSize, Self::Error> {
        let serialized_size = bincode::serialized_size(&msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(SerializedMsgSize(serialized_size))
    }

    fn start_send(mut self: Pin<&mut Self>, msg: Outgoing<&M>) -> Result<(), Self::Error> {
        if msg.recipient.is_some() && msg.recipient != Some(self.counterparty_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recipient index mismatched",
            ));
        }

        if self.as_ref().buffer_capacity() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "channel is not prepared to send a message",
            ));
        }

        let me = self.as_mut().project();

        // Take unfilled part of the buffer
        let buffer = &mut me.buffer[*me.buffer_filled..];
        // Reserve two first bytes for message size
        let (msg_size_buffer, msg_buffer) = buffer.split_at_mut(2);
        let mut msg_buffer = Cursor::new(msg_buffer);

        // Serialize message to the buffer
        bincode::serialize_into(&mut msg_buffer, &msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Calculate message size and prepend it to the message
        let msg_size: u16 = msg_buffer
            .position()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "msg_size overflows u16"))?;
        msg_size_buffer.copy_from_slice(&msg_size.to_be_bytes());

        // Update number of filled bytes
        *me.buffer_filled += 2 + usize::from(msg_size);

        Ok(())
    }
}

/// Size of the message transferring over [SendLink]
pub struct SerializedMsgSize(u16);

pin_project! {
    /// An incoming link from the party
    ///
    /// Wraps AsyncRead that receives bytes from the party, and implements [`Stream<Item=Incoming<M>>`](Stream).
    pub struct RecvLink<M, R> {
        #[pin]
        link: R,

        frame: Vec<u8>,
        msg_len_limit: usize,
        bytes_received: usize,

        counterparty_id: u16,

        _ph: PhantomType<M>,
    }
}

impl<M, L> RecvLink<M, L>
where
    L: AsyncRead,
    M: DeserializeOwned,
{
    /// Constructs a new receive link
    ///
    /// `link` is a `AsyncRead` that receives bytes from counterparty. `capacity` is a maximum length
    /// of serialized message (receiving bigger message results into error).
    pub fn new(link: L, capacity: usize, msg_len_limit: usize, counterparty_id: u16) -> Self {
        RecvLink {
            link,
            frame: vec![0; capacity],
            bytes_received: 0,
            counterparty_id,
            msg_len_limit,
            _ph: PhantomType::new(),
        }
    }
}

fn next_message_available(frame: &[u8], bytes_received: usize) -> bool {
    if bytes_received < 2 {
        return false;
    }
    let msg_len = u16::from_be_bytes(
        <[u8; 2]>::try_from(&frame[0..2]).expect("we took exactly two first bytes"),
    );
    bytes_received >= usize::from(msg_len) + 2
}

fn grow_buffer_if_needed(
    frame: &mut Vec<u8>,
    bytes_received: usize,
    msg_len_limit: usize,
) -> io::Result<()> {
    if bytes_received < 2 {
        return Ok(());
    }

    let msg_len = u16::from_be_bytes(
        <[u8; 2]>::try_from(&frame[0..2]).expect("we took exactly two first bytes"),
    );

    if usize::from(msg_len) > msg_len_limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receiving message too long",
        ));
    }

    if frame.len() < 2 + usize::from(msg_len) {
        frame.resize(2 + usize::from(msg_len), 0)
    }

    Ok(())
}

impl<M, R> Stream for RecvLink<M, R>
where
    R: AsyncRead,
    M: DeserializeOwned,
{
    type Item = io::Result<Incoming<M>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut me = self.project();

        // Unless we have message to parse, we need to read more bytes
        while !next_message_available(me.frame, *me.bytes_received) {
            grow_buffer_if_needed(&mut *me.frame, *me.bytes_received, *me.msg_len_limit)?;

            let bytes_received = *me.bytes_received;
            let mut buf = ReadBuf::new(&mut me.frame[bytes_received..]);

            let bytes_received = match me.link.as_mut().poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            };

            if bytes_received == 0 {
                // No data was read => EOF reached
                if *me.bytes_received != 0 {
                    // We have some bytes received but not handled => EOF is unexpected
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "got EOF at the middle of the message",
                    ))));
                }
                // Otherwise, stream is peacefully terminated
                return Poll::Ready(None);
            }
            *me.bytes_received += bytes_received;
        }

        // At this point we know that we received a message which we need to parse

        let msg_len = usize::from(u16::from_be_bytes(
            <[u8; 2]>::try_from(&me.frame[0..2]).expect("we took exactly two first bytes"),
        ));
        let msg = &me.frame[2..];
        let msg = &msg[..msg_len];

        let msg = match bincode::deserialize::<M>(msg) {
            Ok(m) => m,
            Err(e) => return Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::InvalidData, e)))),
        };

        // Delete parsed message from the buffer
        me.frame.copy_within(2 + msg_len.., 0);
        *me.bytes_received -= 2 + msg_len;

        Poll::Ready(Some(Ok(Incoming {
            sender: *me.counterparty_id,
            msg,
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::ops::RangeInclusive;

    use futures::{TryStream, TryStreamExt};
    use tokio::io;

    use rand::{random, Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use serde::{Deserialize, Serialize};

    use crate::delivery::{
        Delivery, Incoming, Outgoing, OutgoingChannel, OutgoingChannelExt, OutgoingDelivery,
        OutgoingDeliveryExt,
    };

    use super::{Side, TwoParty};

    #[tokio::test]
    async fn test_two_party_in_different_settings() {
        // Link size and buffer size are near to msg len. Messages will be transmitted one by one
        test_duplex_link(115, 115, 115, 100..=100, 10).await;
        // Link size is near to msg len, but buffer size is too small to fit a whole message, so
        // messages will be transmitted part by part
        test_duplex_link(115, 115, 50, 100..=100, 10).await;
        // Link size is twice larger than message size, but buffer size fits only one and half messages
        test_duplex_link(115, 250, 150, 100..=100, 10).await;
        // Buffer fits many messages, but link capable to carry only two and half messages
        test_duplex_link(115, 390, 4000, 100..=100, 10).await;
        // Link size is too small to fit one message, so it grows
        test_duplex_link(115, 50, 115, 100..=100, 10).await;
        // Just send random chunks of bytes
        test_duplex_link(1015, 4096, 4096, 100..=1000, 10).await;
    }

    async fn test_duplex_link(
        msg_len_limit: usize,
        link_capacity: usize,
        buffer_size: usize,
        msg_len: RangeInclusive<usize>,
        msgs_n: usize,
    ) {
        let (server, client) = io::duplex(buffer_size);
        let (server_read, server_write) = io::split(server);
        let (client_read, client_write) = io::split(client);

        let server_link = TwoParty::new(
            Side::Server,
            server_read,
            server_write,
            link_capacity,
            msg_len_limit,
        );
        let client_link = TwoParty::new(
            Side::Client,
            client_read,
            client_write,
            link_capacity,
            msg_len_limit,
        );

        test_two_party_link(server_link, client_link, msg_len, msgs_n).await
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    pub struct Bytes(Vec<u8>);

    // This function pushes through the links chunks of bytes, and asserts that on the other end
    // party receives correct messages
    async fn test_two_party_link<S, C, R>(server: S, client: C, msg_len_range_: R, msgs_n: usize)
    where
        C: Delivery<Bytes> + Send + 'static,
        S: Delivery<Bytes> + Send + 'static,
        R: rand::distributions::uniform::SampleRange<usize> + Clone + Send + 'static,
        S::Send: Unpin,
        <S::Send as OutgoingChannel>::Error: Debug,
        <S::Receive as TryStream>::Error: Debug,
        C::Send: Unpin,
        <C::Send as OutgoingChannel>::Error: Debug,
        <C::Receive as TryStream>::Error: Debug,
    {
        let local_set = tokio::task::LocalSet::new();

        // Make randomness deterministic and reproducible
        let server_seed: [u8; 32] = random();
        let client_seed: [u8; 32] = random();
        println!("Server seed: {:?}", server_seed);
        println!("Client seed: {:?}", client_seed);

        let server_rng = ChaCha20Rng::from_seed(server_seed);
        let client_rng = ChaCha20Rng::from_seed(client_seed);

        // The server
        let local_rng = server_rng.clone();
        let remote_rng = client_rng.clone();
        let msg_len_range = msg_len_range_.clone();
        let (server_recv, server_send) = server.split();
        // Server sends chunks of random bytes to the client
        let server_sending = local_set.spawn_local(push_chunks_of_random_bytes_through_link(
            local_rng,
            server_send,
            msg_len_range.clone(),
            msgs_n,
            0,
            1,
        ));
        // Server receives chunks of random bytes from the client and asserts that they are
        // what we expected to receive
        let server_receiving = local_set.spawn_local(receive_chunks_of_random_bytes_and_compare(
            remote_rng,
            server_recv,
            msg_len_range,
            msgs_n,
            0,
            1,
        ));

        // The client
        let local_rng = client_rng.clone();
        let remote_rng = server_rng.clone();
        let msg_len_range = msg_len_range_.clone();
        let (client_recv, client_send) = client.split();
        // Client sends chunks of random bytes to the server
        let client_sending = local_set.spawn_local(push_chunks_of_random_bytes_through_link(
            local_rng,
            client_send,
            msg_len_range.clone(),
            msgs_n,
            1,
            0,
        ));
        // Client receives chunks of random bytes from the server and asserts that they are
        // what we expected to receive
        let client_receiving = local_set.spawn_local(receive_chunks_of_random_bytes_and_compare(
            remote_rng,
            client_recv,
            msg_len_range,
            msgs_n,
            1,
            0,
        ));

        local_set.await;
        server_sending.await.unwrap();
        server_receiving.await.unwrap();
        client_sending.await.unwrap();
        client_receiving.await.unwrap();
    }

    async fn push_chunks_of_random_bytes_through_link<R, Link, Range>(
        mut rng: R,
        mut link: Link,
        msg_len_range: Range,
        chunks_n: usize,
        party_i: u16,
        counterparty_id: u16,
    ) where
        R: RngCore,
        Link: OutgoingDelivery<Bytes> + Unpin,
        Link::Error: Debug,
        Range: rand::distributions::uniform::SampleRange<usize> + Clone,
    {
        for i in 1..=chunks_n {
            let msg_len = rng.gen_range(msg_len_range.clone());
            let mut msg = vec![0u8; msg_len];
            rng.fill_bytes(&mut msg);
            link.send(Outgoing {
                recipient: Some(counterparty_id),
                msg: &Bytes(msg),
            })
            .await
            .unwrap();
            println!("Party {} sends chunk {}", party_i, i);
        }
        link.shutdown().await.unwrap();
    }

    async fn receive_chunks_of_random_bytes_and_compare<R, Link, Range>(
        mut rng: R,
        mut link: Link,
        msg_len_range: Range,
        chunks_n: usize,
        party_id: u16,
        counterparty_id: u16,
    ) where
        R: RngCore,
        Link: TryStream<Ok = Incoming<Bytes>> + Unpin,
        Link::Error: Debug,
        Range: rand::distributions::uniform::SampleRange<usize> + Clone,
    {
        for i in 1..=chunks_n {
            let msg = link.try_next().await.unwrap();

            let expected_msg_len = rng.gen_range(msg_len_range.clone());
            let mut expected_msg = vec![0; expected_msg_len];
            rng.fill_bytes(&mut expected_msg);
            assert_eq!(
                msg,
                Some(Incoming {
                    sender: counterparty_id,
                    msg: Bytes(expected_msg)
                })
            );
            println!("Party {} receives valid chunk {}", party_id, i);
        }
        assert!(link.try_next().await.unwrap().is_none());
    }
}
