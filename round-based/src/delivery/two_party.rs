use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{
    self,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use phantom_type::PhantomType;
use pin_project_lite::pin_project;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub const SERVER_ID: u16 = 0;
pub const CLIENT_ID: u16 = 1;

use crate::delivery::{DeliverOutgoing, Delivery, Incoming, Outgoing};

/// A link established between two parties that can be used to exchange messages `M`
pub struct TwoPartyLink<M, R, W> {
    recv: RecvLink<M, R>,
    send: SendLink<W>,
}

impl<M, R, W> TwoPartyLink<M, R, W>
where
    M: Serialize + DeserializeOwned + Clone,
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    pub fn new(read_link: R, write_link: W, capacity: usize, counterparty_id: u16) -> Self {
        Self {
            recv: RecvLink::new(read_link, capacity, counterparty_id),
            send: SendLink::new(write_link, capacity, counterparty_id),
        }
    }
}

pub type TcpTwoPartyLink<M> = TwoPartyLink<M, OwnedReadHalf, OwnedWriteHalf>;

impl<M, R, W> Delivery<M> for TwoPartyLink<M, R, W>
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

/// Binds a basic TCP server at given address
pub async fn server<M, A: net::ToSocketAddrs>(
    bind_at: A,
) -> io::Result<(
    impl Stream<Item = io::Result<(TcpTwoPartyLink<M>, SocketAddr)>>,
    SocketAddr,
)>
where
    M: Serialize + DeserializeOwned + Clone,
{
    let server = net::TcpListener::bind(bind_at).await?;
    let local_addr = server.local_addr()?;
    Ok((
        async_stream::try_stream! {
            loop {
                let (conn, remote_addr) = server.accept().await?;
                let (recv, send) = conn.into_split();
                yield (TwoPartyLink::new(recv, send, 4096, CLIENT_ID), remote_addr);
            }
        },
        local_addr,
    ))
}

pub async fn client<M, A: net::ToSocketAddrs>(connect_to: A) -> io::Result<TcpTwoPartyLink<M>>
where
    M: Serialize + DeserializeOwned + Clone,
{
    let conn = net::TcpStream::connect(connect_to).await?;
    let (recv, send) = conn.into_split();
    Ok(TwoPartyLink::new(recv, send, 4096, SERVER_ID))
}

pin_project! {
    /// An outgoing link to the party
    ///
    /// Wraps AsyncWrite that delivers bytes to the party, and implements [DeliverOutgoing].
    pub struct SendLink<S> {
        #[pin]
        link: S,
        buffer: Box<[u8]>,
        buffer_len: usize,
        bytes_written: usize,

        counterparty_id: u16,
    }
}

impl<L> SendLink<L> {
    pub fn new(link: L, capacity: usize, counterparty_id: u16) -> Self {
        Self {
            link,
            buffer: vec![0; capacity].into_boxed_slice(),
            buffer_len: 0,
            bytes_written: 0,
            counterparty_id,
        }
    }
}

impl<M, S> DeliverOutgoing<M> for SendLink<S>
where
    M: Serialize + Clone + Unpin,
    S: AsyncWrite,
{
    type Prepared = ServerPreparedSend<M>;
    type Error = io::Error;

    fn prepare(self: Pin<&Self>, msg: Outgoing<&M>) -> io::Result<Self::Prepared> {
        if !(msg.recipient.is_none() || msg.recipient == Some(self.counterparty_id)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recipient must be a client",
            ));
        }

        let me = self.project_ref();

        let serialized_size = bincode::serialized_size(&msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if usize::from(serialized_size) > me.buffer.len() - 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message is too large to fit into the intermediate buffer",
            ));
        }
        Ok(ServerPreparedSend {
            serialized_size,
            msg: msg.msg.clone(),
        })
    }

    fn poll_start_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        msg: &Self::Prepared,
    ) -> Poll<io::Result<()>> {
        let me = self.as_mut().project();

        // Check if we have enough capacity in the buffer
        if usize::from(msg.serialized_size) + 2 > me.buffer.len() - *me.buffer_len {
            // Not enough capacity - need to flush the buffer
            return match <Self as DeliverOutgoing<M>>::poll_flush(self.as_mut(), cx) {
                Poll::Ready(Ok(())) => {
                    // Flush is finished, try to send again
                    self.poll_start_send(cx, msg)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }

        // Serialize msg to the buffer
        me.buffer[*me.buffer_len..*me.buffer_len + 2]
            .copy_from_slice(&msg.serialized_size.to_be_bytes());
        *me.buffer_len += 2;

        bincode::serialize_into(
            &mut me.buffer[*me.buffer_len..*me.buffer_len + usize::from(msg.serialized_size)],
            &msg.msg,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        *me.buffer_len += usize::from(msg.serialized_size);

        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let me = self.as_mut().project();

        if *me.buffer_len == 0 {
            // Have nothing to send
            Poll::Ready(Ok(()))
        } else if *me.bytes_written < *me.buffer_len {
            // We have more data to write
            match me
                .link
                .poll_write(cx, &me.buffer[*me.bytes_written..*me.buffer_len])
            {
                Poll::Ready(Ok(written)) => {
                    *me.bytes_written += written;
                    // Need to repeat flush
                    <Self as DeliverOutgoing<M>>::poll_flush(self, cx)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            // We've wrote all the data to the I/O, need to flush it
            ready!(me.link.poll_flush(cx))?;
            *me.buffer_len = 0;
            *me.bytes_written = 0;
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match <Self as DeliverOutgoing<M>>::poll_flush(self.as_mut(), cx) {
            Poll::Ready(Ok(())) => {}
            result => return result,
        }
        let me = self.project();
        me.link.poll_shutdown(cx)
    }
}

pub struct ServerPreparedSend<M> {
    msg: M,
    serialized_size: u16,
}

pin_project! {
    /// An incoming link from the party
    ///
    /// Wraps AsyncRead that receives bytes from the party, and implements [`Stream<Item=Incoming<M>>`](Stream).
    pub struct RecvLink<M, R> {
        #[pin]
        link: R,

        frame: Box<[u8]>,
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
    pub fn new(link: L, capacity: usize, counterparty_id: u16) -> Self {
        RecvLink {
            link,
            frame: vec![0; capacity].into_boxed_slice(),
            bytes_received: 0,
            counterparty_id,
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

impl<M, R> Stream for RecvLink<M, R>
where
    R: AsyncRead,
    M: DeserializeOwned,
{
    type Item = io::Result<Incoming<M>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut me = self.project();
        loop {
            // Unless we have message to parse, we need to read more bytes
            while !next_message_available(&me.frame, *me.bytes_received) {
                if *me.bytes_received == me.frame.len() {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "received message is too large",
                    ))));
                }

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

            // At this point we know that we received a message which we can parse

            let msg_len = usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(&me.frame[0..2]).expect("we took exactly two first bytes"),
            ));
            let msg = &me.frame[2..];
            let msg = &msg[..msg_len];

            let msg = match bincode::deserialize::<M>(msg) {
                Ok(m) => m,
                Err(e) => {
                    return Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))))
                }
            };

            // Delete parsed message from the buffer
            me.frame.copy_within(2 + msg_len.., 0);
            *me.bytes_received -= 2 + msg_len;

            return Poll::Ready(Some(Ok(Incoming {
                sender: *me.counterparty_id,
                msg,
            })));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::ops::RangeInclusive;

    use tokio::io;

    use futures::{pin_mut, StreamExt, TryStream, TryStreamExt};
    use rand::{random, Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use serde::{Deserialize, Serialize};

    use crate::delivery::two_party::TwoPartyLink;
    use crate::delivery::{DeliverOutgoing, DeliverOutgoingExt, Delivery, Incoming, Outgoing};

    use super::{client, server};

    #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
    pub struct TestMessage(u16);

    /// This is a demonstrative test that shows how we can simply deploy a TCP server/client that can
    /// exchange messages
    #[tokio::test]
    async fn exchange_server_client_messages() {
        let (clients, server_addr) = server::<TestMessage, _>("127.0.0.1:0").await.unwrap();

        // The client
        let client = tokio::spawn(async move {
            let link = client::<TestMessage, _>(server_addr).await.unwrap();
            let (recv, mut send) = link.split();

            // Client sends 1+2+3 messages to the server
            let sending = tokio::spawn(async move {
                for i in 1..=3 {
                    let msgs = vec![TestMessage(i); usize::from(i)];
                    send.send_all(msgs.iter().map(|msg| Outgoing {
                        recipient: Some(0),
                        msg,
                    }))
                    .await
                    .unwrap()
                }
            });

            // Client receives 1+2+3 messages from the server and asserts that they are what we
            // expected to receive
            let receiving = tokio::spawn(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = (1..=3)
                    .flat_map(|i| {
                        vec![
                            Incoming {
                                sender: 0,
                                msg: TestMessage(i + 100)
                            };
                            usize::from(i)
                        ]
                    })
                    .collect::<Vec<_>>();
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        // The server
        let server = tokio::spawn(async move {
            pin_mut!(clients);
            let (link, _addr) = clients.next().await.unwrap().unwrap();
            let (recv, mut send) = link.split();

            // Server sends 1+2+3 messages to the client. Note that messages payload is different from
            // what client sends to us
            let sending = tokio::spawn(async move {
                for i in 1..=3 {
                    let msgs = vec![TestMessage(i + 100); usize::from(i)];
                    send.send_all(msgs.iter().map(|msg| Outgoing {
                        recipient: Some(1),
                        msg,
                    }))
                    .await
                    .unwrap();
                }
            });

            // Server receives 1+2+3 messages from the client and asserts that they are what we
            // expected to receive
            let receiving = tokio::spawn(async move {
                let msgs = recv.try_collect::<Vec<_>>().await.unwrap();
                let expected_msgs = (1..=3)
                    .flat_map(|i| {
                        vec![
                            Incoming {
                                sender: 1,
                                msg: TestMessage(i)
                            };
                            usize::from(i)
                        ]
                    })
                    .collect::<Vec<_>>();
                assert_eq!(msgs, expected_msgs);
            });

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        client.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_two_party_in_different_settings() {
        // Link size and buffer size are near to msg len. Messages will be transmitted one by one
        test_duplex_link(115, 115, 100..=100, 10).await;
        // Link size is near to msg len, but buffer size is too small to fit a whole message, so
        // messages will be transmitted part by part
        test_duplex_link(115, 50, 100..=100, 10).await;
        // Link size is twice larger than message size, but buffer size fits only one and half messages
        test_duplex_link(250, 150, 100..=100, 10).await;
        // Buffer fits many messages, but link capable to carry only two and half messages
        test_duplex_link(390, 4000, 100..=100, 10).await;
    }

    async fn test_duplex_link(
        link_capacity: usize,
        buffer_size: usize,
        msg_len: RangeInclusive<usize>,
        msgs_n: usize,
    ) {
        let (server, client) = io::duplex(buffer_size);
        let (server_read, server_write) = io::split(server);
        let (client_read, client_write) = io::split(client);

        let server_link = TwoPartyLink::new(server_read, server_write, link_capacity, 1);
        let client_link = TwoPartyLink::new(client_read, client_write, link_capacity, 0);

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
        <S::Send as DeliverOutgoing<Bytes>>::Prepared: Unpin + Send,
        <S::Send as DeliverOutgoing<Bytes>>::Error: Debug,
        <S::Receive as TryStream>::Error: Debug,
        C::Send: Unpin,
        <C::Send as DeliverOutgoing<Bytes>>::Prepared: Unpin + Send,
        <C::Send as DeliverOutgoing<Bytes>>::Error: Debug,
        <C::Receive as TryStream>::Error: Debug,
    {
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
        let server = tokio::spawn(async move {
            let (recv, send) = server.split();

            // Server sends chunks of random bytes to the client
            let sending = tokio::spawn(push_chunks_of_random_bytes_through_link(
                local_rng,
                send,
                msg_len_range.clone(),
                msgs_n,
                0,
                1,
            ));

            // Server receives chunks of random bytes from the client and asserts that they are
            // what we expected to receive
            let receiving = tokio::spawn(receive_chunks_of_random_bytes_and_compare(
                remote_rng,
                recv,
                msg_len_range,
                msgs_n,
                0,
                1,
            ));

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        // The client
        let local_rng = client_rng.clone();
        let remote_rng = server_rng.clone();
        let msg_len_range = msg_len_range_.clone();
        let client = tokio::spawn(async move {
            let (recv, send) = client.split();

            // Client sends chunks of random bytes to the server
            let sending = tokio::spawn(push_chunks_of_random_bytes_through_link(
                local_rng,
                send,
                msg_len_range.clone(),
                msgs_n,
                1,
                0,
            ));

            // Client receives chunks of random bytes from the server and asserts that they are
            // what we expected to receive
            let receiving = tokio::spawn(receive_chunks_of_random_bytes_and_compare(
                remote_rng,
                recv,
                msg_len_range,
                msgs_n,
                1,
                0,
            ));

            sending.await.unwrap();
            receiving.await.unwrap();
        });

        server.await.unwrap();
        client.await.unwrap();
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
        Link: DeliverOutgoing<Bytes> + Unpin,
        Link::Prepared: Unpin,
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
