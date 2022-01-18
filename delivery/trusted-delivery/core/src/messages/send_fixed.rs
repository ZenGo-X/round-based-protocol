use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{self, AsyncWrite};
use futures::ready;

use crate::messages::FixedSizeMessage;
use generic_array::GenericArray;

pub struct SendFixed<M: FixedSizeMessage, IO> {
    channel: IO,
    serialized_msg: GenericArray<u8, M::Size>,
    bytes_sent: usize,
}

impl<M, IO> SendFixed<M, IO>
where
    M: FixedSizeMessage,
    IO: AsyncWrite + Unpin,
    GenericArray<u8, M::Size>: Unpin,
{
    pub fn initiate(msg: M, channel: IO) -> Self {
        Self {
            channel,
            serialized_msg: msg.to_bytes(),
            bytes_sent: 0,
        }
    }

    pub fn into_inner(self) -> IO {
        self.channel
    }
}

impl<M, IO> Future for SendFixed<M, IO>
where
    M: FixedSizeMessage,
    IO: AsyncWrite + Unpin,
    GenericArray<u8, M::Size>: Unpin,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        while this.bytes_sent < this.serialized_msg.as_ref().len() {
            this.bytes_sent += ready!(Pin::new(&mut this.channel)
                .poll_write(cx, &this.serialized_msg.as_ref()[this.bytes_sent..]))?;
        }
        Poll::Ready(Ok(()))
    }
}
