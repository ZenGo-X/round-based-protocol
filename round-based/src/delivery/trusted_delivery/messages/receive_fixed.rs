use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead, ReadBuf};

use thiserror::Error;

use super::{DefaultArray, FixedSizeMsg};

pub struct ReceiveFixed<M: FixedSizeMsg, IO> {
    channel: IO,
    buffer: M::BytesArray,
    buffer_written: usize,
}

impl<M, IO> ReceiveFixed<M, IO>
where
    M: FixedSizeMsg,
    IO: AsyncRead + Unpin,
{
    pub fn new(channel: IO) -> Self {
        Self {
            channel,
            buffer: DefaultArray::default_array(),
            buffer_written: 0,
        }
    }
}

impl<M, IO> Stream for ReceiveFixed<M, IO>
where
    M: FixedSizeMsg,
    IO: AsyncRead + Unpin,
{
    type Item = Result<M, ReceiveFixedSizeMessageError<M::ParseError>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            channel,
            buffer,
            buffer_written,
        } = &mut *self;
        while *buffer_written < buffer.as_ref().len() {
            let mut buf = ReadBuf::new(&mut buffer.as_mut()[*buffer_written..]);
            ready!(Pin::new(&mut *channel).poll_read(cx, &mut buf))
                .map_err(ReceiveFixedSizeMessageError::Io)?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return if *buffer_written != 0 {
                    Poll::Ready(Some(Err(ReceiveFixedSizeMessageError::Io(
                        io::ErrorKind::UnexpectedEof.into(),
                    ))))
                } else {
                    Poll::Ready(None)
                };
            }
            *buffer_written += bytes_received;
        }

        *buffer_written = 0;
        Poll::Ready(Some(
            M::parse(&self.buffer).map_err(ReceiveFixedSizeMessageError::Parse),
        ))
    }
}

#[derive(Debug, Error)]
pub enum ReceiveFixedSizeMessageError<E> {
    #[error("i/o error")]
    Io(
        #[source]
        #[from]
        io::Error,
    ),
    #[error("parse error")]
    Parse(#[source] E),
}
