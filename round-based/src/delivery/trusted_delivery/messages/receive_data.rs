use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead, ReadBuf};

use thiserror::Error;

use super::{DataMsg, DefaultArray, FixedSizeMsg};

pub struct ReceiveData<M: DataMsg, IO> {
    header: Option<M::Header>,
    header_buffer: <M::Header as FixedSizeMsg>::BytesArray,
    header_received: usize,
    data: Vec<u8>,
    data_received: usize,
    data_limit: usize,
    data_valid: bool,

    channel: IO,
    parser: M,
}

impl<M, IO> ReceiveData<M, IO>
where
    M: DataMsg + Unpin,
    IO: AsyncRead + Unpin,
{
    pub fn new(channel: IO, parser: M) -> Self {
        Self::with_capacity(channel, parser, 1000)
    }

    pub fn with_capacity(channel: IO, parser: M, initial_capacity: usize) -> Self {
        Self {
            header: None,
            header_buffer: DefaultArray::default_array(),
            header_received: 0,
            data: Vec::with_capacity(initial_capacity),
            data_received: 0,
            data_limit: 10_000,
            data_valid: false,
            channel,
            parser,
        }
    }

    pub fn set_data_limit(&mut self, limit: usize) {
        self.data_limit = limit;
    }

    pub fn received(&self) -> Option<(&M::Header, &[u8])> {
        let header = self.header.as_ref()?;
        let data_len = self.parser.data_size(header);
        if self.data_received != data_len || !self.data_valid {
            None
        } else {
            Some((header, &self.data[..data_len]))
        }
    }
}

impl<M, IO> Stream for ReceiveData<M, IO>
where
    M: DataMsg + Unpin,
    IO: AsyncRead + Unpin,
{
    type Item = Result<
        (),
        ReceiveDataMessageError<<M::Header as FixedSizeMsg>::ParseError, M::ValidateError>,
    >;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.data_valid {
            // Discard previously received data
            self.header = None;
            self.header_received = 0;
            self.data_received = 0;
            self.data_valid = false;
        }

        let Self {
            header,
            header_buffer,
            header_received,
            data,
            data_received,
            data_limit,
            data_valid,
            channel,
            parser,
        } = &mut *self;

        while *header_received < header_buffer.as_ref().len() {
            let mut buf = ReadBuf::new(&mut header_buffer.as_mut()[*header_received..]);
            ready!(Pin::new(&mut *channel).poll_read(cx, &mut buf))
                .map_err(ReceiveDataMessageError::Io)?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return if *header_received != 0 {
                    Poll::Ready(Some(Err(ReceiveDataMessageError::Io(
                        io::ErrorKind::UnexpectedEof.into(),
                    ))))
                } else {
                    Poll::Ready(None)
                };
            }
            *header_received += bytes_received;
        }

        let header = match &*header {
            Some(header) => header,
            None => {
                let parsed = M::Header::parse(&header_buffer)
                    .map_err(ReceiveDataMessageError::ParseHeader)?;
                header.get_or_insert(parsed)
            }
        };
        let data_len = parser.data_size(header);

        if data.len() < data_len {
            if *data_limit < data_len {}
        }

        while *data_received < data_len {
            let mut buf = ReadBuf::new(&mut data[*data_received..data_len]);
            ready!(Pin::new(&mut *channel).poll_read(cx, &mut buf))
                .map_err(ReceiveDataMessageError::Io)?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return Poll::Ready(Some(Err(ReceiveDataMessageError::Io(
                    io::ErrorKind::UnexpectedEof.into(),
                ))));
            }
            *data_received += bytes_received;
        }

        parser
            .validate(header, &data[..data_len])
            .map_err(ReceiveDataMessageError::ValidateData)?;
        *data_valid = true;

        Poll::Ready(Some(Ok(())))
    }
}

#[derive(Debug, Error)]
pub enum ReceiveDataMessageError<HE, DE> {
    #[error("i/o error")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("parse header")]
    ParseHeader(#[source] HE),
    #[error("validate received data")]
    ValidateData(#[source] DE),
    #[error("message is too large: len={len}bytes, limit={limit}bytes")]
    TooLargeMessage { len: usize, limit: usize },
}
