use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

use thiserror::Error;

use futures::ready;
use tokio::io::{self, AsyncRead, ReadBuf};

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::message::IncomingMessage;
use crate::Incoming;
use secp256k1::{PublicKey, Signature};

const HEADER_LEN: usize = 33 // sender identity
 + 1 // is_broadcast flag
 + 64 // compact signature
 + 2; // msg_len (u16)

pub struct IncomingDelivery<P, IO> {
    channel: IO,
    parties: P,
    identity: PublicKey,

    header: [u8; HEADER_LEN],
    header_received: usize,
    msg_len: Option<u16>,
    buffer: Vec<u8>,
    buffer_received: usize,

    buffer_size_limit: usize,
}

#[derive(Debug, Error)]
pub enum RecvError {
    #[error("i/o error")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("message is too large to receive: len={len}, limit={limit}")]
    MessageTooLarge { len: usize, limit: usize },
    #[error("invalid sender identity")]
    InvalidSenderIdentity(#[source] secp256k1::Error),
    #[error("is_broadcast flag has incorrect value: {0}")]
    InvalidIsBroadcast(u8),
    #[error("message is incorrectly signed")]
    InvalidSignature(#[source] secp256k1::Error),
}

impl From<io::ErrorKind> for RecvError {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Io(kind.into())
    }
}

impl<P, IO> IncomingDelivery<P, IO>
where
    IO: AsyncRead + Unpin,
    P: IdentityResolver + Unpin,
{
    pub fn poll_next<'i>(
        &'i mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Incoming<&'i [u8]>, RecvError>>> {
        while self.header_received < HEADER_LEN {
            let mut buf = ReadBuf::new(&mut self.header[self.header_received..]);
            ready!(Pin::new(&mut self.channel).poll_read(cx, &mut buf))?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return if self.header_received == 0 {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())))
                };
            }
            self.header_received += bytes_received;
        }

        let msg_len: usize = self
            .msg_len
            .unwrap_or_else(|| {
                u16::from_be_bytes(
                    <[u8; 2]>::try_from(&self.header[HEADER_LEN - 2..])
                        .expect("must not panic: we provide exactly 2 bytes"),
                )
            })
            .into();

        if self.buffer_size_limit < msg_len {
            return Poll::Ready(Some(Err(RecvError::MessageTooLarge {
                len: msg_len,
                limit: self.buffer_size_limit,
            })));
        }
        if self.buffer.len() < msg_len {
            self.buffer.resize(msg_len, 0);
        }

        while self.buffer_received < msg_len {
            let mut buf = ReadBuf::new(&mut self.buffer[self.buffer_received..msg_len]);
            ready!(Pin::new(&mut self.channel).poll_read(cx, &mut buf))?;
            let bytes_received = buf.filled().len();
            if bytes_received == 0 {
                return Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())));
            }
            self.buffer_received += bytes_received;
        }

        self.header_received = 0;
        self.buffer_received = 0;
        self.msg_len = None;

        let sender_identity =
            PublicKey::from_slice(&self.header[0..33]).map_err(RecvError::InvalidSenderIdentity)?;
        let is_broadcast = match self.header[33] {
            0 => false,
            1 => true,
            x => return Poll::Ready(Some(Err(RecvError::InvalidIsBroadcast(x)))),
        };
        let signature = Signature::from_compact(&self.header[34..34 + 64])
            .map_err(RecvError::InvalidSignature)?;

        IncomingMessage {
            sender: sender_identity,
            is_broadcast,
            signature,
            message: &self.buffer[..msg_len],
        }
        .verify(&self.identity)
        .map_err(RecvError::InvalidSignature)?;

        let sender_index = match self.parties.lookup_party_index(&sender_identity) {
            Some(index) => index,
            None => {
                // Sender is unknown, ignore message
                return self.poll_next(cx);
            }
        };

        Poll::Ready(Some(Ok(Incoming {
            sender: sender_index,
            msg: &self.buffer[..msg_len],
        })))
    }

    pub async fn next<'i>(&'i mut self) -> Option<Result<Incoming<&'i [u8]>, RecvError>> {
        futures::future::poll_fn(|cx| self.poll_next(cx)).await
    }
}
