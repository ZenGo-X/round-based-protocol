use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead};

use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::messages::{
    ForwardMsg, InvalidForwardMsg, InvalidForwardMsgHeader, ReceiveData, ReceiveDataError,
};
use crate::Incoming;

pub struct Incomings<P, IO> {
    parties: P,
    receive: ReceiveData<ForwardMsg, IO>,
    received_valid_message_from: Option<u16>,
}

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("i/o error")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("received invalid message")]
    InvalidMessage(#[source] InvalidMessage),
    #[error("invalid sender identity")]
    InvalidSenderIdentity(#[source] secp256k1::Error),
    #[error("is_broadcast flag has incorrect value: {0}")]
    InvalidIsBroadcast(u8),
    #[error("message is incorrectly signed")]
    InvalidSignature(#[source] secp256k1::Error),
    #[error("internal bug")]
    Bug(
        #[source]
        #[from]
        Bug,
    ),
}

#[derive(Debug, Error)]
pub enum InvalidMessage {
    #[error("invalid header")]
    Header(#[source] InvalidForwardMsgHeader),
    #[error("invalid data")]
    Data(#[source] InvalidForwardMsg),
    #[error("message is too large: size={len}, limit={limit}")]
    TooLarge { len: usize, limit: usize },
}

#[derive(Debug, Error)]
pub enum Bug {
    #[error(".received() returned None though we just received a valid message")]
    ReceivedNone,
}

impl From<io::ErrorKind> for ReceiveError {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Io(kind.into())
    }
}

impl From<ReceiveDataError<InvalidForwardMsgHeader, InvalidForwardMsg>> for ReceiveError {
    fn from(error: ReceiveDataError<InvalidForwardMsgHeader, InvalidForwardMsg>) -> Self {
        match error {
            ReceiveDataError::Io(error) => Self::Io(error),
            ReceiveDataError::ParseHeader(error) => {
                Self::InvalidMessage(InvalidMessage::Header(error))
            }
            ReceiveDataError::ValidateData(error) => {
                Self::InvalidMessage(InvalidMessage::Data(error))
            }
            ReceiveDataError::TooLargeMessage { len, limit } => {
                Self::InvalidMessage(InvalidMessage::TooLarge { len, limit })
            }
        }
    }
}

impl<P, IO> Incomings<P, IO>
where
    IO: AsyncRead + Unpin,
    P: IdentityResolver + Unpin,
{
    pub fn new(parties: P, receive: ReceiveData<ForwardMsg, IO>) -> Self {
        Self {
            parties,
            receive,
            received_valid_message_from: None,
        }
    }

    pub fn received(&self) -> Option<Incoming<&[u8]>> {
        let sender = match self.received_valid_message_from {
            Some(sender) => sender,
            None => return None,
        };
        Some(Incoming {
            sender,
            msg: self
                .receive
                .received()
                .expect("inconsistent internal state")
                .1,
        })
    }
}

impl<P, IO> Stream for Incomings<P, IO>
where
    IO: AsyncRead + Unpin,
    P: IdentityResolver + Unpin,
{
    type Item = Result<(), ReceiveError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.received_valid_message_from.is_some() {
            this.received_valid_message_from = None;
        }
        loop {
            match ready!(Pin::new(&mut this.receive).poll_next(cx)) {
                Some(result) => result?,
                None => return Poll::Ready(None),
            }
            let (header, _data) = this.receive.received().ok_or(Bug::ReceivedNone)?;
            let sender = match this.parties.lookup_party_index(&header.sender) {
                Some(sender) => sender,
                None => {
                    // Sender is unknown, ignore this message
                    continue;
                }
            };
            this.received_valid_message_from = Some(sender);
            return Poll::Ready(Some(Ok(())));
        }
    }
}
