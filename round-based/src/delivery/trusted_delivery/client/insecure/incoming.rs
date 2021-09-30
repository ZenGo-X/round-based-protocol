use std::pin::Pin;
use std::task::{Context, Poll};

use generic_array::{typenum::Unsigned, GenericArray};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead};

use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::client::insecure::crypto::{DecryptionKey, DecryptionKeys};
use crate::delivery::trusted_delivery::messages::{
    ForwardMsg, InvalidForwardMsg, InvalidForwardMsgHeader, ReceiveData, ReceiveDataError,
};
use crate::Incoming;

pub struct Incomings<P, K, IO> {
    parties: P,
    decryption_keys: K,

    receive: ReceiveData<ForwardMsg, IO>,

    received_valid_message_from: Option<u16>,
    received_message_was_encrypted: bool,
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
    InvalidMessage(
        #[source]
        #[from]
        InvalidMessage,
    ),
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
    #[error("cannot decrypt the message")]
    Decryption,
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

impl<P, K, IO> Incomings<P, K, IO>
where
    IO: AsyncRead + Unpin,
    P: IdentityResolver + Unpin,
    K: DecryptionKeys + Unpin,
{
    pub fn new(parties: P, decryption_keys: K, receive: ReceiveData<ForwardMsg, IO>) -> Self {
        Self {
            parties,
            decryption_keys,

            receive,

            received_valid_message_from: None,
            received_message_was_encrypted: false,
        }
    }

    pub fn received(&self) -> Option<Incoming<&[u8]>> {
        let sender = match self.received_valid_message_from {
            Some(sender) => sender,
            None => return None,
        };
        let mut data = self
            .receive
            .received()
            .expect("inconsistent internal state")
            .1;
        if self.received_message_was_encrypted {
            // We need to strip the tag
            data = &data[..data.len() - <K::Key as DecryptionKey>::TagSize::USIZE]
        }
        Some(Incoming { sender, msg: data })
    }
}

impl<P, K, IO> Stream for Incomings<P, K, IO>
where
    IO: AsyncRead + Unpin,
    P: IdentityResolver + Unpin,
    K: DecryptionKeys + Unpin,
{
    type Item = Result<(), ReceiveError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.received_valid_message_from.is_some() {
            this.received_valid_message_from = None;
            this.received_message_was_encrypted = false;
        }
        loop {
            match ready!(Pin::new(&mut this.receive).poll_next(cx)) {
                Some(result) => result?,
                None => return Poll::Ready(None),
            }
            let (header, data) = this.receive.received_mut().ok_or(Bug::ReceivedNone)?;
            let sender = match this.parties.lookup_party_index(&header.sender) {
                Some(sender) => sender,
                None => {
                    // Sender is unknown, ignore this message
                    continue;
                }
            };

            if !header.is_broadcast {
                if let Some(decryption_key) =
                    this.decryption_keys.get_decryption_key(&header.sender)
                {
                    let mut tag = GenericArray::<u8, <K::Key as DecryptionKey>::TagSize>::default();
                    if data.len() < tag.len() {
                        return Poll::Ready(Some(Err(InvalidMessage::Decryption.into())));
                    }
                    let (buffer, tag_bytes) = data.split_at_mut(data.len() - tag.len());
                    tag.as_mut_slice().copy_from_slice(&tag_bytes);

                    decryption_key
                        .decrypt(&[], buffer, &tag)
                        .map_err(|_| InvalidMessage::Decryption)?;
                    this.received_message_was_encrypted = true;
                }
            }

            this.received_valid_message_from = Some(sender);
            return Poll::Ready(Some(Ok(())));
        }
    }
}
