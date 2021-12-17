use std::collections::HashMap;
use std::io::{self, ErrorKind, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, AsyncWrite, Sink};
use generic_array::GenericArray;
use serde::Serialize;
use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::{
    IdentityResolver, SortedIdentities,
};
use crate::delivery::trusted_delivery::client::insecure::crypto::default_suite::DefaultSuite;
use crate::delivery::trusted_delivery::client::insecure::crypto::{
    CryptoSuite, EncryptionKey, EncryptionKeys,
};
use crate::delivery::trusted_delivery::messages::{FixedSizeMessage, PublishMessageHeader};
use crate::Outgoing;

pub struct OutgoingMessages<
    IO,
    C: CryptoSuite = DefaultSuite,
    P = SortedIdentities<<C as CryptoSuite>::VerificationKey>,
    E: EncryptionKeys = HashMap<
        <C as CryptoSuite>::VerificationKey,
        <C as CryptoSuite>::EncryptionKey,
    >,
    S = Bincode,
> {
    channel: IO,
    parties: P,
    encryption_keys: E,
    serializer: S,
    identity_key: C::SigningKey,

    in_progress: bool,
    header: GenericArray<u8, <PublishMessageHeader<C> as FixedSizeMessage>::Size>,
    body: Vec<u8>,
    tag: GenericArray<u8, E::TagSize>,
    bytes_written: usize,
}

impl<T, IO, C, P, E, S> Sink<Outgoing<&T>> for OutgoingMessages<IO, C, P, E, S>
where
    IO: AsyncWrite + Unpin,
    C: CryptoSuite,
    P: IdentityResolver<Identity = C::VerificationKey> + Unpin,
    E: EncryptionKeys<
            Identity = C::VerificationKey,
            Key = C::EncryptionKey,
            TagSize = C::EncryptionTagSize,
        > + Unpin,
    S: SerializationBackend<T> + Unpin,
    GenericArray<u8, <PublishMessageHeader<C> as FixedSizeMessage>::Size>: Unpin,
    GenericArray<u8, E::TagSize>: Unpin,
{
    type Error = SendError<S::Error>;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;

        if !this.in_progress {
            return Poll::Ready(Ok(()));
        }

        while this.bytes_written < this.header.len() {
            let written = ready!(Pin::new(&mut this.channel).poll_write_vectored(
                cx,
                &[
                    IoSlice::new(&this.header[this.bytes_written..]),
                    IoSlice::new(&this.body),
                    IoSlice::new(&this.tag),
                ]
            ))?;

            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            this.bytes_written += written
        }

        while this.bytes_written - this.header.len() < this.body.len() {
            let written = ready!(Pin::new(&mut this.channel).poll_write_vectored(
                cx,
                &[
                    IoSlice::new(&this.body[this.bytes_written - this.header.len()..]),
                    IoSlice::new(&this.tag),
                ]
            ))?;

            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            this.bytes_written += written
        }

        while this.bytes_written - this.header.len() - this.body.len() < this.tag.len() {
            let written = ready!(Pin::new(&mut this.channel).poll_write(
                cx,
                &this.tag[this.bytes_written - this.header.len() - this.body.len()..]
            ))?;

            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            this.bytes_written += written
        }

        this.body.clear();
        this.bytes_written = 0;
        this.in_progress = false;

        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, message: Outgoing<&T>) -> Result<(), Self::Error> {
        let this = &mut *self;

        if this.in_progress {
            return Err(SendError::NotReady);
        }

        let recipient = message
            .recipient
            .map(|recipient| {
                this.parties
                    .lookup_party_identity(recipient)
                    .ok_or(SendError::UnknownRecipient {
                        recipient,
                        n: this.parties.number_of_parties(),
                    })
            })
            .transpose()?
            .cloned();

        this.serializer
            .serialize_into(message.msg, &mut this.body)
            .map_err(SendError::Serialization)?;

        let encryption_keys = &mut this.encryption_keys;
        if let Some(ek) = recipient
            .as_ref()
            .and_then(|recipient| encryption_keys.get_encryption_key(&recipient))
        {
            this.tag = ek
                .encrypt(&[], &mut this.body)
                .or(Err(SendError::Encrypt))?;
        }

        let header =
            PublishMessageHeader::<C>::new(&this.identity_key, recipient, &this.body, &this.tag);
        this.header = header.to_bytes();

        this.in_progress = true;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx))?;
        ready!(Pin::new(&mut self.channel).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx))?;
        ready!(Pin::new(&mut self.channel).poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Error)]
pub enum SendError<S> {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("channel is not ready to send a message (missing `poll_ready` call)")]
    NotReady,
    #[error("recipient index (i={recipient}) is out of range: there are only n={n} parties, index must be in range [0; n)")]
    UnknownRecipient { recipient: u16, n: u16 },
    #[error("cannot serialize a message")]
    Serialization(#[source] S),
    #[error("cannot encrypt a message")]
    Encrypt,
}

impl<S> From<io::ErrorKind> for SendError<S> {
    fn from(e: ErrorKind) -> Self {
        io::Error::from(e).into()
    }
}

pub trait SerializationBackend<T> {
    type Error;

    fn serialize_into(&self, value: &T, buffer: &mut Vec<u8>) -> Result<(), Self::Error>;
}

pub struct Bincode;

impl<T> SerializationBackend<T> for Bincode
where
    T: Serialize,
{
    type Error = bincode::Error;

    fn serialize_into(&self, value: &T, buffer: &mut Vec<u8>) -> Result<(), Self::Error> {
        bincode::serialize_into(buffer, value)
    }
}
