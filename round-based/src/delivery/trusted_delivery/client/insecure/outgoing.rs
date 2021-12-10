use std::convert::TryInto;
use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use generic_array::typenum::Unsigned;
use secp256k1::{PublicKey, SecretKey};
use serde::Serialize;

use futures::ready;
use tokio::io::{self, AsyncWrite};

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::client::insecure::crypto::{EncryptionKey, EncryptionKeys};
use crate::delivery::trusted_delivery::messages::{FixedSizeMsg, PublishMsgHeader};
use crate::delivery::OutgoingChannel;
use crate::{Outgoing, OutgoingDelivery};

pub struct Outgoings<P, K, IO> {
    identity_key: SecretKey,
    parties: P,
    encryption_keys: K,

    /// ```text
    /// [<header1><data1><header2><data2><    capacity    >]
    ///                  ^- sent_bytes   ^- filled_bytes
    /// ```
    ///
    /// * Message can be pushed to the buffer as long as `<capacity>` fits entire message
    /// * Sending message with size more than [`buffer_limit`] results into error
    /// * If buffer size is less than message size, buffer is resized to message size
    /// * If buffer capacity can't fit a message, it needs to be flushed. Otherwise, we append message
    ///   to the buffer, and increase [`filled_bytes`] counter.
    /// * Flushing works by sending bytes from head of buffer to downstream [`channel`] and increasing
    ///   [`sent_bytes`] counter
    /// * Once `sent_bytes == filled_bytes`, we reset `sent_bytes = 0` and `filled_bytes = 0`. Now buffer
    ///   can fit more messages.
    ///
    /// [`channel`]: Self::channel
    /// [`sent_bytes`]: Self::sent_bytes
    /// [`buffer_limit`]: Self::buffer_limit
    /// [`filled_bytes`]: Self::filled_bytes
    buffer: Vec<u8>,
    sent_bytes: usize,
    filled_bytes: usize,
    buffer_limit: usize,

    channel: IO,
}

impl<P, K, IO> Outgoings<P, K, IO>
where
    P: IdentityResolver + Unpin,
    K: EncryptionKeys + Unpin,
    IO: AsyncWrite + Unpin,
{
    pub fn new(identity_key: SecretKey, parties: P, encryption_keys: K, channel: IO) -> Self {
        Self {
            identity_key,
            parties,
            encryption_keys,
            channel,
            buffer: vec![0; 1000],
            sent_bytes: 0,
            filled_bytes: 0,
            buffer_limit: 10_000,
        }
    }
    pub fn set_initial_buffer_capacity(&mut self, capacity: usize) {
        assert_ne!(self.filled_bytes, 0);
        self.buffer.resize(capacity, 0)
    }
    pub fn set_buffer_size_limit(&mut self, limit: usize) {
        self.buffer_limit = limit
    }
}

impl<'msg, P, K, IO, M> OutgoingDelivery<M> for Outgoings<P, K, IO>
where
    M: Serialize,
    P: IdentityResolver + Unpin,
    K: EncryptionKeys + Unpin,
    IO: AsyncWrite + Unpin,
{
    fn message_size(self: Pin<&Self>, msg: Outgoing<&M>) -> io::Result<MessageSize> {
        let recipient = self.lookup_recipient_pk(msg.recipient)?;
        let shall_be_encrypted = recipient
            .map(|pk_i| self.encryption_keys.has_encryption_key(&pk_i))
            .unwrap_or(false);
        let serialized_msg_size: usize = bincode::serialized_size(msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
        Ok(MessageSize(
            PublishMsgHeader::SIZE
                + serialized_msg_size
                + if shall_be_encrypted {
                    <K::Key as EncryptionKey>::TagSize::USIZE
                } else {
                    0
                },
        ))
    }
    fn start_send(mut self: Pin<&mut Self>, msg: Outgoing<&M>) -> io::Result<()> {
        let this = &mut *self;

        let recipient = this.lookup_recipient_pk(msg.recipient)?;

        let (_filled, capacity) = this.buffer.split_at_mut(this.filled_bytes);
        let (header, capacity) = capacity.split_at_mut(PublishMsgHeader::SIZE);

        let mut writer = Cursor::new(&mut *capacity);
        bincode::serialize_into(&mut writer, &msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let msg_len: usize = writer.position().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "cannot convert cursor position to usize",
            )
        })?;
        let (data, capacity) = capacity.split_at_mut(msg_len);

        let constructed_header = if let Some(recipient) = recipient {
            if let Some(ek) = this.encryption_keys.get_encryption_key(&recipient) {
                let (tag, _capacity) =
                    capacity.split_at_mut(<K::Key as EncryptionKey>::TagSize::USIZE);
                let tag_bytes = ek.encrypt(&[], data).map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "cannot encrypt the message")
                })?;
                tag.copy_from_slice(tag_bytes.as_slice());
                PublishMsgHeader::new(&this.identity_key, Some(recipient), data, tag)
            } else {
                PublishMsgHeader::new(&this.identity_key, Some(recipient), data, &[])
            }
        } else {
            PublishMsgHeader::new(&this.identity_key, recipient, data, &[])
        };

        header.copy_from_slice(&constructed_header.to_bytes());
        this.filled_bytes +=
            PublishMsgHeader::SIZE + usize::from(constructed_header.message_body_len);

        Ok(())
    }
}

impl<'msg, P, K, IO> Outgoings<P, K, IO>
where
    P: IdentityResolver + Unpin,
    K: EncryptionKeys + Unpin,
    IO: AsyncWrite + Unpin,
{
    fn lookup_recipient_pk(&self, recipient_index: Option<u16>) -> io::Result<Option<PublicKey>> {
        match recipient_index {
            Some(i) => {
                let identity = self.parties.lookup_party_identity(i).ok_or(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unknown recipient #{}", i),
                ))?;
                Ok(Some(*identity))
            }
            None => Ok(None),
        }
    }
}

impl<'msg, P, K, IO> OutgoingChannel for Outgoings<P, K, IO>
where
    P: IdentityResolver + Unpin,
    K: EncryptionKeys + Unpin,
    IO: AsyncWrite + Unpin,
{
    type MessageSize = MessageSize;

    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        &MessageSize(msg_size): &MessageSize,
    ) -> Poll<io::Result<()>> {
        if msg_size > self.buffer_limit {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "message too long: len={}, limit={}",
                    msg_size, self.buffer_limit
                ),
            )));
        }
        if msg_size > self.buffer.len() {
            self.buffer.resize(msg_size, 0)
        }
        if msg_size > self.buffer.len() - self.filled_bytes {
            // Not enough capacity - need to drain the buffer
            ready!(Pin::new(&mut *self).poll_flush(cx))?;
            debug_assert!(self.filled_bytes == 0);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;
        while this.sent_bytes != this.filled_bytes {
            let filled_not_sent = &this.buffer[this.sent_bytes..this.filled_bytes];
            this.sent_bytes += ready!(Pin::new(&mut this.channel).poll_write(cx, filled_not_sent))?;
        }

        ready!(Pin::new(&mut this.channel).poll_flush(cx))?;

        this.sent_bytes = 0;
        this.filled_bytes = 0;

        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.channel).poll_shutdown(cx)
    }
}

pub struct SendingMsg<'msg, M> {
    msg: Outgoing<&'msg M>,
    recipient: Option<PublicKey>,
    shall_be_encrypted: bool,
    serialized_plaintext_len: u16,
}

impl<'msg, M> SendingMsg<'msg, M> {
    fn serialized_size<K: EncryptionKey>(&self) -> usize {
        PublishMsgHeader::SIZE
            + usize::from(self.serialized_plaintext_len)
            + if self.shall_be_encrypted {
                K::TagSize::USIZE
            } else {
                0
            }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MessageSize(usize);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::iter::FromIterator;
    use std::pin::Pin;

    use aes_gcm::Aes256Gcm;
    use aes_gcm::NewAead;
    use generic_array::GenericArray;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use serde::{Deserialize, Serialize};

    use proptest::prelude::*;

    use crate::delivery::trusted_delivery::client::insecure::crypto::{
        AesGcmEncryptionKey, EncryptionKey,
    };
    use crate::delivery::trusted_delivery::client::insecure::outgoing::Outgoings;
    use crate::delivery::trusted_delivery::messages::{FixedSizeMsg, PublishMsgHeader};
    use crate::{Outgoing, OutgoingDelivery};

    use crate::delivery::trusted_delivery::client::insecure::test_utils::generate_parties_sk;
    use crate::delivery::OutgoingChannel;

    #[derive(Debug, Serialize, Deserialize)]
    struct Message {
        string_field: String,
        integer: u128,
    }

    fn generate_aes_key() -> Aes256Gcm {
        let mut key = GenericArray::default();
        OsRng.fill_bytes(key.as_mut_slice());
        Aes256Gcm::new(&key)
    }

    fn message() -> impl Strategy<Value = Outgoing<Message>> {
        (1..=5u16, ".{1,100}", any::<u128>()).prop_map(|(recipient, string_field, integer)| {
            Outgoing {
                recipient: if recipient == 5 {
                    None
                } else {
                    Some(recipient)
                },
                msg: Message {
                    string_field,
                    integer,
                },
            }
        })
    }

    proptest! {
        #[test]
        fn fuzz_outgoings(msgs in prop::collection::vec(message(), 1..1000)) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(test_on_messages(msgs))?
        }
    }

    async fn test_on_messages(msgs: Vec<Outgoing<Message>>) -> Result<(), TestCaseError> {
        let (pk, sk) = generate_parties_sk(5);
        let mut ek = HashMap::from_iter([
            (pk[3], AesGcmEncryptionKey::new(0, generate_aes_key())),
            (pk[4], AesGcmEncryptionKey::new(0, generate_aes_key())),
        ]);

        let mut actual = vec![];
        let mut expected = vec![];

        let mut outgoing = Outgoings::new(
            sk[0].clone(),
            pk.clone(),
            ek.clone(),
            Cursor::new(&mut actual),
        );

        for Outgoing { recipient, msg } in msgs {
            let mut outgoing = Pin::new(&mut outgoing);

            let has_to_be_encrypted = recipient == Some(3) || recipient == Some(4);
            let serialized_data = bincode::serialize(&msg).unwrap();
            let msg_size = PublishMsgHeader::SIZE
                + serialized_data.len()
                + if has_to_be_encrypted { 16 } else { 0 };
            let recipient_pk = recipient.map(|i| pk[usize::from(i)]);

            let len = expected.len();
            expected.resize(len + msg_size, 0);
            let expected = &mut expected[len..];
            expected[PublishMsgHeader::SIZE..PublishMsgHeader::SIZE + serialized_data.len()]
                .copy_from_slice(&serialized_data);
            if has_to_be_encrypted {
                let recipient = recipient_pk.unwrap();
                let ek_i = ek.get_mut(&recipient).unwrap();
                let tag = ek_i
                    .encrypt(
                        &[],
                        &mut expected[PublishMsgHeader::SIZE
                            ..PublishMsgHeader::SIZE + serialized_data.len()],
                    )
                    .unwrap();
                expected[PublishMsgHeader::SIZE + serialized_data.len()..]
                    .copy_from_slice(tag.as_slice());
            }
            let header = PublishMsgHeader::new(
                &sk[0],
                recipient_pk,
                &expected[PublishMsgHeader::SIZE..PublishMsgHeader::SIZE + serialized_data.len()],
                &expected[PublishMsgHeader::SIZE + serialized_data.len()..],
            );
            let header = header.to_bytes();
            expected[..PublishMsgHeader::SIZE].copy_from_slice(&header);

            let msg = Outgoing {
                recipient,
                msg: &msg,
            };
            let message_size = outgoing.as_ref().message_size(msg).unwrap();
            futures::future::poll_fn(|cx| outgoing.as_mut().poll_ready(cx, &message_size))
                .await
                .unwrap();
            let old_position = outgoing.filled_bytes;
            outgoing.as_mut().start_send(msg).unwrap();
            let new_position = outgoing.filled_bytes;
            prop_assert_eq!(message_size.0, new_position - old_position)
        }

        futures::future::poll_fn(move |cx| Pin::new(&mut outgoing).poll_flush(cx))
            .await
            .unwrap();

        // println!("Actual  : {}", hex::encode(&actual));
        // println!("Expected: {}", hex::encode(&expected));
        prop_assert_eq!(actual, expected);
        Ok(())
    }
}
