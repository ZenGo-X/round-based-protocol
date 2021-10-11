use std::convert::TryInto;
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
use crate::{DeliverOutgoing, Outgoing};

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

impl<'msg, P, K, IO, M> DeliverOutgoing<'msg, &'msg M> for Outgoings<P, K, IO>
where
    P: IdentityResolver + Unpin,
    K: EncryptionKeys + Unpin,
    IO: AsyncWrite + Unpin,
    M: Serialize,
{
    type Prepared = SendingMsg<'msg, M>;

    fn prepare(self: Pin<&Self>, msg: Outgoing<&'msg M>) -> Result<Self::Prepared, Self::Error> {
        let recipient = match msg.recipient {
            Some(i) => {
                let identity = self.parties.lookup_party_identity(i).ok_or(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unknown recipient #{}", i),
                ))?;
                Some(identity)
            }
            None => None,
        };
        let shall_be_encrypted = recipient
            .map(|pk_i| self.encryption_keys.has_encryption_key(pk_i))
            .unwrap_or(false);
        let msg_size: u16 = bincode::serialized_size(msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
        Ok(SendingMsg {
            msg,
            shall_be_encrypted,
            recipient: recipient.copied(),
            serialized_plaintext_len: msg_size,
        })
    }

    fn poll_start_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        msg: &mut Self::Prepared,
    ) -> Poll<Result<(), Self::Error>> {
        let this = &mut *self;
        let msg_size = msg.serialized_size::<K::Key>();
        if msg_size > this.buffer_limit {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "message too long: len={}, limit={}",
                    msg_size, this.buffer_limit
                ),
            )));
        }
        if msg_size > this.buffer.len() {
            this.buffer.resize(msg_size, 0)
        }
        if msg_size > this.buffer.len() - this.filled_bytes {
            // Not enough capacity - need to drain the buffer
            ready!(Pin::new(&mut *this).poll_flush(cx))?;
            debug_assert!(this.filled_bytes == 0);
        }

        let (_filled, capacity) = this.buffer.split_at_mut(this.filled_bytes);
        let (msg_bytes, _capacity) = capacity.split_at_mut(msg_size);
        let (header, data) = msg_bytes.split_at_mut(PublishMsgHeader::SIZE);
        let (data, tag) = data.split_at_mut(msg.serialized_plaintext_len.into());

        bincode::serialize_into(&mut *data, &msg.msg.msg)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if msg.shall_be_encrypted {
            let recipient = msg.recipient.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "bug: recipient must be specified (see prepare method)",
                )
            })?;
            let encryption_key = this
                .encryption_keys
                .get_encryption_key(&recipient)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "bug: recipient enc key not found (see prepare method)",
                    )
                })?;
            let tag_bytes = encryption_key
                .encrypt(&[], &mut *data)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "cannot decrypt the message"))?;
            tag.copy_from_slice(tag_bytes.as_slice());
        }

        let constructed_header =
            PublishMsgHeader::new(&this.identity_key, msg.recipient, data, tag);
        header.copy_from_slice(&constructed_header.to_bytes());

        this.filled_bytes += msg_size;

        Poll::Ready(Ok(()))
    }
}

impl<'msg, P, K, IO> OutgoingChannel for Outgoings<P, K, IO>
where
    P: IdentityResolver + Unpin,
    K: EncryptionKeys + Unpin,
    IO: AsyncWrite + Unpin,
{
    type Error = io::Error;

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
    use crate::{DeliverOutgoingExt, Outgoing};

    use crate::delivery::trusted_delivery::client::insecure::incoming::tests::generate_parties_sk;

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
        let mut outgoing = Pin::new(&mut outgoing);

        for Outgoing { recipient, msg } in msgs {
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

            outgoing
                .send(Outgoing {
                    recipient,
                    msg: &msg,
                })
                .await
                .unwrap();
        }

        // println!("Actual  : {}", hex::encode(&actual));
        // println!("Expected: {}", hex::encode(&expected));
        prop_assert_eq!(actual, expected);
        Ok(())
    }
}
