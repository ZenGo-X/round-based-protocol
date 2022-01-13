use std::sync::Arc;

use tokio::sync::{Notify, RwLock};

use crate::crypto::CryptoSuite;

use crate::messages::{ForwardMsgHeader, PublishMessageHeader};

pub struct Room<C: CryptoSuite> {
    history: RwLock<RoomHistory<C>>,
    history_changed: Notify,
}

impl<C: CryptoSuite> Room<C> {
    pub fn subscribe(self: Arc<Self>, subscriber: C::VerificationKey) -> Subscription<C> {
        Subscription {
            subscriber,
            room: self,
            next_message: 0,
            buffer: vec![],
        }
    }

    pub async fn publish_message(
        &self,
        author: C::VerificationKey,
        header: PublishMessageHeader<C>,
        msg: &[u8],
    ) {
        debug_assert_eq!(usize::from(header.message_body_len), msg.len());
        let mut history = self.history.write().await;

        let offset = history.concated_messages.len();
        history.concated_messages.resize(offset + msg.len(), 0);
        history.concated_messages[offset..].copy_from_slice(msg);

        history.headers.push(MessageHeader {
            offset,
            len: header.message_body_len,
            sender: author,
            recipient: header.recipient,
            signature: header.signature,
        });

        self.history_changed.notify_waiters();
    }
}

struct RoomHistory<C: CryptoSuite> {
    headers: Vec<MessageHeader<C>>,
    concated_messages: Vec<u8>,
}

struct MessageHeader<C: CryptoSuite> {
    offset: usize,
    len: u16,
    sender: C::VerificationKey,
    recipient: Option<C::VerificationKey>,
    signature: C::Signature,
}

pub struct Subscription<C: CryptoSuite> {
    subscriber: C::VerificationKey,
    room: Arc<Room<C>>,
    next_message: usize,
    buffer: Vec<u8>,
}

impl<C: CryptoSuite> Subscription<C> {
    pub async fn next(&mut self) -> (ForwardMsgHeader<C>, &[u8]) {
        loop {
            let history = self.room.history.read().await;
            if let Some(header) = history.headers.get(self.next_message) {
                self.next_message += 1;

                if header.recipient.is_some() && header.recipient.as_ref() != Some(&self.subscriber)
                {
                    continue;
                }

                self.buffer.resize(usize::from(header.len), 0);
                self.buffer.copy_from_slice(
                    &history.concated_messages
                        [header.offset..header.offset + usize::from(header.len)],
                );

                let header = ForwardMsgHeader {
                    sender: header.sender.clone(),
                    is_broadcast: header.recipient.is_some(),
                    signature: header.signature.clone(),
                    data_len: header.len,
                };

                return (header, &self.buffer);
            }

            let notification = self.room.history_changed.notified();
            drop(history);
            notification.await;
        }
    }
}
