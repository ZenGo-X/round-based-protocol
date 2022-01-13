use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use thiserror::Error;

use tokio::sync::{Notify, RwLock};

use crate::crypto::CryptoSuite;

use crate::messages::{ForwardMsgHeader, PublishMessageHeader, RoomId};

pub struct Db<C: CryptoSuite> {
    rooms: RwLock<HashMap<RoomId, Arc<Room<C>>>>,
}

impl<C: CryptoSuite> Db<C> {
    pub fn empty() -> Self {
        Self {
            rooms: Default::default(),
        }
    }

    // pub fn get_room_or_create_empty(&self, room_id: RoomId)
}

pub struct Room<C: CryptoSuite> {
    history: RwLock<RoomHistory<C>>,
    history_changed: Notify,

    subscribers: AtomicUsize,
    writers: AtomicUsize,
}

impl<C: CryptoSuite> Room<C> {
    pub fn subscribe(self: Arc<Self>, subscriber: C::VerificationKey) -> Subscription<C> {
        self.subscribers.fetch_add(1, Ordering::Relaxed);

        Subscription {
            subscriber,
            room: self,
            next_message: 0,
            buffer: vec![],
        }
    }

    pub async fn add_writer(self: Arc<Self>, writer_identity: C::VerificationKey) -> Writer<C> {
        self.writers.fetch_add(1, Ordering::Relaxed);

        Writer {
            writer_identity,
            room: self,
        }
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

impl<C: CryptoSuite> Drop for Subscription<C> {
    fn drop(&mut self) {
        self.room.subscribers.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct Writer<C: CryptoSuite> {
    writer_identity: C::VerificationKey,
    room: Arc<Room<C>>,
}

impl<C: CryptoSuite> Writer<C> {
    pub async fn publish_message(
        &self,
        header: PublishMessageHeader<C>,
        msg: &[u8],
    ) -> Result<(), MismatchedSignature> {
        debug_assert_eq!(usize::from(header.message_body_len), msg.len());
        header
            .verify(&self.writer_identity, msg)
            .or(Err(MismatchedSignature))?;

        let mut history = self.room.history.write().await;

        let offset = history.concated_messages.len();
        history.concated_messages.resize(offset + msg.len(), 0);
        history.concated_messages[offset..].copy_from_slice(msg);

        history.headers.push(MessageHeader {
            offset,
            len: header.message_body_len,
            sender: self.writer_identity.clone(),
            recipient: header.recipient,
            signature: header.signature,
        });

        self.room.history_changed.notify_waiters();

        Ok(())
    }
}

impl<C: CryptoSuite> Drop for Writer<C> {
    fn drop(&mut self) {
        self.room.writers.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Error)]
#[error("message signature doesn't match its content")]
pub struct MismatchedSignature;
