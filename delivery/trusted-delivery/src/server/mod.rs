use std::collections::hash_map::{Entry, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use thiserror::Error;

use tokio::sync::{Notify, RwLock, RwLockReadGuard, RwLockWriteGuard};

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

    pub async fn get_room_or_create_empty<'db>(
        &'db self,
        room_id: RoomId,
    ) -> LockedDb<'db, C, Arc<Room<C>>> {
        let rooms = self.rooms.read().await;

        match rooms.get(&room_id) {
            Some(room) if !room.is_abandoned() => {
                return LockedDb {
                    inner: room.clone(),
                    _lock: DbLock::ReadLock(rooms),
                };
            }
            _ => (),
        }

        drop(rooms);
        let mut rooms = self.rooms.write().await;

        match rooms.entry(room_id) {
            Entry::Occupied(room) if !room.get().is_abandoned() => LockedDb {
                inner: room.get().clone(),
                _lock: DbLock::ReadLock(rooms.downgrade()),
            },
            Entry::Occupied(mut entry) => {
                let room = Arc::new(Room::empty());
                *entry.get_mut() = room.clone();
                LockedDb {
                    inner: room,
                    _lock: DbLock::WriteLock(rooms),
                }
            }
            Entry::Vacant(entry) => {
                let room = entry.insert(Arc::new(Room::empty())).clone();
                LockedDb {
                    inner: room,
                    _lock: DbLock::WriteLock(rooms),
                }
            }
        }
    }
}

pub struct LockedDb<'db, C: CryptoSuite, T> {
    inner: T,
    _lock: DbLock<'db, C>,
}

impl<'db, C: CryptoSuite, T> LockedDb<'db, C, T> {
    pub fn map<K, F>(self, f: F) -> LockedDb<'db, C, K>
    where
        F: FnOnce(T) -> K,
    {
        LockedDb {
            inner: f(self.inner),
            _lock: self._lock,
        }
    }

    pub fn unlock_db(self) -> T {
        self.inner
    }
}

enum DbLock<'db, C: CryptoSuite> {
    ReadLock(RwLockReadGuard<'db, HashMap<RoomId, Arc<Room<C>>>>),
    WriteLock(RwLockWriteGuard<'db, HashMap<RoomId, Arc<Room<C>>>>),
}

pub struct Room<C: CryptoSuite> {
    history: RwLock<RoomHistory<C>>,
    history_changed: Notify,

    subscribers: AtomicUsize,
    writers: AtomicUsize,
}

impl<C: CryptoSuite> Room<C> {
    fn empty() -> Self {
        Self {
            history: RwLock::new(RoomHistory {
                headers: vec![],
                concated_messages: vec![],
            }),
            history_changed: Notify::new(),

            subscribers: AtomicUsize::new(0),
            writers: AtomicUsize::new(0),
        }
    }

    pub fn subscribe(self: Arc<Self>, subscriber: C::VerificationKey) -> Subscription<C> {
        self.subscribers.fetch_add(1, Ordering::Relaxed);

        Subscription {
            subscriber,
            room: self,
            next_message: 0,
            buffer: vec![],
        }
    }

    pub fn add_writer(self: Arc<Self>, writer_identity: C::VerificationKey) -> Writer<C> {
        self.writers.fetch_add(1, Ordering::Relaxed);

        Writer {
            writer_identity,
            room: self,
        }
    }

    pub fn is_abandoned(&self) -> bool {
        self.subscribers.load(Ordering::Relaxed) == 0 && self.writers.load(Ordering::Relaxed) == 0
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
                    is_broadcast: header.recipient.is_none(),
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

#[cfg(test)]
mod tests {
    use std::iter;

    use crate::crypto::default_suite::DefaultSuite;
    use crate::crypto::*;

    use super::*;

    const TEST_ROOM: RoomId = *b"0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn message_is_broadcasted_to_everyone() {
        message_is_broadcasted_to_everyone_generic::<DefaultSuite>().await;
    }

    async fn message_is_broadcasted_to_everyone_generic<C: CryptoSuite>() {
        let db = Db::<C>::empty();

        let mut parties = MockedParties::generate(&db, TEST_ROOM, 3).await;

        let msg = b"hello everyone, ready to generate some threshold keys?";
        let publish_header = PublishMessageHeader::<C>::new(&parties.sk[0], None, msg, &[]);
        let forward_header = ForwardMsgHeader::new(&parties.sk[0], None, msg);

        parties.writer[0]
            .publish_message(publish_header, msg.as_ref())
            .await
            .unwrap();

        for subscription in &mut parties.subscription {
            let (received_header, received_msg) = subscription.next().await;
            assert_eq!(forward_header, received_header);
            assert_eq!(msg.as_ref(), received_msg);
        }
    }

    struct MockedParties<C: CryptoSuite> {
        pub sk: Vec<C::SigningKey>,
        pub pk: Vec<C::VerificationKey>,
        pub subscription: Vec<Subscription<C>>,
        pub writer: Vec<Writer<C>>,
    }

    impl<C: CryptoSuite> MockedParties<C> {
        pub async fn generate(db: &Db<C>, room_id: RoomId, n: usize) -> Self {
            let sk: Vec<C::SigningKey> = iter::repeat_with(|| C::SigningKey::generate())
                .take(n)
                .collect();
            let pk: Vec<C::VerificationKey> = sk.iter().map(|sk| sk.verification_key()).collect();

            let mut subscription = vec![];
            let mut writer = vec![];
            for pk_i in &pk {
                let subscription_i = db
                    .get_room_or_create_empty(room_id)
                    .await
                    .map(|room| room.subscribe(pk_i.clone()))
                    .unlock_db();
                subscription.push(subscription_i);

                let writer_i = db
                    .get_room_or_create_empty(room_id)
                    .await
                    .map(|room| room.add_writer(pk_i.clone()))
                    .unlock_db();
                writer.push(writer_i);
            }

            Self {
                sk,
                pk,
                subscription,
                writer,
            }
        }
    }
}
