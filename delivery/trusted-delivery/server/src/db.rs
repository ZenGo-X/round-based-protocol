use std::collections::hash_map::{Entry, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use thiserror::Error;

use tokio::sync::{Notify, RwLock, RwLockReadGuard, RwLockWriteGuard};

use trusted_delivery_core::crypto::CryptoSuite;
use trusted_delivery_core::publish_msg::{
    ForwardMessageHeader, Header, MessageDestination, PublishMessageHeader,
};
use trusted_delivery_core::RoomId;

pub struct Db<C: CryptoSuite> {
    rooms: RwLock<HashMap<RoomId, Arc<Room<C>>>>,
}

impl<C: CryptoSuite> Db<C> {
    pub fn empty() -> Self {
        Self {
            rooms: Default::default(),
        }
    }

    pub async fn get_room<'db>(
        &'db self,
        room_id: RoomId,
    ) -> Option<LockedDb<'db, C, Arc<Room<C>>>> {
        let rooms = self.rooms.read().await;

        match rooms.get(&room_id) {
            Some(room) if !room.is_abandoned() => Some(LockedDb {
                inner: room.clone(),
                _lock: DbLock::ReadLock(rooms),
            }),
            _ => None,
        }
    }

    pub async fn get_room_or_create_empty<'db>(
        &'db self,
        room_id: RoomId,
    ) -> LockedDb<'db, C, Arc<Room<C>>> {
        if let Some(room) = self.get_room(room_id).await {
            return room;
        }

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
                let room = Arc::new(Room::empty());
                entry.insert(room.clone());
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
                sequence_numbers: HashMap::new(),
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
        self.subscribers() == 0 && self.writers() == 0
    }

    pub fn subscribers(&self) -> usize {
        self.subscribers.load(Ordering::Relaxed)
    }

    pub fn writers(&self) -> usize {
        self.writers.load(Ordering::Relaxed)
    }
}

struct RoomHistory<C: CryptoSuite> {
    headers: Vec<MessageHeader<C>>,
    concated_messages: Vec<u8>,
    sequence_numbers: HashMap<C::VerificationKey, u16>,
}

struct MessageHeader<C: CryptoSuite> {
    offset: usize,
    len: u16,
    sender: C::VerificationKey,
    recipient: MessageDestination<C::VerificationKey>,
    signature: C::Signature,
}

pub struct Subscription<C: CryptoSuite> {
    subscriber: C::VerificationKey,
    room: Arc<Room<C>>,
    next_message: usize,
    buffer: Vec<u8>,
}

impl<C: CryptoSuite> Subscription<C> {
    pub async fn next(&mut self) -> (ForwardMessageHeader<C>, &[u8]) {
        loop {
            let history = self.room.history.read().await;
            if let Some(header) = history.headers.get(self.next_message) {
                self.next_message += 1;

                if !header.recipient.is_broadcast()
                    && header.recipient.recipient_identity() != Some(&self.subscriber)
                {
                    continue;
                }

                self.buffer.resize(usize::from(header.len), 0);
                self.buffer.copy_from_slice(
                    &history.concated_messages
                        [header.offset..header.offset + usize::from(header.len)],
                );

                let header = ForwardMessageHeader {
                    sender: header.sender.clone(),
                    is_broadcast: header.recipient.is_broadcast(),
                    sequence_number: header.recipient.sequence_number(),
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
    ) -> Result<(), MalformedMessage> {
        debug_assert_eq!(usize::from(header.data_len), msg.len());
        header
            .verify(&self.writer_identity, msg)
            .or(Err(MalformedMessage::MismatchedSignature))?;

        let mut history = self.room.history.write().await;

        if let Some(seq_num) = header.recipient.sequence_number() {
            let expected = history
                .sequence_numbers
                .entry(self.writer_identity.clone())
                .or_insert(0);
            if seq_num != *expected {
                return Err(MalformedMessage::MismatchedSequenceNumber {
                    expected: *expected,
                    actual: seq_num,
                });
            }
            *expected += 1;
        }

        let offset = history.concated_messages.len();
        history.concated_messages.resize(offset + msg.len(), 0);
        history.concated_messages[offset..].copy_from_slice(msg);

        history.headers.push(MessageHeader {
            offset,
            len: header.data_len,
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
pub enum MalformedMessage {
    #[error("message signature doesn't match its content")]
    MismatchedSignature,
    #[error("mismatched sequence number: expected={expected} actual={actual}")]
    MismatchedSequenceNumber { expected: u16, actual: u16 },
}

#[cfg(test)]
mod tests {
    use std::iter;

    use matches::assert_matches;

    use trusted_delivery_core::crypto::default_suite::DefaultSuite;
    use trusted_delivery_core::crypto::*;

    use super::*;

    const TEST_ROOM: RoomId = *b"0123456789abcdef0123456789abcdef";
    const ANOTHER_ROOM: RoomId = *b"abcdabcdabcdabcdabcdabcdabcdabcd";

    #[tokio::test]
    async fn message_is_broadcasted_to_everyone() {
        message_is_broadcasted_to_everyone_generic::<DefaultSuite>().await;
    }

    async fn message_is_broadcasted_to_everyone_generic<C: CryptoSuite>() {
        let db = Db::<C>::empty();
        let mut group = MockedParties::generate(&db, TEST_ROOM, 3).await;

        let msg = b"hello everyone, ready to generate some threshold keys?";
        let publish_header = PublishMessageHeader::<C>::new(
            &group.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg,
        );
        let forward_header = ForwardMessageHeader::new(
            &group.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg,
        );

        group.writer[0]
            .publish_message(publish_header, msg.as_ref())
            .await
            .unwrap();

        for subscription in &mut group.subscription {
            let (received_header, received_msg) = subscription.next().await;
            assert_eq!(forward_header, received_header);
            assert_eq!(msg.as_ref(), received_msg);
        }
    }

    #[tokio::test]
    async fn p2p_message_is_sent_only_to_destination() {
        p2p_message_is_sent_only_to_destination_generic::<DefaultSuite>().await;
    }

    async fn p2p_message_is_sent_only_to_destination_generic<C: CryptoSuite>() {
        let db = Db::<C>::empty();
        let mut group = MockedParties::generate(&db, TEST_ROOM, 3).await;

        let direct_message = b"this is a direct message that'll be received only by destination";
        let publish_header1 = PublishMessageHeader::<C>::new(
            &group.sk[0],
            MessageDestination::OneParty {
                recipient_identity: group.pk[1].clone(),
            },
            direct_message,
        );
        let forward_header1 = ForwardMessageHeader::<C>::new(
            &group.sk[0],
            MessageDestination::OneParty {
                recipient_identity: group.pk[1].clone(),
            },
            direct_message,
        );

        let public_message = b"this message is seen by everyone";
        let publish_header2 = PublishMessageHeader::<C>::new(
            &group.sk[2],
            MessageDestination::AllParties { sequence_number: 0 },
            public_message,
        );
        let forward_header2 = ForwardMessageHeader::<C>::new(
            &group.sk[2],
            MessageDestination::AllParties { sequence_number: 0 },
            public_message,
        );

        group.writer[0]
            .publish_message(publish_header1, direct_message)
            .await
            .unwrap();
        group.writer[2]
            .publish_message(publish_header2, public_message)
            .await
            .unwrap();

        for (i, subscription_i) in group.subscription.iter_mut().enumerate() {
            if i == 1 {
                let (header, msg) = subscription_i.next().await;
                assert_eq!(header, forward_header1);
                assert_eq!(msg, direct_message.as_ref());
            }

            let (header, msg) = subscription_i.next().await;
            assert_eq!(header, forward_header2);
            assert_eq!(msg, public_message.as_ref());
        }
    }

    #[tokio::test]
    async fn message_appears_only_in_its_room() {
        message_appears_only_in_its_room_generic::<DefaultSuite>().await
    }

    async fn message_appears_only_in_its_room_generic<C: CryptoSuite>() {
        let db = Db::<C>::empty();

        let mut group1 = MockedParties::generate(&db, TEST_ROOM, 3).await;
        let mut group2 = MockedParties::generate(&db, ANOTHER_ROOM, 2).await;

        let msg1 = b"some message";
        let publish_header1 = PublishMessageHeader::<C>::new(
            &group1.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg1,
        );
        let forward_header1 = ForwardMessageHeader::<C>::new(
            &group1.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg1,
        );

        let msg2 = b"another message";
        let publish_header2 = PublishMessageHeader::<C>::new(
            &group2.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg2,
        );
        let forward_header2 = ForwardMessageHeader::<C>::new(
            &group2.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg2,
        );

        group1.writer[0]
            .publish_message(publish_header1, msg1)
            .await
            .unwrap();
        group2.writer[0]
            .publish_message(publish_header2, msg2)
            .await
            .unwrap();

        for subscription in &mut group1.subscription {
            let (header, msg) = subscription.next().await;
            assert_eq!(header, forward_header1);
            assert_eq!(msg, msg1);
        }

        for subscription in &mut group2.subscription {
            let (header, msg) = subscription.next().await;
            assert_eq!(header, forward_header2);
            assert_eq!(msg, msg2);
        }
    }

    #[tokio::test]
    async fn db_checks_that_being_published_message_is_not_temped() {
        db_checks_that_being_published_message_is_not_temped_generic::<DefaultSuite>().await
    }

    async fn db_checks_that_being_published_message_is_not_temped_generic<C: CryptoSuite>() {
        let db = Db::<C>::empty();
        let group = MockedParties::generate(&db, TEST_ROOM, 3).await;

        let msg = b"message sent by party";
        let publish_header = PublishMessageHeader::<C>::new(
            &group.sk[0],
            MessageDestination::AllParties { sequence_number: 0 },
            msg,
        );

        let temped_msg = b"MiTMed message ------";

        let result = group.writer[0]
            .publish_message(publish_header, temped_msg)
            .await;
        assert_matches!(result, Err(MalformedMessage::MismatchedSignature));
    }

    #[tokio::test]
    async fn db_checks_that_broadcast_messages_appear_in_expected_order() {
        db_checks_that_broadcast_messages_appear_in_expected_order_generic::<DefaultSuite>().await
    }

    async fn db_checks_that_broadcast_messages_appear_in_expected_order_generic<C: CryptoSuite>() {
        let db = Db::<C>::empty();
        let mut group = MockedParties::generate(&db, TEST_ROOM, 3).await;

        let msg0 = b"first broad message";
        let headers0 = group.derive_broadcast_message_headers(0, 0, msg0);

        let direct_msg = b"p2p message";
        let direct_headers = group.derive_direct_message_headers(0, 2, direct_msg);

        let msg1 = b"second broad message";
        let headers1 = group.derive_broadcast_message_headers(0, 1, msg1);

        let msg2 = b"third broad message";
        let headers2 = group.derive_broadcast_message_headers(1, 0, msg2);

        let msg3 = b"fourth broad message";
        let headers3 = group.derive_broadcast_message_headers(0, 2, msg3);

        let result = group.writer[0]
            .publish_message(headers1.publish.clone(), msg1)
            .await;
        assert_matches!(
            result,
            Err(MalformedMessage::MismatchedSequenceNumber { expected, actual }) if expected == 0 && actual == 1
        );

        group.writer[0]
            .publish_message(headers0.publish, msg0)
            .await
            .unwrap();
        group.writer[0]
            .publish_message(direct_headers.publish, direct_msg)
            .await
            .unwrap();

        let result = group.writer[0]
            .publish_message(headers3.publish.clone(), msg3)
            .await;
        assert_matches!(
            result,
            Err(MalformedMessage::MismatchedSequenceNumber { expected, actual }) if expected == 1 && actual == 2
        );

        group.writer[0]
            .publish_message(headers1.publish.clone(), msg1)
            .await
            .unwrap();
        group.writer[1]
            .publish_message(headers2.publish, msg2)
            .await
            .unwrap();

        let result = group.writer[0]
            .publish_message(headers1.publish.clone(), msg1)
            .await;
        assert_matches!(
            result,
            Err(MalformedMessage::MismatchedSequenceNumber { expected, actual }) if expected == 2 && actual == 1
        );

        group.writer[0]
            .publish_message(headers3.publish, msg3)
            .await
            .unwrap();

        for (i, subscription) in group.subscription.iter_mut().enumerate() {
            let (header, msg) = subscription.next().await;
            assert_eq!(header, headers0.forward);
            assert_eq!(msg, msg0);

            if i == 2 {
                let (header, msg) = subscription.next().await;
                assert_eq!(header, direct_headers.forward);
                assert_eq!(msg, direct_msg);
            }

            let (header, msg) = subscription.next().await;
            assert_eq!(header, headers1.forward);
            assert_eq!(msg, msg1);

            let (header, msg) = subscription.next().await;
            assert_eq!(header, headers2.forward);
            assert_eq!(msg, msg2);

            let (header, msg) = subscription.next().await;
            assert_eq!(header, headers3.forward);
            assert_eq!(msg, msg3);
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

        pub fn derive_broadcast_message_headers(
            &self,
            sender: u16,
            sequence_number: u16,
            msg: &[u8],
        ) -> DerivedHeaders<C> {
            let publish_header = PublishMessageHeader::<C>::new(
                &self.sk[usize::from(sender)],
                MessageDestination::AllParties { sequence_number },
                msg,
            );
            let forward_header = ForwardMessageHeader::<C>::new(
                &self.sk[usize::from(sender)],
                MessageDestination::AllParties { sequence_number },
                msg,
            );
            DerivedHeaders {
                publish: publish_header,
                forward: forward_header,
            }
        }

        pub fn derive_direct_message_headers(
            &self,
            sender: u16,
            recipient: u16,
            msg: &[u8],
        ) -> DerivedHeaders<C> {
            let publish_header = PublishMessageHeader::<C>::new(
                &self.sk[usize::from(sender)],
                MessageDestination::OneParty {
                    recipient_identity: self.pk[usize::from(recipient)].clone(),
                },
                msg,
            );
            let forward_header = ForwardMessageHeader::<C>::new(
                &self.sk[usize::from(sender)],
                MessageDestination::OneParty {
                    recipient_identity: self.pk[usize::from(recipient)].clone(),
                },
                msg,
            );
            DerivedHeaders {
                publish: publish_header,
                forward: forward_header,
            }
        }
    }

    pub struct DerivedHeaders<C: CryptoSuite> {
        pub publish: PublishMessageHeader<C>,
        pub forward: ForwardMessageHeader<C>,
    }
}
