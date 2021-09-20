use std::collections::hash_map::{Entry, HashMap};
use std::mem::size_of;
use std::sync::{Arc, Weak};

use thiserror::Error;

use secp256k1::{PublicKey, Signature};

use futures::StreamExt;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinError;

use crate::delivery::trusted_delivery::messages::{
    DataMsg, FixedSizeMsg, ForwardMsgHeader, PublishMsg, PublishMsgHeader, ReceiveData,
    ReceiveDataError,
};

pub use self::acceptor::*;

mod acceptor;

pub struct Server {
    rooms: HashMap<[u8; 32], Weak<Room>>,

    number_of_preallocated_messages: usize,
    size_of_preallocated_buffer: usize,
    size_limit: usize,
    size_of_preallocated_buffer_per_channel: usize,
    buffer_size_limit_per_channel: usize,
}

impl Server {
    pub fn new() -> Self {
        Self {
            rooms: HashMap::new(),

            number_of_preallocated_messages: 20,
            size_of_preallocated_buffer: 1024,
            size_limit: 100_000,
            size_of_preallocated_buffer_per_channel: 1024,
            buffer_size_limit_per_channel: 10_000,
        }
    }

    pub fn set_number_of_preallocated_messages(&mut self, n: usize) {
        self.number_of_preallocated_messages = n
    }
    pub fn set_size_of_preallocated_buffer(&mut self, size: usize) {
        self.size_of_preallocated_buffer = size
    }
    pub fn set_size_limit(&mut self, limit: usize) {
        self.size_limit = limit
    }
    pub fn set_size_of_preallocated_buffer_per_channel(&mut self, size: usize) {
        self.size_of_preallocated_buffer_per_channel = size
    }
    pub fn set_buffer_size_limit_per_channel(&mut self, limit: usize) {
        self.buffer_size_limit_per_channel = limit
    }

    pub fn get_or_create_room(&mut self, room_id: [u8; 32]) -> Arc<Room> {
        match self.rooms.entry(room_id) {
            Entry::Vacant(entry) => {
                let empty_room = Room::new(
                    self.number_of_preallocated_messages,
                    self.size_of_preallocated_buffer,
                    self.size_limit,
                    self.size_of_preallocated_buffer_per_channel,
                    self.buffer_size_limit_per_channel,
                );
                entry.insert(Arc::downgrade(&empty_room));
                empty_room
            }
            Entry::Occupied(entry) => {
                let room = entry.into_mut();
                if let Some(room) = room.upgrade() {
                    return room;
                }
                let empty_room = Room::new(
                    self.number_of_preallocated_messages,
                    self.size_of_preallocated_buffer,
                    self.size_limit,
                    self.size_of_preallocated_buffer_per_channel,
                    self.buffer_size_limit_per_channel,
                );
                *room = Arc::downgrade(&empty_room);
                empty_room
            }
        }
    }

    pub fn clean_abandoned_rooms(&mut self) {
        self.rooms.retain(|_room_id, room| room.strong_count() > 0)
    }
}

pub struct Room {
    history: RwLock<RoomHistory>,
    history_changed: Notify,

    initial_capacity_per_channel: usize,
    max_buffer_size_per_channel: usize,
}

impl Room {
    pub fn new(
        number_of_preallocated_messages: usize,
        size_of_preallocated_buffer: usize,
        size_limit: usize,
        initial_capacity_per_channel: usize,
        max_buffer_size_per_channel: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            history: RwLock::new(RoomHistory {
                headers: Vec::with_capacity(number_of_preallocated_messages),
                concated_messages: Vec::with_capacity(size_of_preallocated_buffer),
                size_limit,
            }),
            history_changed: Notify::new(),

            initial_capacity_per_channel,
            max_buffer_size_per_channel,
        })
    }

    pub async fn join<IO>(self: Arc<Self>, stream: Stream<IO>) -> Result<(), ServePartyError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let client_identity = stream.client_identity();
        let initial_capacity_per_channel = self.initial_capacity_per_channel;
        let max_buffer_size_per_channel = self.max_buffer_size_per_channel;
        let (input, mut output) = io::split(stream.into_inner());

        let room = self.clone();
        let mut publish_messages = tokio::spawn(async move {
            let mut receive = ReceiveData::with_capacity(
                input,
                PublishMsg::new(client_identity),
                initial_capacity_per_channel,
            );
            receive.set_data_limit(max_buffer_size_per_channel);
            process_publishing_messages(client_identity, room, receive).await
        });
        let mut forward_messages = tokio::spawn(async move {
            let buffer = vec![0u8; initial_capacity_per_channel];
            forward_messages(
                client_identity,
                self,
                &mut output,
                buffer,
                max_buffer_size_per_channel,
            )
            .await
        });

        tokio::select! {
            result = &mut publish_messages => {
                forward_messages.abort();
                result
                    .map_err(PublishMessagesError::TaskError)
                    .and_then(|x| x)
                    .map_err(|e| ServePartyError(FirstOccurredError::Input(e)))
            },
            result = &mut forward_messages => {
                publish_messages.abort();
                result
                    .map_err(ForwardMessagesError::TaskError)
                    .and_then(|x| x)
                    .map_err(|e| ServePartyError(FirstOccurredError::Output(e)))
            },
        }
    }
}

struct RoomHistory {
    headers: Vec<MessageHeader>,
    concated_messages: Vec<u8>,

    size_limit: usize,
}

struct MessageHeader {
    offset: usize,
    len: u16,
    sender: PublicKey,
    recipient: Option<PublicKey>,
    signature: Signature,
}

impl MessageHeader {
    pub fn serialized_size(&self) -> usize {
        ForwardMsgHeader::SIZE + usize::from(self.len)
    }
}

async fn process_publishing_messages<I>(
    party_pk: PublicKey,
    room: Arc<Room>,
    mut input: ReceiveData<PublishMsg, I>,
) -> Result<(), PublishMessagesError>
where
    I: AsyncRead + Unpin,
{
    while let Some(()) = input.next().await.transpose()? {
        let publishing_message = input.received().ok_or(Bug::ReceivedReturnedNone)?;
        let mut history = room.history.write().await;

        let offset = match history.headers.last() {
            Some(header) => header.offset + usize::from(header.len),
            None => 0,
        };

        history.headers.push(MessageHeader {
            offset,
            len: publishing_message.0.message_body_len,
            sender: party_pk,
            recipient: publishing_message.0.recipient,
            signature: publishing_message.0.signature,
        });

        if history.concated_messages.len() < offset + publishing_message.1.len() {
            history
                .concated_messages
                .resize(offset + publishing_message.1.len(), 0);
        }

        history.concated_messages[offset..offset + publishing_message.1.len()]
            .copy_from_slice(publishing_message.1);
        room.history_changed.notify_waiters();

        let size_of_concated_messages = offset + publishing_message.1.len();
        let size_of_headers = history.headers.len() * size_of::<MessageHeader>();

        if size_of_concated_messages + size_of_headers > history.size_limit {
            return Err(PublishMessagesError::HistorySizeLimitExceeded);
        }
    }

    Ok(())
}

async fn forward_messages<O>(
    party_pk: PublicKey,
    room: Arc<Room>,
    output: &mut O,
    mut buffer: Vec<u8>,
    buffer_size_limit: usize,
) -> Result<(), ForwardMessagesError>
where
    O: AsyncWrite + Unpin,
{
    let mut next_msg = 0;
    loop {
        let mut history = room.history.read().await;
        while history.headers.len() == next_msg {
            let history_changed = room.history_changed.notified();
            drop(history);
            history_changed.await;
            history = room.history.read().await;
        }

        if history.headers[next_msg].recipient != Some(party_pk)
            && history.headers[next_msg].recipient != None
        {
            // Ignore this message
            continue;
        }

        // Message needs to be forwarded to the party
        // 1. Build a message in the buffer
        let header = &history.headers[next_msg];
        if buffer_size_limit < header.serialized_size() {
            return Err(ForwardMessagesError::MessageTooLarge {
                message_size: header.serialized_size(),
                buffer_size: buffer_size_limit,
            });
        }
        if buffer.len() < header.serialized_size() {
            buffer.resize(header.serialized_size(), 0);
        }

        let buffer = &mut buffer[0..header.serialized_size()];
        // Header
        let forward_header = ForwardMsgHeader {
            sender: header.sender,
            is_broadcast: header.recipient.is_none(),
            signature: header.signature,
            data_len: header.len,
        }
        .to_bytes();
        buffer[0..ForwardMsgHeader::SIZE].copy_from_slice(&forward_header);
        // Data
        buffer[ForwardMsgHeader::SIZE..].copy_from_slice(
            &history.concated_messages[header.offset..header.offset + usize::from(header.len)],
        );
        let mut buffer = &*buffer;

        // 2. Release history lock and send the message
        drop(history);
        while !buffer.is_empty() {
            let bytes_sent = output
                .write_buf(&mut buffer)
                .await
                .map_err(ForwardMessagesError::SendMessage)?;
            if bytes_sent == 0 {
                // Connection closed
                return Ok(());
            }
        }

        next_msg += 1;
    }
}

#[derive(Debug, Error)]
enum PublishMessagesError {
    #[error("receive publishing message")]
    Receive(
        #[source]
        #[from]
        ReceiveDataError<
            <PublishMsgHeader as FixedSizeMsg>::ParseError,
            <PublishMsg as DataMsg>::ValidateError,
        >,
    ),
    #[error("history size limit exceeded")]
    HistorySizeLimitExceeded,
    #[error("task unexpectedly terminated")]
    TaskError(
        #[source]
        #[from]
        JoinError,
    ),
    #[error("bug")]
    Bug(
        #[source]
        #[from]
        Bug,
    ),
}

#[derive(Debug, Error)]
enum Bug {
    #[error(".received() returned None though we just received a valid message")]
    ReceivedReturnedNone,
}

#[derive(Error, Debug)]
enum ForwardMessagesError {
    #[error(
        "message is too large to forward to the party: size={message_size} limit={buffer_size}"
    )]
    MessageTooLarge {
        message_size: usize,
        buffer_size: usize,
    },
    #[error("i/o error")]
    SendMessage(#[source] io::Error),
    #[error("green thread unexpectedly terminated")]
    TaskError(#[source] JoinError),
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct ServePartyError(#[from] FirstOccurredError);

#[derive(Error, Debug)]
enum FirstOccurredError {
    #[error("process message published by the party")]
    Input(#[source] PublishMessagesError),
    #[error("forward published message to the party")]
    Output(#[source] ForwardMessagesError),
}
