mod acceptor;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::mem::size_of;
use std::sync::Arc;

use secp256k1::{PublicKey, Signature};

use never::Never;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinError;

use crate::delivery::trusted_delivery::message::{
    HelloMsg, MessageDestination, OutgoingMessage, ParseError,
};

pub struct Server {
    rooms: HashMap<[u8; 32], Arc<Room>>,

    number_of_preallocated_messages: usize,
    size_of_preallocated_buffer: usize,
    size_limit: usize,
}

pub struct Room {
    history: RwLock<RoomHistory>,
    history_changed: Notify,
}

impl Room {
    pub fn new(
        number_of_preallocated_messages: usize,
        size_of_preallocated_buffer: usize,
        size_limit: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            history: RwLock::new(RoomHistory {
                headers: Vec::with_capacity(number_of_preallocated_messages),
                messages: Vec::with_capacity(size_of_preallocated_buffer),
                size_limit,
            }),
            history_changed: Notify::new(),
        })
    }

    pub async fn join<I, O>(
        self: Arc<Self>,
        party_public_key: PublicKey,
        input: I,
        mut output: O,
        max_msg_size: usize,
    ) -> (ProcessOutgoingsError, ForwardMessagesError)
    where
        I: AsyncRead + Unpin + Send + 'static,
        O: AsyncWrite + Unpin + Send + 'static,
    {
        let pk = party_public_key.clone();
        let room = self.clone();
        let process_outgoing = tokio::spawn(async move {
            let mut buffer = vec![0u8; max_msg_size];
            join_room_outgoing(pk, room, input, &mut buffer).await
        });
        let forward_messages = tokio::spawn(async move {
            let mut buffer = vec![0u8; max_msg_size];
            join_room_forward_messages(party_public_key, self, &mut output, &mut buffer).await
        });

        let process_outgoing_err = match process_outgoing.await {
            Ok(Ok(never)) => never.into_any(),
            Ok(Err(err)) => err,
            Err(err) => ProcessOutgoingsError::TaskError(err),
        };
        let forward_messages_err = match forward_messages.await {
            Ok(Ok(never)) => never.into_any(),
            Ok(Err(err)) => err,
            Err(err) => ForwardMessagesError::TaskError(err),
        };

        (process_outgoing_err, forward_messages_err)
    }
}

pub struct RoomHistory {
    headers: Vec<MessageHeader>,
    messages: Vec<u8>,

    size_limit: usize,
}

struct MessageHeader {
    offset: usize,
    len: usize,
    sender: PublicKey,
    recipient: MessageDestination,
    signature: Signature,
}

impl MessageHeader {
    pub fn serialized_size(&self) -> usize {
        // sender public key
        33
        // is_broadcast flag
        + 1
        // message length (u16)
        + 2
        // the message
        + self.len
        // signature
        + 64
    }
}

pub async fn join_room_outgoing<I>(
    party_pk: PublicKey,
    room: Arc<Room>,
    mut input: I,
    buffer: &mut [u8],
) -> Result<Never, ProcessOutgoingsError>
where
    I: AsyncRead + Unpin,
{
    loop {
        let sent_message = OutgoingMessage::parse(&party_pk, buffer, &mut input).await?;
        let mut history = room.history.write().await;

        let offset = match history.headers.last() {
            Some(header) => header.offset + header.len,
            None => 0,
        };

        history.headers.push(MessageHeader {
            offset,
            len: sent_message.message.len(),
            sender: party_pk,
            recipient: sent_message.recipient,
            signature: sent_message.signature,
        });

        if history.messages.len() < offset + sent_message.message.len() {
            history
                .messages
                .resize(offset + sent_message.message.len(), 0);
        }

        history.messages[offset..offset + sent_message.message.len()]
            .copy_from_slice(sent_message.message);
        room.history_changed.notify_waiters();

        let size_of_messages = offset + sent_message.message.len();
        let size_of_headers = history.headers.len() * size_of::<MessageHeader>();

        if size_of_messages + size_of_headers > history.size_limit {
            return Err(ProcessOutgoingsError::HistorySizeLimitExceeded);
        }
    }
}

pub async fn join_room_forward_messages<O>(
    party_pk: PublicKey,
    room: Arc<Room>,
    output: &mut O,
    buffer: &mut [u8],
) -> Result<Never, ForwardMessagesError>
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

        if history.headers[next_msg].recipient != MessageDestination::P2P(party_pk)
            && history.headers[next_msg].recipient != MessageDestination::Broadcast
        {
            // Ignore this message
            continue;
        }

        // Message needs to be forwarded to the party
        // 1. Build a message in the buffer
        let header = &history.headers[next_msg];
        if buffer.len() < header.serialized_size() {
            return Err(ForwardMessagesError::MessageTooLarge {
                message_size: header.serialized_size(),
                buffer_size: buffer.len(),
            });
        }

        let buffer = &mut buffer[0..header.serialized_size()];
        // Sender public key
        buffer[0..33].copy_from_slice(&header.sender.serialize());
        // is_broadcast flag
        buffer[33] = match header.recipient {
            MessageDestination::P2P(_) => 0,
            MessageDestination::Broadcast => 1,
        };
        // message length (u16)
        let message_len = u16::try_from(header.len).map_err(|_| {
            ForwardMessagesError::MessageSizeDoestFitToU16 {
                message_size: header.len,
            }
        })?;
        buffer[34..36].copy_from_slice(&message_len.to_be_bytes());
        // message
        buffer[36..36 + header.len]
            .copy_from_slice(&history.messages[header.offset..header.offset + header.len]);
        // signature
        buffer[36 + header.len..36 + header.len + 64]
            .copy_from_slice(&header.signature.serialize_compact());

        // 2. Release history lock and send the message
        drop(history);
        output
            .write_all(&*buffer)
            .await
            .map_err(ForwardMessagesError::SendMessage)?;
    }
}

pub enum ProcessOutgoingsError {
    Parse(ParseError),
    HistorySizeLimitExceeded,
    TaskError(JoinError),
}

pub enum ForwardMessagesError {
    MessageTooLarge {
        message_size: usize,
        buffer_size: usize,
    },
    MessageSizeDoestFitToU16 {
        message_size: usize,
    },
    SendMessage(io::Error),
    TaskError(JoinError),
}

impl From<ParseError> for ProcessOutgoingsError {
    fn from(err: ParseError) -> Self {
        Self::Parse(err)
    }
}
