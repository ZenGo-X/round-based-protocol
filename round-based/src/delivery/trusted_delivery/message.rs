use std::convert::TryFrom;

use tokio::io::{self, AsyncRead, AsyncReadExt};

use secp256k1::key::PublicKey;
use secp256k1::{Signature, SECP256K1};
use sha2::{Digest, Sha256};

pub struct HelloMsg {
    pub public_key: PublicKey,
    pub room_id: [u8; 32],
    pub signature: Signature,
}

impl HelloMsg {
    pub async fn parse<I>(mut input: I) -> Result<Self, ParseError>
    where
        I: AsyncRead + Unpin,
    {
        let mut public_key = [0u8; 32];
        input.read_exact(&mut public_key).await?;
        let public_key =
            PublicKey::from_slice(&public_key).map_err(ParseError::InvalidSenderPublicKey)?;

        let mut room_id = [0u8; 32];
        input.read_exact(&mut room_id).await?;

        let mut signature = [0u8; 64];
        input.read_exact(&mut signature).await?;
        let signature =
            Signature::from_compact(&signature).map_err(ParseError::InvalidSignature)?;

        let message_hash = Sha256::digest(&room_id);
        let message_hash = secp256k1::Message::from_slice(&message_hash)
            .map_err(internal::InternalError::WrongHashSize)?;

        SECP256K1
            .verify(&message_hash, &signature, &public_key)
            .map_err(ParseError::SignatureMismatched)?;

        Ok(Self {
            public_key,
            room_id,
            signature,
        })
    }
}

pub struct IncomingMessage<'b> {
    pub sender: PublicKey,
    pub is_broadcast: bool,
    pub message: &'b [u8],
    pub signature: Signature,
}

impl<'b> IncomingMessage<'b> {
    pub async fn parse<I>(
        public_key: &PublicKey,
        buffer: &'b mut [u8],
        mut input: I,
    ) -> Result<IncomingMessage<'b>, ParseError>
    where
        I: AsyncRead + Unpin,
    {
        let mut sender = [0u8; 33];
        input.read_exact(&mut sender).await?;
        let sender = PublicKey::from_slice(&sender).map_err(ParseError::InvalidSenderPublicKey)?;

        let mut is_broadcast = [0u8; 1];
        input.read_exact(&mut is_broadcast).await?;
        let is_broadcast = match is_broadcast[0] {
            0 => false,
            1 => true,
            x => return Err(ParseError::InvalidIsBroadcastFlag(x)),
        };

        let mut message_len = [0u8; 2];
        input.read_exact(&mut message_len).await?;
        let message_len = u16::from_be_bytes(message_len);

        if buffer.len() < usize::from(message_len) {
            return Err(ParseError::MessageTooLarge {
                message_len,
                limit: buffer.len(),
            });
        }

        let message = &mut buffer[0..usize::from(message_len)];
        input.read_exact(message).await?;
        let message = &*message;

        let mut signature = [0u8; 64];
        input.read_exact(&mut signature).await?;
        let signature =
            Signature::from_compact(&signature).map_err(ParseError::InvalidSignature)?;

        let message_hash = Sha256::new()
            .chain(if is_broadcast {
                [0u8; 33]
            } else {
                public_key.serialize()
            })
            .chain(message)
            .finalize();
        let message_hash = secp256k1::Message::from_slice(message_hash.as_ref())
            .map_err(internal::InternalError::WrongHashSize)?;
        SECP256K1
            .verify(&message_hash, &signature, public_key)
            .map_err(ParseError::SignatureMismatched)?;

        Ok(IncomingMessage {
            sender,
            is_broadcast,
            message,
            signature,
        })
    }
}

pub struct OutgoingMessage<'b> {
    pub recipient: MessageDestination,
    pub message: &'b [u8],
    pub signature: Signature,
}

impl<'b> OutgoingMessage<'b> {
    /// Input must be buffered, otherwise performance sucks!
    pub async fn parse<I>(
        public_key: &PublicKey,
        buffer: &'b mut [u8],
        mut input: I,
    ) -> Result<OutgoingMessage<'b>, ParseError>
    where
        I: AsyncRead + Unpin,
    {
        let mut message_type = [0u8; 1];
        input.read_exact(&mut message_type).await?;

        let recipient = match message_type[0] {
            0 => {
                // Broadcast msg
                MessageDestination::Broadcast
            }
            1 => {
                // P2P msg
                let mut recipient_pk = [0u8; 33];
                input.read_exact(&mut recipient_pk).await?;
                MessageDestination::P2P(
                    PublicKey::from_slice(&recipient_pk)
                        .map_err(ParseError::InvalidRecipientPublicKey)?,
                )
            }
            ty => return Err(ParseError::UnknownMessageType(ty)),
        };

        let mut message_len = [0u8; 2];
        input.read_exact(&mut message_len).await?;
        let message_len = u16::from_be_bytes(message_len);

        if buffer.len() < usize::from(message_len) {
            return Err(ParseError::MessageTooLarge {
                message_len,
                limit: buffer.len(),
            });
        }

        let message = &mut buffer[0..usize::from(message_len)];
        input.read_exact(message).await?;
        let message = &*message;

        let mut signature = [0u8; 64];
        input.read_exact(&mut signature).await?;
        let signature =
            Signature::from_compact(&signature).map_err(ParseError::InvalidSignature)?;

        let message_hash = Sha256::new()
            .chain(match &recipient {
                MessageDestination::P2P(pk) => pk.serialize(),
                MessageDestination::Broadcast => [0u8; 33],
            })
            .chain(message)
            .finalize();
        let message_hash = secp256k1::Message::from_slice(message_hash.as_ref())
            .map_err(internal::InternalError::WrongHashSize)?;
        SECP256K1
            .verify(&message_hash, &signature, public_key)
            .map_err(ParseError::SignatureMismatched)?;

        Ok(OutgoingMessage {
            recipient,
            message,
            signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MessageDestination {
    Broadcast,
    P2P(PublicKey),
}

pub enum ParseError {
    UnknownMessageType(u8),
    InvalidIsBroadcastFlag(u8),
    InvalidSenderPublicKey(secp256k1::Error),
    InvalidRecipientPublicKey(secp256k1::Error),
    InvalidSignature(secp256k1::Error),
    MessageTooLarge { message_len: u16, limit: usize },
    SignatureMismatched(secp256k1::Error),
    Io(io::Error),
    Internal(internal::InternalError),
}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<internal::InternalError> for ParseError {
    fn from(err: internal::InternalError) -> Self {
        Self::Internal(err)
    }
}

mod internal {
    pub enum InternalError {
        WrongHashSize(secp256k1::Error),
    }
}
