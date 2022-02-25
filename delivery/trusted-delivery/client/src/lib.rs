use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, iter};

use generic_array::GenericArray;
use typenum::{Unsigned, U32};

use futures::{sink, Sink, Stream};

use delivery_core::round_store::{MessagesStore as _, RoundInput};
use delivery_core::serialization_backend::{Bincode, DeserializationBackend, SerializationBackend};
use delivery_core::{Incoming, Outgoing};
use trusted_delivery_core::crypto::*;
use trusted_delivery_core::generic_array_ext::Sum;
use trusted_delivery_core::RoomId;

use thiserror::Error;

use crate::sorted_list::SizeU16;

pub use self::client::{
    ApiClient, Authenticated, Error as ApiError, JoinedRoom, NotAuthenticated, Subscription,
};
pub use self::sorted_list::SortedList;
pub use reqwest::Client as HttpClient;

mod client;
mod sorted_list;

pub struct Delivery<C: CryptoSuite, S = Bincode, D = Bincode> {
    i: u16,

    api_client: ApiClient<JoinedRoom<C>>,
    subscription: Subscription<C>,
    parties: SizeU16<SortedList<C::VerificationKey>>,

    serializer: S,
    deserializer: D,

    encryption_keys: HashMap<C::VerificationKey, C::EncryptionKey>,
    decryption_keys: HashMap<C::VerificationKey, C::DecryptionKey>,
}

impl<M, C, S, D> delivery_core::Delivery<M> for Delivery<C, S, D>
where
    M: Send + 'static,
    C: CryptoSuite,
    S: SerializationBackend<M> + Send + 'static,
    D: DeserializationBackend<M> + Send + 'static,
{
    type Send = Outgoings<M, S>;
    type Receive = Incomings<M, D>;
    type SendError = SendError<S::Error>;
    type ReceiveError = ReceiveError<D::Error>;

    fn split(self) -> (Self::Receive, Self::Send) {
        let sending = Sending {
            api_client: self.api_client,
            parties: self.parties.clone(),
            encryption_keys: self.encryption_keys,
            serializer: self.serializer,
            serialization_buffer: Vec::with_capacity(1000),
        };
        let sending = sink::unfold(sending, |mut sending, outgoing: Outgoing<M>| async {
            sending.send(outgoing).await?;
            Ok(sending)
        });
        let sending = Outgoings::<M, S>(Box::pin(sending));

        let mut receiving = Receiving {
            subscription: self.subscription,
            parties: self.parties.clone(),
            decryption_keys: self.decryption_keys,
            deserializer: self.deserializer,
        };
        let receiving = Incomings::<M, D>(Box::pin(async_stream::stream! {
            loop {
                match receiving.next().await.transpose() {
                    Some(received) => yield received,
                    None => break,
                }
            }
        }));

        (receiving, sending)
    }
}

struct Sending<C: CryptoSuite, S> {
    api_client: ApiClient<JoinedRoom<C>>,
    parties: SizeU16<SortedList<C::VerificationKey>>,
    encryption_keys: HashMap<C::VerificationKey, C::EncryptionKey>,

    serializer: S,
    serialization_buffer: Vec<u8>,
}

impl<C: CryptoSuite, S> Sending<C, S> {
    pub async fn send<M>(&mut self, outgoing: Outgoing<M>) -> Result<(), SendError<S::Error>>
    where
        S: SerializationBackend<M>,
    {
        // Find out who recipient is
        let recipient_identity = match outgoing.recipient {
            Some(recipient) => {
                let recipient_identity =
                    self.parties
                        .get(recipient)
                        .ok_or(SendReason::UnknownRecipient {
                            recipient,
                            n: self.parties.len(),
                        })?;
                Some(recipient_identity)
            }
            None => None,
        };

        // Serialize message
        self.serialization_buffer.clear();
        self.serializer
            .serialize_into(&outgoing.msg, &mut self.serialization_buffer)
            .map_err(SendReason::Serialize)?;

        // Optionally encrypt message
        if let Some(encryption_key) =
            recipient_identity.and_then(|i| self.encryption_keys.get_mut(i))
        {
            let tag = encryption_key
                .encrypt(&[], &mut self.serialization_buffer)
                .or(Err(SendReason::Encrypt))?;
            self.serialization_buffer.extend_from_slice(&tag);
        }

        // Send message
        self.api_client
            .send(recipient_identity.cloned(), &self.serialization_buffer)
            .await
            .map_err(SendReason::Send)?;
        Ok(())
    }
}

struct Receiving<C: CryptoSuite, D> {
    subscription: Subscription<C>,
    parties: SizeU16<SortedList<C::VerificationKey>>,
    decryption_keys: HashMap<C::VerificationKey, C::DecryptionKey>,

    deserializer: D,
}

impl<C, D> Receiving<C, D>
where
    C: CryptoSuite,
{
    pub async fn next<M>(&mut self) -> Result<Option<Incoming<M>>, ReceiveError<D::Error>>
    where
        D: DeserializationBackend<M>,
    {
        loop {
            // Receive message
            let (header, mut data) = match self
                .subscription
                .next()
                .await
                .map_err(ReceiveReason::Receive)?
            {
                Some(m) => m,
                None => return Ok(None),
            };

            // Identify sender
            let sender = match self.parties.find_index(&header.sender) {
                Some(i) => i,
                None => {
                    // Sender is unknown, silently ignore message
                    continue;
                }
            };

            // Optionally decrypt message
            if let Some(dk) = self
                .decryption_keys
                .get_mut(&header.sender)
                .filter(|_| !header.is_broadcast)
            {
                let tag_size = C::EncryptionTagSize::USIZE;
                if data.len() < tag_size {
                    return Err(ReceiveReason::Decrypt.into());
                }

                let (serialized_msg, tag) = data.split_at_mut(data.len() - tag_size);

                dk.decrypt(&[], serialized_msg, (&*tag).into())
                    .or(Err(ReceiveReason::Decrypt))?;

                data = serialized_msg;
            }

            // Deserialize message
            let msg = self
                .deserializer
                .deserialize(data)
                .map_err(ReceiveReason::Deserialize)?;

            return Ok(Some(Incoming { sender, msg }));
        }
    }
}

impl<C: CryptoSuite> Delivery<C> {
    pub async fn connect(
        api_client: ApiClient<Authenticated<C>>,
        group: Group<C>,
    ) -> Result<Self, ConnectError> {
        // 1. Validate input parameters
        let parties = SizeU16::from_list(group.parties)
            .map_err(|err| ConnectReason::TooManyParties { n: err.0.len() })?;
        let pk = api_client.identity();
        let mut api_client = api_client.join_room(group.id);

        let i = parties
            .find_index(&pk)
            .ok_or(ConnectReason::LocalPartyNotInGroup)?;
        let n = parties.len();

        if n < 2 {
            return Err(ConnectReason::TooFewParties { n: parties.len() }.into());
        }

        // 2. Subscribe for messages
        let mut incomings = api_client
            .subscribe()
            .await
            .map_err(ConnectReason::Subscribe)?;

        // 3. Perform P2P handshake

        // 3.1. Generate ephemeral DH keys
        let (ephemeral_pk, ephemeral_sk): (Vec<_>, Vec<_>) =
            iter::repeat_with(C::KeyExchangeScheme::generate)
                .take(usize::from(parties.len() - 1))
                .unzip();

        // 3.2. Send each key to corresponding party
        for ((i, pk_i), ephemeral) in (0..)
            .zip(parties.iter())
            .filter(|(_i, pk_i)| **pk_i != pk)
            .zip(ephemeral_pk)
        {
            api_client
                .send(Some(pk_i.clone()), &ephemeral.to_bytes())
                .await
                .map_err(|err| HandshakeError::Send {
                    destination: i,
                    err,
                })?;
        }

        // 3.3. Receive ephemeral keys from other parties
        let mut ephemeral_remote = RoundInput::<C::KeyExchangeRemoteShare>::new(i, n);

        while ephemeral_remote.wants_more() {
            let (header, data) = incomings
                .next()
                .await
                .map_err(HandshakeError::Receive)?
                .ok_or(HandshakeError::ReceiveEof)?;
            let sender = match parties.find_index(&header.sender) {
                Some(i) => i,
                None => {
                    // Sender is unknown, ignore message
                    continue;
                }
            };
            let ephemeral_key = C::KeyExchangeRemoteShare::from_bytes(data).or(Err(
                HandshakeError::ReceivedMalformedEphemeralKey { sender },
            ))?;
            ephemeral_remote
                .add_message(Incoming {
                    sender,
                    msg: ephemeral_key,
                })
                .map_err(HandshakeError::ProcessReceivedEphemeralKey)?;
        }

        // 3.4. Derive p2p encryption keys
        let ephemeral_remote = ephemeral_remote
            .output()
            .or(Err(HandshakeError::StoreDidntOutput))?
            .into_vec();

        let mut encryption_keys = HashMap::with_capacity(usize::from(parties.len()));
        let mut decryption_keys = HashMap::with_capacity(usize::from(parties.len()));

        for ((local, remote), remote_identity) in ephemeral_sk
            .into_iter()
            .zip(ephemeral_remote)
            .zip(parties.iter())
        {
            let mut encryption_key = <C::EncryptionScheme as EncryptionScheme>::Key::default();
            let mut decryption_key = <C::EncryptionScheme as EncryptionScheme>::Key::default();

            let encryption_label = KdfLabel::<C>::new(&group.id, &pk, remote_identity);
            let decryption_label = KdfLabel::<C>::new(&group.id, remote_identity, &pk);

            let kdf = C::KeyExchangeScheme::kdf::<C::Kdf>(local, &remote)
                .or(Err(HandshakeError::DeriveKeys))?;
            kdf.expand(encryption_label.as_bytes(), encryption_key.as_mut())
                .or(Err(HandshakeError::DeriveKeys))?;
            kdf.expand(decryption_label.as_bytes(), decryption_key.as_mut())
                .or(Err(HandshakeError::DeriveKeys))?;

            encryption_keys.insert(
                remote_identity.clone(),
                C::EncryptionScheme::encryption_key(&encryption_key),
            );
            decryption_keys.insert(
                remote_identity.clone(),
                C::EncryptionScheme::decryption_key(&decryption_key),
            );
        }

        Ok(Self {
            i,

            api_client,
            subscription: incomings,
            parties,

            serializer: Bincode::default(),
            deserializer: Bincode::default(),

            encryption_keys,
            decryption_keys,
        })
    }

    // Returns index of local party
    pub fn party_index(&self) -> u16 {
        self.i
    }

    // Returns number of parties
    pub fn parties_number(&self) -> u16 {
        self.parties.len()
    }
}

impl<C: CryptoSuite, S, D> Delivery<C, S, D> {
    pub fn set_serialization_backend<B>(self, serializer: B) -> Delivery<C, B, D> {
        Delivery {
            serializer,

            i: self.i,
            api_client: self.api_client,
            subscription: self.subscription,
            parties: self.parties,
            deserializer: self.deserializer,
            encryption_keys: self.encryption_keys,
            decryption_keys: self.decryption_keys,
        }
    }

    pub fn set_deserialization_backend<B>(self, deserializer: B) -> Delivery<C, S, B> {
        Delivery {
            deserializer,

            i: self.i,
            api_client: self.api_client,
            subscription: self.subscription,
            parties: self.parties,
            serializer: self.serializer,
            encryption_keys: self.encryption_keys,
            decryption_keys: self.decryption_keys,
        }
    }
}

struct KdfLabel<C: CryptoSuite> {
    label: GenericArray<u8, KdfLabelSize<C>>,
}

type KdfLabelSize<C> = Sum![
    U32,                                     // Room id
    <C as CryptoSuite>::VerificationKeySize, // Encryptor identity
    <C as CryptoSuite>::VerificationKeySize, // Decryptor identity
];

impl<C: CryptoSuite> KdfLabel<C> {
    pub fn new(
        room: &RoomId,
        encryptor: &C::VerificationKey,
        decryptor: &C::VerificationKey,
    ) -> Self {
        let identity_size = C::VerificationKeySize::USIZE;

        let mut label = GenericArray::<u8, KdfLabelSize<C>>::default();
        label[0..32].copy_from_slice(room);
        label[32..32 + identity_size].copy_from_slice(&encryptor.to_bytes());
        label[32 + identity_size..].copy_from_slice(&decryptor.to_bytes());

        Self { label }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.label
    }
}

/// Group of parties that run MPC protocol
pub struct Group<C: CryptoSuite> {
    /// Unique identifier of that group
    pub id: RoomId,
    /// Sorted list of parties public keys
    ///
    /// Public key of local party must be present in the list.
    pub parties: SortedList<C::VerificationKey>,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ConnectError(#[from] ConnectReason);

#[derive(Debug, Error)]
enum ConnectReason {
    #[error("too few parties in the group: n={n} (required at least 2 parties)")]
    TooFewParties { n: u16 },
    #[error("too many parties in the group: n={n} (limit is {limit}", limit = u16::MAX)]
    TooManyParties { n: usize },
    #[error("local party is not in the list of group parties")]
    LocalPartyNotInGroup,
    #[error("subscribe for new messages in the room")]
    Subscribe(#[source] client::Error),
    #[error("couldn't perform p2p handshake")]
    PeerToPeerHandshake(
        #[source]
        #[from]
        HandshakeError,
    ),
}

#[derive(Debug, Error)]
enum HandshakeError {
    #[error("sending ephemeral DH key to party #{destination}")]
    Send {
        destination: u16,
        #[source]
        err: client::Error,
    },
    #[error("receive ephemeral DH key")]
    Receive(#[source] client::Error),
    #[error("party #{sender} sent invalid ephemeral DH key")]
    ReceivedMalformedEphemeralKey { sender: u16 },
    #[error("process received ephemeral DH key")]
    ProcessReceivedEphemeralKey(#[source] delivery_core::round_store::Error),
    #[error("unexpected eof in the middle of p2p handshake")]
    ReceiveEof,
    #[error("bug: RoundInput didn't output though store.wants_more() == false")]
    StoreDidntOutput,
    #[error("p2p key derivation failed")]
    DeriveKeys,
}

impl From<HandshakeError> for ConnectError {
    fn from(err: HandshakeError) -> Self {
        ConnectError(ConnectReason::PeerToPeerHandshake(err))
    }
}

pub struct Incomings<M, D: DeserializationBackend<M>>(
    Pin<Box<dyn Stream<Item = Result<Incoming<M>, ReceiveError<D::Error>>> + Send>>,
);
pub struct Outgoings<M, S: SerializationBackend<M>>(
    Pin<Box<dyn Sink<Outgoing<M>, Error = SendError<S::Error>> + Send>>,
);

impl<M, D: DeserializationBackend<M>> Stream for Incomings<M, D> {
    type Item = Result<Incoming<M>, ReceiveError<D::Error>>;

    #[inline(always)]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

impl<M, S: SerializationBackend<M>> Sink<Outgoing<M>> for Outgoings<M, S> {
    type Error = SendError<S::Error>;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.as_mut().poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        self.0.as_mut().start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.as_mut().poll_close(cx)
    }
}

#[derive(Debug)]
pub struct ReceiveError<D = bincode::Error>(ReceiveReason<D>);

impl<S: fmt::Display> fmt::Display for ReceiveError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<D: std::error::Error + 'static> std::error::Error for ReceiveError<D> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl<D> From<ReceiveReason<D>> for ReceiveError<D> {
    fn from(err: ReceiveReason<D>) -> Self {
        ReceiveError(err)
    }
}

#[derive(Debug, Error)]
enum ReceiveReason<D> {
    #[error("message deserialization error")]
    Deserialize(#[source] D),
    #[error("receive message")]
    Receive(#[source] client::Error),
    #[error("cannot decrypt received message")]
    Decrypt,
}

#[derive(Debug)]
pub struct SendError<S = bincode::Error>(SendReason<S>);

impl<S: fmt::Display> fmt::Display for SendError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<S: std::error::Error + 'static> std::error::Error for SendError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl<S> From<SendReason<S>> for SendError<S> {
    fn from(err: SendReason<S>) -> Self {
        SendError(err)
    }
}

#[derive(Debug, Error)]
enum SendReason<S> {
    #[error("recipient #{recipient} is unknown (there are only {n} parties)")]
    UnknownRecipient { recipient: u16, n: u16 },
    #[error("serialize message error")]
    Serialize(#[source] S),
    #[error("couldn't encrypt message")]
    Encrypt,
    #[error("send message to server")]
    Send(client::Error),
}
