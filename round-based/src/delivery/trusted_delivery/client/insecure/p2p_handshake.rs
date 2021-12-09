use std::collections::HashMap;
use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use phantom_type::PhantomType;
use tokio::io::{self, AsyncRead, AsyncWrite};

use secp256k1::PublicKey;

use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::client::insecure::crypto::{
    EncryptionScheme, NoDecryption, NoEncryption,
};
use crate::delivery::trusted_delivery::client::insecure::incoming::{
    Incomings, ReceiveAndParse, ReceiveError,
};
use crate::delivery::trusted_delivery::client::insecure::outgoing::{MessageSize, Outgoings};
use crate::delivery::OutgoingChannel;
use crate::rounds::store::{RoundInput, RoundInputError};
use crate::rounds::MessagesStore;
use crate::{Incoming, Outgoing, OutgoingDelivery};

mod ephemeral;

use self::ephemeral::{EphemeralKey, EphemeralPublicKey};

pub struct Handshake<E, P, I, O> {
    i: u16,
    n: u16,
    local_party_identity: PublicKey,
    parties: P,
    incomings: ReceiveAndParse<EphemeralPublicKey, Incomings<P, NoDecryption, I>>,
    outgoings: Outgoings<P, NoEncryption, O>,
    ephemeral_keys: Vec<EphemeralKey>,
    received_keys: Option<RoundInput<EphemeralPublicKey>>,
    state: State,
    _encryption_scheme: PhantomType<E>,
}

enum State {
    SendKeys {
        i: RecipientIndex,
        size: MessageSize,
    },
    Flush,
    RecvKeys,
    Gone,
}

impl<E, P, I, O> Handshake<E, P, I, O>
where
    E: EncryptionScheme,
    P: IdentityResolver + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    pub fn new(
        identity: PublicKey,
        parties: P,
        incomings: Incomings<P, NoDecryption, I>,
        outgoings: Outgoings<P, NoEncryption, O>,
    ) -> Result<Self, ConstructError> {
        let n = parties.number_of_parties();
        if n < 2 {
            return Err(ConstructError::NumberOfPartiesTooSmall { n });
        }
        let local_party_index = parties
            .lookup_party_index(&identity)
            .ok_or(ConstructError::PartyPkNotInTheList)?;
        let ephemeral_keys = iter::repeat_with(EphemeralKey::generate)
            .take(usize::from(n))
            .collect::<Vec<_>>();
        let mut handshake = Self {
            i: local_party_index,
            n,
            local_party_identity: identity,
            parties,
            incomings: ReceiveAndParse::new(incomings),
            outgoings,
            ephemeral_keys,
            received_keys: Some(RoundInput::new(local_party_index, n)),
            state: State::Gone,
            _encryption_scheme: PhantomType::new(),
        };
        let recipient_index = RecipientIndex::new(local_party_index, n);
        let state = State::SendKeys {
            size: Pin::new(&handshake.outgoings)
                .message_size(handshake.ith_handshake_message(&recipient_index).as_ref())
                .map_err(ConstructError::EstimateMessageSize)?,
            i: recipient_index,
        };
        handshake.state = state;
        Ok(handshake)
    }

    /// We send (n-1) messages to all parties except ourselves. `i` is in range `[0; n-1)`
    fn ith_handshake_message(&self, i: &RecipientIndex) -> Outgoing<EphemeralPublicKey> {
        Outgoing {
            recipient: Some(i.recipient_index()),
            msg: self.ephemeral_keys[usize::from(i.sequent_number())].public_key(),
        }
    }
}

impl<E, P, I, O> Future for Handshake<E, P, I, O>
where
    E: EncryptionScheme,
    P: IdentityResolver + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    type Output = Result<DerivedKeys<E>, HandshakeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            this.state = match this.state {
                State::SendKeys { i, size } => {
                    ready!(Pin::new(&mut this.outgoings).poll_ready(cx, &size)).map_err(|err| {
                        HandshakeError::ReserveSpaceInOutgoingsBuffer {
                            recipient: i.recipient_index(),
                            err,
                        }
                    })?;
                    let ith_message = this.ith_handshake_message(&i);
                    Pin::new(&mut this.outgoings)
                        .start_send(ith_message.as_ref())
                        .map_err(|err| HandshakeError::StartSending {
                            recipient: i.recipient_index(),
                            err,
                        })?;

                    if let Some(i) = i.increment() {
                        let next_msg = this.ith_handshake_message(&i);
                        let size = Pin::new(&mut this.outgoings)
                            .as_ref()
                            .message_size(next_msg.as_ref())
                            .map_err(HandshakeError::EstimateMessageSize)?;
                        State::SendKeys { i, size }
                    } else {
                        State::Flush
                    }
                }
                State::Flush => {
                    ready!(Pin::new(&mut this.outgoings).poll_flush(cx))
                        .map_err(HandshakeError::FlushOutgoings)?;
                    State::RecvKeys
                }
                State::RecvKeys => {
                    let received_keys = this
                        .received_keys
                        .as_mut()
                        .ok_or(OccurredBug::ReceivedMessagesGone)?;
                    let received_message: Incoming<EphemeralPublicKey> =
                        ready!(Pin::new(&mut this.incomings).poll_next(cx))
                            .ok_or(HandshakeError::RecvEof)?
                            .map_err(HandshakeError::Recv)?;

                    received_keys.add_message(received_message).map_err(|err| {
                        HandshakeError::PartySabotagedHandshake {
                            party: received_message.sender,
                            err,
                        }
                    })?;

                    if !received_keys.wants_more() {
                        let received_ephemeral_keys = this
                            .received_keys
                            .take()
                            .ok_or(OccurredBug::ReceivedMessagesGone)?
                            .finish()
                            .map_err(OccurredBug::CannotExtractReceivedMessages)?;
                        let derived_keys = DerivedKeys::<E>::derive(
                            &this.local_party_identity,
                            &this.parties,
                            &this.ephemeral_keys,
                            &received_ephemeral_keys.into_vec(),
                        )
                        .or(Err(HandshakeError::Kdf))?;

                        this.state = State::Gone;
                        return Poll::Ready(Ok(derived_keys));
                    }

                    State::RecvKeys
                }
                State::Gone => return Poll::Ready(Err(HandshakeError::PollAfterComplete)),
            };
        }
    }
}

/// Iterates over all recipients in `[0; n-1] \ {local_party_ind}`
#[derive(Debug, Copy, Clone)]
struct RecipientIndex {
    counter: u16,
    i: u16,
    n: u16,
}

impl RecipientIndex {
    pub fn new(i: u16, n: u16) -> Self {
        debug_assert!(n > 1);
        debug_assert!(i < n);
        Self { counter: 0, i, n }
    }

    pub fn increment(mut self) -> Option<Self> {
        self.counter += 1;
        if self.counter < self.n - 1 {
            Some(self)
        } else {
            None
        }
    }

    pub fn sequent_number(&self) -> u16 {
        self.counter
    }

    pub fn recipient_index(&self) -> u16 {
        if self.counter < self.i {
            self.counter
        } else {
            self.counter + 1
        }
    }
}

pub struct DerivedKeys<E: EncryptionScheme> {
    pub encryption_keys: HashMap<PublicKey, E::EncryptionKey>,
    pub decryption_keys: HashMap<PublicKey, E::DecryptionKey>,
}

impl<E: EncryptionScheme> DerivedKeys<E> {
    fn derive<P>(
        local_party_identity: &PublicKey,
        parties: &P,
        ephemeral_keys: &[EphemeralKey],
        received_ephemeral_keys: &[EphemeralPublicKey],
    ) -> Result<Self, KdfError>
    where
        P: IdentityResolver,
    {
        let mut encryption_keys = HashMap::new();
        let mut decryption_keys = HashMap::new();

        for ((remote_party_identity, ephemeral_key), party_ephemeral) in parties
            .identities()
            .zip(ephemeral_keys)
            .zip(received_ephemeral_keys)
        {
            let encryption_key_label = KdfLabel::new(local_party_identity, &remote_party_identity);
            let decryption_key_label = KdfLabel::new(&remote_party_identity, local_party_identity);

            let mut encryption_key = E::Key::default();
            let mut decryption_key = E::Key::default();

            let kdf = ephemeral_key.hkdf(party_ephemeral);
            kdf.expand(encryption_key_label.as_bytes(), encryption_key.as_mut())
                .or(Err(KdfError))?;
            kdf.expand(decryption_key_label.as_bytes(), decryption_key.as_mut())
                .or(Err(KdfError))?;

            encryption_keys.insert(remote_party_identity, E::encryption_key(&encryption_key));
            decryption_keys.insert(remote_party_identity, E::decryption_key(&decryption_key));
        }

        Ok(Self {
            encryption_keys,
            decryption_keys,
        })
    }
}

struct KdfLabel {
    label: [u8; 33 + 33],
}

impl KdfLabel {
    /// Takes public identity of party who encrypts messages, public identity of party who decrypts
    /// them and derives KDF label
    pub fn new(encryptor: &PublicKey, decryptor: &PublicKey) -> Self {
        let mut label = [0u8; 33 + 33];
        label[0..33].copy_from_slice(&encryptor.serialize());
        label[33..].copy_from_slice(&decryptor.serialize());
        Self { label }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.label
    }
}

#[derive(Debug, Error)]
pub enum ConstructError {
    #[error("local party public key is not in the list of parties public keys")]
    PartyPkNotInTheList,
    #[error("number of participants is too small: n={n}")]
    NumberOfPartiesTooSmall { n: u16 },
    #[error("party index out of bounds: i={i}, n={n}")]
    IncorrectPartyIndex { i: u16, n: u16 },
    #[error("cannot estimate size of handshake message")]
    EstimateMessageSize(#[source] io::Error),
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("reserve space for outgoing handshake message dedicated to party {recipient:?}")]
    ReserveSpaceInOutgoingsBuffer {
        recipient: u16,
        #[source]
        err: io::Error,
    },
    #[error("add handshake message dedicated to party {recipient:?} into sending queue")]
    StartSending {
        recipient: u16,
        #[source]
        err: io::Error,
    },
    #[error("flush outgoing handshake messages")]
    FlushOutgoings(#[source] io::Error),
    #[error("cannot estimate size of handshake message")]
    EstimateMessageSize(#[source] io::Error),
    #[error("receive message")]
    Recv(#[source] ReceiveError),
    #[error("unexpected eof: connection is suddenly closed")]
    RecvEof,
    #[error("party {party} sabotaged handshake")]
    PartySabotagedHandshake {
        party: u16,
        #[source]
        err: RoundInputError,
    },
    #[error("couldn't derive encryption/decryption key")]
    Kdf,
    #[error("future is polled after complete")]
    PollAfterComplete,
    #[error("bug occurred - please open an issue")]
    Bug(Bug),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Bug(OccurredBug);

#[derive(Debug, Error)]
enum OccurredBug {
    #[error("store of received ephemeral keys is unexpectedly gone")]
    ReceivedMessagesGone,
    #[error("store didn't return received messages")]
    CannotExtractReceivedMessages(#[source] RoundInputError),
}

impl From<OccurredBug> for HandshakeError {
    fn from(bug: OccurredBug) -> Self {
        HandshakeError::Bug(Bug(bug))
    }
}

#[derive(Debug, Error)]
#[error("couldn't derive encryption/decryption key")]
pub struct KdfError;
