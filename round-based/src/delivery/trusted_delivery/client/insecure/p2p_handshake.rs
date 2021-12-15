use std::collections::HashMap;
use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::client::insecure::crypto::{
    CryptoSuite, EncryptionScheme, Kdf, KeyExchangeScheme, Serde, Serializable,
};
use crate::delivery::trusted_delivery::generic_array_ext::Sum;
use crate::delivery::OutgoingChannel;
use crate::rounds::store::{RoundInput, RoundInputError};
use crate::rounds::MessagesStore;
use crate::{Incoming, Outgoing, OutgoingDelivery};

mod ephemeral;

pub struct Handshake<C: CryptoSuite, P, I, O: OutgoingChannel> {
    i: u16,
    n: u16,
    local_party_identity: C::VerificationKey,
    parties: P,
    // incomings: ReceiveAndParse<EphemeralPublicKey, Incomings<P, NoDecryption, I>>,
    // outgoings: Outgoings<P, NoEncryption, O>,
    incomings: I,
    outgoings: O,
    ephemeral_keys: Vec<(C::KeyExchangeRemoteShare, C::KeyExchangeLocalShare)>,
    received_keys: Option<RoundInput<Serde<C::KeyExchangeRemoteShare>>>,
    state: State<O::MessageSize>,
}

enum State<S> {
    NotStarted,
    SendKeys { i: RecipientIndex, size: S },
    Flush,
    RecvKeys,
    Gone,
}

impl<C, P, I, O, IErr, OErr> Handshake<C, P, I, O>
where
    C: CryptoSuite,
    P: IdentityResolver<Identity = C::VerificationKey> + Unpin,
    I: Stream<Item = Result<Incoming<Serde<C::KeyExchangeRemoteShare>>, IErr>> + Unpin,
    O: OutgoingDelivery<Serde<C::KeyExchangeRemoteShare>, Error = OErr> + Unpin,
    O::MessageSize: Copy,
{
    pub fn new(
        identity: C::VerificationKey,
        parties: P,
        // incomings: Incomings<P, NoDecryption, I>,
        // outgoings: Outgoings<P, NoEncryption, O>,
        incomings: I,
        outgoings: O,
    ) -> Result<Self, ConstructError> {
        let n = parties.number_of_parties();
        if n < 2 {
            return Err(ConstructError::TooFewParties { n });
        }
        let local_party_index = parties
            .lookup_party_index(&identity)
            .ok_or(ConstructError::LocalPartyIdentityNotInTheList)?;
        let ephemeral_keys = iter::repeat_with(C::KeyExchangeScheme::generate)
            .take(usize::from(n))
            .collect::<Vec<_>>();
        Ok(Self {
            i: local_party_index,
            n,
            local_party_identity: identity,
            parties,
            incomings,
            outgoings,
            ephemeral_keys,
            received_keys: Some(RoundInput::new(local_party_index, n)),
            state: State::NotStarted,
        })
    }

    /// Returns handshake message that needs to be send next
    fn next_handshake_message(
        &self,
        i: &RecipientIndex,
    ) -> Outgoing<Serde<C::KeyExchangeRemoteShare>> {
        Outgoing {
            recipient: Some(i.recipient_index()),
            msg: Serde(
                self.ephemeral_keys[usize::from(i.sequent_number())]
                    .0
                    .clone(),
            ),
        }
    }
}

impl<C, P, I, O, IErr, OErr> Future for Handshake<C, P, I, O>
where
    C: CryptoSuite,
    P: IdentityResolver<Identity = C::VerificationKey> + Unpin,
    I: Stream<Item = Result<Incoming<Serde<C::KeyExchangeRemoteShare>>, IErr>> + Unpin,
    O: OutgoingDelivery<Serde<C::KeyExchangeRemoteShare>, Error = OErr> + Unpin,
    O::MessageSize: Copy,
{
    type Output = Result<DerivedKeys<C>, HandshakeError<IErr, OErr>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            this.state = match this.state {
                State::NotStarted => {
                    let recipient_index = RecipientIndex::initial(this.i, this.n);
                    State::SendKeys {
                        size: Pin::new(&this.outgoings)
                            .message_size(this.next_handshake_message(&recipient_index).as_ref())
                            .map_err(HandshakeError::EstimateMessageSize)?,
                        i: recipient_index,
                    }
                }
                State::SendKeys { i, size } => {
                    ready!(Pin::new(&mut this.outgoings).poll_ready(cx, &size)).map_err(|err| {
                        HandshakeError::ReserveSpaceInOutgoingsBuffer {
                            recipient: i.recipient_index(),
                            err,
                        }
                    })?;
                    let ith_message = this.next_handshake_message(&i);
                    Pin::new(&mut this.outgoings)
                        .start_send(ith_message.as_ref())
                        .map_err(|err| HandshakeError::StartSending {
                            recipient: i.recipient_index(),
                            err,
                        })?;

                    if let Some(i) = i.increment() {
                        let next_msg = this.next_handshake_message(&i);
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
                    let received_message: Incoming<Serde<C::KeyExchangeRemoteShare>> =
                        ready!(Pin::new(&mut this.incomings).poll_next(cx))
                            .ok_or(HandshakeError::RecvEof)?
                            .map_err(HandshakeError::Recv)?;
                    let sender = received_message.sender;

                    received_keys.add_message(received_message).map_err(|err| {
                        HandshakeError::PartySabotagedHandshake { party: sender, err }
                    })?;

                    if !received_keys.wants_more() {
                        let received_ephemeral_keys = this
                            .received_keys
                            .take()
                            .ok_or(OccurredBug::ReceivedMessagesGone)?
                            .finish()
                            .map_err(OccurredBug::CannotExtractReceivedMessages)?;
                        let derived_keys = DerivedKeys::<C>::derive(
                            &this.local_party_identity,
                            &this.parties,
                            this.ephemeral_keys.iter().map(|(_pk, sk)| sk),
                            received_ephemeral_keys
                                .into_vec()
                                .iter()
                                .map(|Serde(remote)| remote),
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
    pub fn initial(i: u16, n: u16) -> Self {
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

pub struct DerivedKeys<C: CryptoSuite> {
    pub encryption_keys: HashMap<C::VerificationKey, C::EncryptionKey>,
    pub decryption_keys: HashMap<C::VerificationKey, C::DecryptionKey>,
}

impl<C: CryptoSuite> DerivedKeys<C> {
    fn derive<'k, P>(
        local_party_identity: &C::VerificationKey,
        parties: &P,
        ephemeral_keys: impl IntoIterator<Item = &'k C::KeyExchangeLocalShare>,
        received_ephemeral_keys: impl IntoIterator<Item = &'k C::KeyExchangeRemoteShare>,
    ) -> Result<Self, KdfError>
    where
        P: IdentityResolver<Identity = C::VerificationKey>,
    {
        let mut encryption_keys = HashMap::new();
        let mut decryption_keys = HashMap::new();

        for ((remote_party_identity, ephemeral_key), party_ephemeral) in parties
            .identities()
            .filter(|pk| pk != local_party_identity)
            .zip(ephemeral_keys)
            .zip(received_ephemeral_keys)
        {
            let encryption_key_label =
                KdfLabel::<C>::new(local_party_identity, &remote_party_identity);
            let decryption_key_label =
                KdfLabel::<C>::new(&remote_party_identity, local_party_identity);

            let mut encryption_key = <C::EncryptionScheme as EncryptionScheme>::Key::default();
            let mut decryption_key = <C::EncryptionScheme as EncryptionScheme>::Key::default();

            let kdf = C::KeyExchangeScheme::kdf::<C::Kdf>(ephemeral_key, party_ephemeral);
            kdf.expand(encryption_key_label.as_bytes(), encryption_key.as_mut())
                .or(Err(KdfError))?;
            kdf.expand(decryption_key_label.as_bytes(), decryption_key.as_mut())
                .or(Err(KdfError))?;

            encryption_keys.insert(
                remote_party_identity.clone(),
                C::EncryptionScheme::encryption_key(&encryption_key),
            );
            decryption_keys.insert(
                remote_party_identity,
                C::EncryptionScheme::decryption_key(&decryption_key),
            );
        }

        Ok(Self {
            encryption_keys,
            decryption_keys,
        })
    }
}

struct KdfLabel<C: CryptoSuite> {
    label: GenericArray<u8, KdfLabelSize<C>>,
}

type KdfLabelSize<C> = Sum![
    <C as CryptoSuite>::VerificationKeySize,
    <C as CryptoSuite>::VerificationKeySize,
];

impl<C: CryptoSuite> KdfLabel<C> {
    /// Takes public identity of party who encrypts messages, public identity of party who decrypts
    /// them and derives KDF label
    pub fn new(encryptor: &C::VerificationKey, decryptor: &C::VerificationKey) -> Self {
        let identity_size = C::VerificationKeySize::to_usize();

        let mut label = GenericArray::<u8, KdfLabelSize<C>>::default();
        label[0..identity_size].copy_from_slice(&encryptor.to_bytes());
        label[identity_size..].copy_from_slice(&decryptor.to_bytes());
        Self { label }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.label
    }
}

#[derive(Debug, Error)]
pub enum ConstructError {
    #[error("local party public key is not in the list of parties public keys")]
    LocalPartyIdentityNotInTheList,
    #[error("number of participants is too small: n={n}")]
    TooFewParties { n: u16 },
    #[error("party index out of bounds: i={i}, n={n}")]
    IncorrectPartyIndex { i: u16, n: u16 },
}

#[derive(Debug, Error)]
pub enum HandshakeError<IErr, OErr> {
    #[error("reserve space for outgoing handshake message dedicated to party {recipient:?}")]
    ReserveSpaceInOutgoingsBuffer {
        recipient: u16,
        #[source]
        err: OErr,
    },
    #[error("add handshake message dedicated to party {recipient:?} into sending queue")]
    StartSending {
        recipient: u16,
        #[source]
        err: OErr,
    },
    #[error("flush outgoing handshake messages")]
    FlushOutgoings(#[source] OErr),
    #[error("cannot estimate size of handshake message")]
    EstimateMessageSize(#[source] OErr),
    #[error("receive message")]
    Recv(#[source] IErr),
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

impl<IErr, OErr> From<OccurredBug> for HandshakeError<IErr, OErr> {
    fn from(bug: OccurredBug) -> Self {
        HandshakeError::Bug(Bug(bug))
    }
}

#[derive(Debug, Error)]
#[error("couldn't derive encryption/decryption key")]
pub struct KdfError;

#[cfg(test)]
mod tests {
    use std::iter;

    use rand::rngs::OsRng;
    use rand::RngCore;

    use crate::delivery::trusted_delivery::client::insecure::crypto::aead::AeadEncryptionScheme;
    use crate::delivery::trusted_delivery::client::insecure::p2p_handshake::ephemeral::EphemeralPublicKey;
    use crate::delivery::trusted_delivery::client::insecure::test_utils::generate_parties_sk;
    use crate::simulation::Simulation;
    use crate::Delivery;

    use super::Handshake;
    use crate::delivery::trusted_delivery::client::insecure::crypto::{
        DecryptionKey, EncryptionKey,
    };

    type EncryptionScheme = AeadEncryptionScheme<aes_gcm::Aes256Gcm>;

    #[tokio::test]
    async fn simulated_two_party_handshake() {
        let (pk, _sk) = generate_parties_sk(2);

        let mut simulation = Simulation::<EphemeralPublicKey>::new();
        let party1 = simulation.connect_new_party();
        let party2 = simulation.connect_new_party();

        let (party1_in, party1_out) = party1.split();
        let (party2_in, party2_out) = party2.split();

        let handshake1 =
            Handshake::<EncryptionScheme, _, _, _>::new(pk[0], pk.clone(), party1_in, party1_out)
                .unwrap();
        let handshake2 =
            Handshake::<EncryptionScheme, _, _, _>::new(pk[1], pk.clone(), party2_in, party2_out)
                .unwrap();

        let (mut keys1, mut keys2) = futures::future::try_join(handshake1, handshake2)
            .await
            .unwrap();

        // Ensure that party1 can encrypt arbitrary message and party2 can decrypt it
        let mut msg1 = [0u8; 100];
        let mut ad1 = [0u8; 20];
        OsRng.fill_bytes(&mut msg1);
        OsRng.fill_bytes(&mut ad1);

        let mut encrypted_msg1 = msg1;
        let tag1 = keys1
            .encryption_keys
            .get_mut(&pk[1])
            .unwrap()
            .encrypt(&ad1, &mut encrypted_msg1)
            .unwrap();

        let mut decrypted_msg1 = encrypted_msg1;
        keys2
            .decryption_keys
            .get_mut(&pk[0])
            .unwrap()
            .decrypt(&ad1, &mut decrypted_msg1, &tag1)
            .unwrap();

        assert_eq!(msg1, decrypted_msg1);

        // Ensure that party2 can encrypt arbitrary message and party2 can decrypt it
        let mut msg2 = [0u8; 100];
        let mut ad2 = [0u8; 20];
        OsRng.fill_bytes(&mut msg2);
        OsRng.fill_bytes(&mut ad2);

        let mut encrypted_msg2 = msg2;
        let tag2 = keys2
            .encryption_keys
            .get_mut(&pk[0])
            .unwrap()
            .encrypt(&ad2, &mut encrypted_msg2)
            .unwrap();

        let mut decrypted_msg2 = encrypted_msg2;
        keys1
            .decryption_keys
            .get_mut(&pk[1])
            .unwrap()
            .decrypt(&ad2, &mut decrypted_msg2, &tag2)
            .unwrap();

        assert_eq!(msg2, decrypted_msg2);
    }

    #[tokio::test]
    async fn simulated_handshake_among_many_parties() {
        for n in 2..=10 {
            simulated_n_parties_handshake(n).await
        }
    }

    async fn simulated_n_parties_handshake(n: u16) {
        let (pk, _sk) = generate_parties_sk(n);

        let mut simulation =
            Simulation::<EphemeralPublicKey>::with_capacity(usize::from(n * (n - 1)));

        let parties = (0..n).zip(iter::repeat_with(|| simulation.connect_new_party()));

        let handshakes = parties.map(|(i, party)| {
            let (party_in, party_out) = party.split();
            Handshake::<EncryptionScheme, _, _, _>::new(
                pk[usize::from(i)],
                pk.clone(),
                party_in,
                party_out,
            )
            .unwrap()
        });

        let mut keys = futures::future::try_join_all(handshakes).await.unwrap();

        // Ensure that party_i can encrypt arbitrary message and party_j can decrypt it (forall i j. i != j)
        for i in 0..n {
            for j in (0..n).filter(|j| i != *j) {
                let mut msg = [0u8; 100];
                let mut ad = [0u8; 20];
                OsRng.fill_bytes(&mut msg);
                OsRng.fill_bytes(&mut ad);

                let mut encrypted_msg = msg;
                let tag = keys[usize::from(i)]
                    .encryption_keys
                    .get_mut(&pk[usize::from(j)])
                    .unwrap()
                    .encrypt(&ad, &mut encrypted_msg)
                    .unwrap();

                let mut decrypted_msg = encrypted_msg;
                keys[usize::from(j)]
                    .decryption_keys
                    .get_mut(&pk[usize::from(i)])
                    .unwrap()
                    .decrypt(&ad, &mut decrypted_msg, &tag)
                    .unwrap();

                assert_eq!(msg, decrypted_msg);
            }
        }
    }
}
