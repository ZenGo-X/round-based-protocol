use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Stream};
use tokio::io::{self, AsyncRead, AsyncWrite};

use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use serde_bytes::Bytes;

use thiserror::Error;

use crate::delivery::trusted_delivery::client::identity_resolver::IdentityResolver;
use crate::delivery::trusted_delivery::client::insecure::crypto::{NoDecryption, NoEncryption};
use crate::delivery::trusted_delivery::client::insecure::incoming::{
    Incomings, ReceiveAndParse, ReceiveError,
};
use crate::delivery::trusted_delivery::client::insecure::outgoing::{MessageSize, Outgoings};
use crate::delivery::OutgoingChannel;
use crate::rounds::store::{RoundInput, RoundInputError};
use crate::rounds::MessagesStore;
use crate::{Incoming, Outgoing};

mod ephemeral;

use self::ephemeral::EphemeralKey;

pub struct Handshake<P, I, O> {
    i: u16,
    n: u16,
    parties: P,
    incomings: ReceiveAndParse<PublicKey, Incomings<P, NoDecryption, I>>,
    outgoings: Outgoings<P, NoEncryption, O>,
    ephemeral_keys: Vec<EphemeralKey>,
    received_keys: RoundInput<PublicKey>,
    state: State,
}

enum State {
    SendKeys { i: u16, size: MessageSize },
    Flush,
    RecvKeys,
    Gone,
}

impl<P, I, O> Handshake<P, I, O>
where
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
            parties,
            incomings: ReceiveAndParse::new(incomings),
            outgoings,
            ephemeral_keys,
            state: State::Gone,
            received_keys: RoundInput::new(local_party_index, n),
        };
        let state = State::SendKeys {
            i: 0,
            size: handshake
                .outgoings
                .message_size(handshake.ith_handshake_message(0).as_ref())
                .map_err(ConstructError::EstimateMessageSize)?,
        };
        handshake.state = state;
        Ok(handshake)
    }

    /// We send (n-1) messages to all parties except ourselves. `i` is in range `[0; n-1)`
    fn ith_handshake_message(&self, i: u16) -> Outgoing<PublicKey> {
        debug_assert!(i < self.n - 1);
        let recipient = if i < self.i { i } else { i + 1 };
        debug_assert!(recipient < self.n);
        Outgoing {
            recipient: Some(recipient),
            msg: self.ephemeral_keys[usize::from(i)].public_share(),
        }
    }
}

impl<P, I, O> Future for Handshake<P, I, O>
where
    P: IdentityResolver + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    type Output = Result<(), HandshakeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            this.state = match this.state {
                State::SendKeys { i, size } => {
                    let ith_message = this.ith_handshake_message(i);
                    ready!(this.outgoings.poll_ready(cx, size)).map_err(|err| {
                        HandshakeError::ReserveSpaceInOutgoingsBuffer {
                            recipient: ith_message.recipient,
                            err,
                        }
                    })?;
                    this.outgoings
                        .start_send(ith_message.as_ref())
                        .map_err(|err| HandshakeError::StartSending {
                            recipient: ith_message.recipient,
                            err,
                        })?;

                    if i + 1 == this.n - 1 {
                        State::Flush
                    } else {
                        let next_msg = this.ith_handshake_message(i + 1);
                        let size = this
                            .outgoings
                            .message_size(next_msg.as_ref())
                            .map_err(HandshakeError::EstimateMessageSize)?;
                        State::SendKeys { i: i + 1, size }
                    }
                }
                State::Flush => {
                    ready!(Pin::new(&mut this.outgoings).poll_flush(cx))
                        .map_err(HandshakeError::FlushOutgoings)?;
                    State::RecvKeys
                }
                State::RecvKeys => {
                    let received_message: Incoming<PublicKey> =
                        ready!(Pin::new(&mut this.incomings).poll_next(cx))
                            .ok_or(HandshakeError::RecvEof)?
                            .map_err(HandshakeError::Recv)?;

                    this.received_keys
                        .add_message(received_message)
                        .map_err(|err| HandshakeError::PartySabotagedHandshake {
                            party: received_message.sender,
                            err,
                        })?;

                    todo!()
                }
                State::Gone => return Poll::Ready(Err(HandshakeError::PollAfterComplete)),
            };
        }
        todo!()
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
        recipient: Option<u16>,
        #[source]
        err: io::Error,
    },
    #[error("add handshake message dedicated to party {recipient:?} into sending queue")]
    StartSending {
        recipient: Option<u16>,
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
    #[error("future is polled after complete")]
    PollAfterComplete,
}
