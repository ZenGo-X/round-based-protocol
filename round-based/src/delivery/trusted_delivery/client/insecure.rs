use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use thiserror::Error;

use futures::ready;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_rustls::{client::TlsStream, Connect as TlsConnect, TlsConnector};

use secp256k1::{Message, PublicKey, SecretKey, Signature, SECP256K1};
use sha2::{Digest, Sha256};

use crate::delivery::trusted_delivery::message::{HelloMsg, HELLO_MSG_LEN};
use crate::delivery::utils::tls::ClientTlsConfig;
use crate::{DeliverOutgoing, Outgoing};

use super::identity_resolver::IdentityResolver;
use crate::delivery::OutgoingChannel;

type TlsHandshake<IO> =
    crate::delivery::trusted_delivery::tls_handshake::TlsHandshake<TlsConnect<IO>, TlsStream<IO>>;

pub struct Connector {
    tls_connector: TlsConnector,
    identity_key: SecretKey,
    identity: PublicKey,
}

pub struct Connect<P, IO> {
    handshake: TlsHandshake<IO>,
    identity_key: SecretKey,
    parties: P,
    hello_msg: [u8; HELLO_MSG_LEN],
    sent_bytes: usize,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct MalformedListOfParties(#[from] Reason);

#[derive(Debug, Error)]
pub enum Reason {
    #[error("list of parties doesn't include identity of local party")]
    DoesntIncludeIdentityOfLocalParty,
    #[error("list of parties consist of {n} identity, at least 2 are required")]
    TooFewParties { n: u16 },
}

impl Connector {
    pub fn new(tls_config: &ClientTlsConfig, identity_key: SecretKey) -> Self {
        Self::with_connector(
            TlsConnector::from(tls_config.to_rustls_config()),
            identity_key,
        )
    }

    pub fn with_connector(tls_connector: TlsConnector, identity_key: SecretKey) -> Self {
        Self {
            tls_connector,
            identity: PublicKey::from_secret_key(&SECP256K1, &identity_key),
            identity_key,
        }
    }

    pub fn connect<P, IO>(
        &self,
        room_id: [u8; 32],
        parties: P,
        domain: webpki::DNSNameRef,
        stream: IO,
    ) -> Result<Connect<P, IO>, MalformedListOfParties>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        P: IdentityResolver,
    {
        if parties.lookup_party_index(&self.identity).is_none() {
            return Err(Reason::DoesntIncludeIdentityOfLocalParty.into());
        }
        if parties.number_of_parties() < 2 {
            return Err(Reason::TooFewParties { n: 1 }.into());
        }
        let hashed_msg = Sha256::digest(&room_id);
        let hashed_msg = Message::from_slice(&hashed_msg)
            .expect("message has appropriate length, from_slice must never fail");

        let signature = SECP256K1.sign(&hashed_msg, &self.identity_key);
        let hello_msg = HelloMsg {
            public_key: self.identity,
            room_id,
            signature,
        };

        Ok(Connect {
            handshake: TlsHandshake::InProgress(self.tls_connector.connect(domain, stream)),
            identity_key: self.identity_key,
            parties,
            hello_msg: hello_msg.to_bytes(),
            sent_bytes: 0,
        })
    }
}

impl<P, IO> Future for Connect<P, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    P: IdentityResolver + Unpin,
{
    type Output = io::Result<ConnectedClient<P, IO>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self {
            handshake,
            hello_msg,
            sent_bytes,
            ..
        } = &mut *self;
        let stream = ready!(handshake.poll_handshake(cx))?;
        while *sent_bytes < HELLO_MSG_LEN {
            let bytes_written =
                ready!(Pin::new(&mut *stream).poll_write(cx, &hello_msg[*sent_bytes..]))?;
            if bytes_written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            *sent_bytes += bytes_written;
        }
        ready!(Pin::new(stream).poll_flush(cx))?;

        Poll::Ready(Ok(ConnectedClient {
            stream: self
                .handshake
                .take_completed()
                .ok()
                .expect("guaranteed to be completed"),
            identity_key: self.identity_key,
            parties: self.parties.clone(),
        }))
    }
}

pub struct ConnectedClient<P, IO> {
    stream: TlsStream<IO>,
    identity_key: SecretKey,
    parties: P,
}

pub struct OutgoingDelivery<P, IO> {
    channel: io::WriteHalf<TlsStream<IO>>,
    identity_key: SecretKey,
    parties: P,
}

pub struct PreparedOutgoing<'b> {
    header: [u8; 36],
    header_len: HeaderLength,
    msg: &'b [u8],
    signature: [u8; 64],
    sent_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
enum HeaderLength {
    Broadcast = 3,
    P2P = 36,
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("malformed message")]
    MalformedMessage(
        #[from]
        #[source]
        MalformedMessage,
    ),
    #[error("i/o error")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
}

#[derive(Debug, Error)]
pub enum MalformedMessage {
    #[error("destination party is unknown")]
    UnknownParty(u16),
    #[error("message too long: len={len}, limit={}", u16::MAX)]
    MessageTooLong { len: usize },
}

impl<P, IO> OutgoingChannel for OutgoingDelivery<P, IO>
where
    P: IdentityResolver + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Error = SendError;

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.channel).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        ready!(Pin::new(&mut self.channel).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<'b, P, IO> DeliverOutgoing<'b, &'b [u8]> for OutgoingDelivery<P, IO>
where
    P: IdentityResolver + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Prepared = PreparedOutgoing<'b>;
    fn prepare(
        self: Pin<&Self>,
        msg: Outgoing<&'b [u8]>,
    ) -> Result<PreparedOutgoing<'b>, SendError> {
        let msg_len = u16::try_from(msg.msg.len())
            .or(Err(MalformedMessage::MessageTooLong { len: msg.msg.len() }))?;
        let recipient = msg
            .recipient
            .map(|idx| {
                self.parties
                    .lookup_party_identity(idx)
                    .ok_or(MalformedMessage::UnknownParty(idx))
            })
            .transpose()?;

        let mut header = [0u8; 36];
        let header_len;
        match recipient {
            Some(recipient) => {
                header[0] = 1;
                header[1..34].copy_from_slice(&recipient.serialize());
                header[34..36].copy_from_slice(&msg_len.to_be_bytes());
                header_len = HeaderLength::P2P;
            }
            None => {
                header[0] = 0;
                header[1..3].copy_from_slice(&msg_len.to_be_bytes());
                header_len = HeaderLength::Broadcast;
            }
        };

        let hashed_msg = Sha256::new()
            .chain(recipient.map(PublicKey::serialize).unwrap_or([0u8; 33]))
            .chain(msg.msg)
            .finalize();
        let hashed_msg =
            Message::from_slice(hashed_msg.as_slice()).expect("sha256 output can be signed");

        let signature = SECP256K1
            .sign(&hashed_msg, &self.identity_key)
            .serialize_compact();

        Ok(PreparedOutgoing {
            header,
            header_len,
            msg: msg.msg,
            signature,
            sent_bytes: 0,
        })
    }

    fn poll_start_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        msg: &mut PreparedOutgoing<'b>,
    ) -> Poll<Result<(), SendError>> {
        let header_len = msg.header_len as usize;
        while msg.sent_bytes < header_len {
            let header = &msg.header[msg.sent_bytes..header_len];
            let sent_bytes = ready!(Pin::new(&mut self.channel).poll_write(cx, header))?;
            msg.sent_bytes += sent_bytes;
        }

        while msg.sent_bytes < header_len + msg.msg.len() {
            let offset = msg.sent_bytes - header_len;
            let sent_bytes =
                ready!(Pin::new(&mut self.channel).poll_write(cx, &msg.msg[offset..]))?;
            msg.sent_bytes += sent_bytes;
        }

        while msg.sent_bytes < header_len + msg.msg.len() + 64 {
            let offset = msg.sent_bytes - (header_len + msg.msg.len());
            let sent_bytes =
                ready!(Pin::new(&mut self.channel).poll_write(cx, &msg.signature[offset..]))?;
            msg.sent_bytes += sent_bytes;
        }

        Poll::Ready(Ok(()))
    }
}
