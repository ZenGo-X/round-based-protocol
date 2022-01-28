use futures::{Sink, Stream};
use reqwest::{Client as HttpClient, IntoUrl, Url};

use delivery_core::{Delivery, Incoming};
use trusted_delivery_core::crypto::CryptoSuite;
use trusted_delivery_core::messages::RoomId;

struct Connection<I, O> {
    incomings: I,
    outgoings: O,
}

impl<I, O, IErr, M> Delivery<M> for Connection<I, O>
where
    I: Stream<Item = Result<Incoming<M>, IErr>> + Send + Unpin + 'static,
    O: Sink<M> + Send + Unpin,
{
    type Send = O;
    type Receive = I;
    type SendError = O::Error;
    type ReceiveError = IErr;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.incomings, self.outgoings)
    }
}

pub struct Client<C: CryptoSuite> {
    /// HTTP client (backed by [reqwest])
    pub http_client: HttpClient,
    /// Server address
    pub base_url: Url,
    /// Group info
    pub group: Group<C>,
    /// Secret key of local party that is used to sign messages
    pub secret_key: C::SigningKey,
}

pub struct Group<C: CryptoSuite> {
    /// Unique identifier of that group
    pub id: RoomId,
    /// Sorted list of parties public keys
    ///
    /// Public key of local party must be present in the list.
    pub parties: SortedList<C::VerificationKey>,
}

#[derive(Debug, Clone)]
pub struct SortedList<T>(Vec<T>);

impl<T: Ord> From<Vec<T>> for SortedList<T> {
    fn from(mut v: Vec<T>) -> Self {
        v.sort();
        Self(v)
    }
}

impl<T> std::ops::Deref for SortedList<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct Incomings<C: CryptoSuite> {
    response: reqwest::Response,
    parsed_header: u8,
    buffer: Vec<u8>,
}
