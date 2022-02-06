use std::{io, iter};

use trusted_delivery_core::crypto::*;
use trusted_delivery_core::RoomId;

use thiserror::Error;

use crate::sorted_list::SizeU16;

pub use self::client::{
    ApiClient, Authenticated, Error as ApiError, JoinedRoom, NotAuthenticated, Subscription,
};
pub use self::sorted_list::SortedList;

mod client;
mod sorted_list;

pub struct Delivery<C: CryptoSuite> {
    c: C,
}

impl<C: CryptoSuite> Delivery<C> {
    pub async fn connect(
        api_client: ApiClient<Authenticated<C>>,
        group: Group<C>,
    ) -> Result<(), Error> {
        // 1. Validate input parameters
        let parties = SizeU16::from_list(group.parties)
            .map_err(|err| Reason::TooManyParties { n: err.0.len() })?;
        let pk = api_client.identity();
        let mut api_client = api_client.join_room(group.id);

        let i = parties
            .find_index(&pk)
            .ok_or(Reason::LocalPartyNotInGroup)?;

        if parties.len() < 2 {
            return Err(Reason::TooFewParties { n: parties.len() }.into());
        }

        // 2. Perform P2P handshake

        // 2.1. Generate ephemeral DH keys
        let (ephemeral_pk, ephemeral_sk): (Vec<_>, Vec<_>) =
            iter::repeat_with(C::KeyExchangeScheme::generate)
                .take(group.parties.len() - 1)
                .unzip();

        // 2.2. Send each key to corresponding party
        for ((i, pk_i), ephemeral) in (0..)
            .zip(group.parties.iter())
            .filter(|(_i, pk_i)| pk_i != pk)
            .zip(ephemeral_pk)
        {
            api_client
                .send(Some(pk_i.clone()), &ephemeral.to_bytes())
                .await
                .map_err(|err| Reason::SendEphemeralKey {
                    destination: i,
                    err,
                })?;
        }

        // 2.3. Receive ephemeral keys from other parties
        let ephemeral_remote = 1;

        todo!()
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
pub struct Error(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("too few parties in the group: n={n} (required at least 2 parties)")]
    TooFewParties { n: u16 },
    #[error("too many parties in the group: n={n} (limit is {limit}", limit = u16::MAX)]
    TooManyParties { n: usize },
    #[error("local party is not in the list of group parties")]
    LocalPartyNotInGroup,
    #[error("sending ephemeral DH key to party #{destination}")]
    SendEphemeralKey {
        destination: u16,
        #[source]
        err: client::Error,
    },
}
