use trusted_delivery_core::crypto::CryptoSuite;
use trusted_delivery_core::RoomId;

use thiserror::Error;

use crate::sorted_list::SizeU16;

pub use self::client::{
    ApiClient, Authenticated, Error as ApiError, JoinedRoom, NotAuthenticated, Subscription,
};
pub use self::sorted_list::SortedList;

mod client;
mod sorted_list;

pub struct DeliveryBuilder<C: CryptoSuite> {
    /// API Client of Delivery Server
    pub api_client: ApiClient<Authenticated<C>>,
    /// Group info
    pub group: Group<C>,
}

impl<C: CryptoSuite> DeliveryBuilder<C> {
    pub async fn build(self) -> Result<(), BuildError> {
        let parties = SizeU16::from_list(self.group.parties)
            .map_err(|err| Reason::TooManyParties { n: err.0.len() })?;
        let pk = self.api_client.identity();
        let api_client = self.api_client.join_room(self.group.id);

        let i = parties
            .find_index(&pk)
            .ok_or(Reason::LocalPartyNotInGroup)?;

        if parties.len() < 2 {
            return Err(Reason::TooFewParties { n: parties.len() }.into());
        }

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
pub struct BuildError(#[from] Reason);

#[derive(Debug, Error)]
enum Reason {
    #[error("too few parties in the group: n={n} (required at least 2 parties)")]
    TooFewParties { n: u16 },
    #[error("too many parties in the group: n={n} (limit is {limit}", limit = u16::MAX)]
    TooManyParties { n: usize },
    #[error("local party is not in the list of group parties")]
    LocalPartyNotInGroup,
}
