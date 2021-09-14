use std::convert::TryFrom;

use secp256k1::PublicKey;

pub trait IdentityResolver {
    fn lookup_party_index(&self, party_identity: &PublicKey) -> Option<u16>;
    fn lookup_party_identity(&self, party_index: u16) -> Option<&PublicKey>;
}

pub struct SortedIdentities(Vec<PublicKey>);

impl From<Vec<PublicKey>> for SortedIdentities {
    fn from(mut pk: Vec<PublicKey>) -> Self {
        pk.sort();
        Self(pk)
    }
}

impl std::ops::Deref for SortedIdentities {
    type Target = [PublicKey];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IdentityResolver for Vec<PublicKey> {
    fn lookup_party_index(&self, party_identity: &PublicKey) -> Option<u16> {
        self.binary_search(party_identity)
            .ok()
            .and_then(|n| u16::try_from(n).ok())
    }

    fn lookup_party_identity(&self, party_index: u16) -> Option<&PublicKey> {
        self.get(usize::from(party_index))
    }
}
