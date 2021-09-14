use std::convert::TryFrom;

use secp256k1::PublicKey;

pub trait IdentityResolver: Clone {
    type IdentitiesIter: Iterator<Item = PublicKey>;

    /// Number of parties
    fn number_of_parties(&self) -> u16;
    /// Returns index of party with specified public key, or `None` if this party's unknown
    fn lookup_party_index(&self, party_identity: &PublicKey) -> Option<u16>;
    /// Returns public key of i-th party, or `None` if `i >= n`
    fn lookup_party_identity(&self, party_index: u16) -> Option<&PublicKey>;

    /// Iterator over parties identities
    ///
    /// First yielded identity correspond to party with index `0`, second identity — to party with
    /// index `1`, etc.
    fn identities(&self) -> Self::IdentitiesIter;
}

#[derive(Clone, Debug)]
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

impl IdentityResolver for SortedIdentities {
    type IdentitiesIter = std::vec::IntoIter<PublicKey>;

    fn number_of_parties(&self) -> u16 {
        u16::try_from(self.len()).expect("too many parties")
    }

    fn lookup_party_index(&self, party_identity: &PublicKey) -> Option<u16> {
        self.binary_search(party_identity)
            .ok()
            .and_then(|n| u16::try_from(n).ok())
    }

    fn lookup_party_identity(&self, party_index: u16) -> Option<&PublicKey> {
        self.get(usize::from(party_index))
    }

    fn identities(&self) -> Self::IdentitiesIter {
        self.0.clone().into_iter()
    }
}
