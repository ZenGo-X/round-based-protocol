use std::convert::TryFrom;

pub trait IdentityResolver: Clone {
    type Identity: Clone;
    type IdentitiesIter: Iterator<Item = Self::Identity>;

    /// Number of parties
    fn number_of_parties(&self) -> u16;
    /// Returns index of party with specified public key, or `None` if this party's unknown
    fn lookup_party_index(&self, party_identity: &Self::Identity) -> Option<u16>;
    /// Returns public key of i-th party, or `None` if `i >= n`
    fn lookup_party_identity(&self, party_index: u16) -> Option<&Self::Identity>;

    /// Iterator over parties identities
    ///
    /// First yielded identity correspond to party with index `0`, second identity — to party with
    /// index `1`, etc.
    fn identities(&self) -> Self::IdentitiesIter;
}

#[derive(Clone, Debug)]
pub struct SortedIdentities<I>(Vec<I>);

impl<I: Ord + Clone> From<Vec<I>> for SortedIdentities<I> {
    fn from(mut pk: Vec<I>) -> Self {
        pk.sort();
        Self(pk)
    }
}

impl<I> std::ops::Deref for SortedIdentities<I> {
    type Target = [I];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<I: Ord + Clone> IdentityResolver for SortedIdentities<I> {
    type Identity = I;
    type IdentitiesIter = std::vec::IntoIter<I>;

    fn number_of_parties(&self) -> u16 {
        u16::try_from(self.len()).expect("too many parties")
    }

    fn lookup_party_index(&self, party_identity: &Self::Identity) -> Option<u16> {
        self.binary_search(party_identity)
            .ok()
            .and_then(|n| u16::try_from(n).ok())
    }

    fn lookup_party_identity(&self, party_index: u16) -> Option<&Self::Identity> {
        self.get(usize::from(party_index))
    }

    fn identities(&self) -> Self::IdentitiesIter {
        self.0.clone().into_iter()
    }
}
