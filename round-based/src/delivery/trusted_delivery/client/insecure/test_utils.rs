use std::iter;

use crate::delivery::trusted_delivery::client::identity_resolver::SortedIdentities;
use crate::delivery::trusted_delivery::client::insecure::crypto::{CryptoSuite, SigningKey};

pub fn generate_parties_sk<C: CryptoSuite>(
    n: u16,
) -> (SortedIdentities<C::VerificationKey>, Vec<C::SigningKey>) {
    let mut keys = iter::repeat_with(C::SigningKey::generate)
        .map(|sk_i| (sk_i.verification_key(), sk_i))
        .take(usize::from(n))
        .collect::<Vec<_>>();
    keys.sort_by_key(|(pk_i, _)| pk_i.clone());

    let (pk, sk): (Vec<_>, Vec<_>) = keys.into_iter().unzip();
    let pk = SortedIdentities::from(pk);
    (pk, sk)
}
