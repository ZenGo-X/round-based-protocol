use std::iter;

use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, SecretKey, SECP256K1};

use crate::delivery::trusted_delivery::client::identity_resolver::SortedIdentities;

pub fn generate_parties_sk(n: u16) -> (SortedIdentities, Vec<SecretKey>) {
    let generate_sk = || loop {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        if let Ok(key) = SecretKey::from_slice(&key) {
            break key;
        }
    };
    let mut keys = iter::repeat_with(generate_sk)
        .map(|sk_i| (PublicKey::from_secret_key(&SECP256K1, &sk_i), sk_i))
        .take(usize::from(n))
        .collect::<Vec<_>>();
    keys.sort_by_key(|(pk_i, _)| *pk_i);

    let (pk, sk): (Vec<_>, Vec<_>) = keys.into_iter().unzip();
    let pk = SortedIdentities::from(pk);
    (pk, sk)
}
