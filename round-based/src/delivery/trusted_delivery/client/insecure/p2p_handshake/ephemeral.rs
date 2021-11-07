use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::Sha256;

use serde::{Deserialize, Serialize};

pub struct EphemeralKey {
    sk: SecretKey,
    pk: PublicKey,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let sk = loop {
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            if let Ok(key) = SecretKey::from_slice(&secret) {
                break key;
            }
        };
        let pk = PublicKey::from_secret_key(&SECP256K1, &sk);
        Self { sk, pk }
    }

    pub fn public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey(self.pk)
    }

    pub fn hkdf(&self, public_key: &EphemeralPublicKey) -> Hkdf<Sha256> {
        let mut shared_secret = public_key.0;
        shared_secret
            .mul_assign(&SECP256K1, self.sk.as_ref())
            .expect("sk must be valid");
        Hkdf::new(
            Some(b"trusted delivery p2p handshake"),
            &shared_secret.serialize(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
#[serde(transparent)]
pub struct EphemeralPublicKey(PublicKey);
