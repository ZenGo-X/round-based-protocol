use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, SecretKey, SECP256K1};

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

    pub fn public_share(&self) -> PublicKey {
        self.pk
    }
}
