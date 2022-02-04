pub use x25519_dalek::{EphemeralSecret, PublicKey};

use generic_array::GenericArray;
use never::Never;
use rand_v7::rngs::OsRng;
use typenum::U32;

use crate::crypto::{InvalidRemoteShare, Kdf, KdfError, KeyExchangeScheme, Serializable};

pub struct DalekEcdh {
    _cannot_be_constructed: Never,
}

impl KeyExchangeScheme for DalekEcdh {
    type PublicKey = PublicKey;
    type SecretKey = EphemeralSecret;

    fn generate() -> (Self::PublicKey, Self::SecretKey) {
        let sk = EphemeralSecret::new(OsRng);
        let pk = PublicKey::from(&sk);
        (pk, sk)
    }

    fn kdf<K: Kdf>(local: Self::SecretKey, remote: &Self::PublicKey) -> Result<K, KdfError> {
        let shared_secret = local.diffie_hellman(remote);
        K::new(shared_secret.as_bytes())
    }
}

impl Serializable for PublicKey {
    type Size = U32;
    type Error = InvalidRemoteShare;

    const NAME: &'static str = "ECDH X25519 public key";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::from(self.to_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let pk = <[u8; 32]>::try_from(bytes).or(Err(InvalidRemoteShare))?;
        Ok(PublicKey::from(pk))
    }
}
