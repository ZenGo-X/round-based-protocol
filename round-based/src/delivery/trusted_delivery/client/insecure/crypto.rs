use std::collections::HashMap;
use std::convert::Infallible;

use never::Never;

use generic_array::typenum::{U0, U12, U16};
use generic_array::{ArrayLength, GenericArray};
use secp256k1::PublicKey;

use aes_gcm::{AeadInPlace, Aes256Gcm};

pub trait EncryptionKey {
    type TagSize: ArrayLength<u8>;
    type Error;

    fn encrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Self::Error>;
}

pub trait DecryptionKey {
    type TagSize: ArrayLength<u8>;
    type Error;

    fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Self::Error>;
}

pub trait EncryptionKeys {
    type Key: EncryptionKey;

    fn has_encryption_key(&self, recipient_identity: &PublicKey) -> bool;
    fn get_encryption_key(&mut self, recipient_identity: &PublicKey) -> Option<&mut Self::Key>;
}

pub trait DecryptionKeys {
    type Key: DecryptionKey;

    fn has_decryption_key(&self, recipient_identity: &PublicKey) -> bool;
    fn get_decryption_key(&mut self, sender_identity: &PublicKey) -> Option<&mut Self::Key>;
}

impl<K: EncryptionKey> EncryptionKeys for HashMap<PublicKey, K> {
    type Key = K;

    fn has_encryption_key(&self, recipient_identity: &PublicKey) -> bool {
        self.contains_key(recipient_identity)
    }
    fn get_encryption_key(&mut self, sender_identity: &PublicKey) -> Option<&mut Self::Key> {
        self.get_mut(sender_identity)
    }
}

impl<K: DecryptionKey> DecryptionKeys for HashMap<PublicKey, K> {
    type Key = K;

    fn has_decryption_key(&self, recipient_identity: &PublicKey) -> bool {
        self.contains_key(recipient_identity)
    }
    fn get_decryption_key(&mut self, sender_identity: &PublicKey) -> Option<&mut Self::Key> {
        self.get_mut(sender_identity)
    }
}

#[derive(Clone, Debug)]
pub struct NoEncryption;

impl EncryptionKeys for NoEncryption {
    type Key = Never;

    fn has_encryption_key(&self, _recipient_identity: &PublicKey) -> bool {
        false
    }
    fn get_encryption_key(&mut self, _recipient_identity: &PublicKey) -> Option<&mut Self::Key> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct NoDecryption;

impl DecryptionKeys for NoDecryption {
    type Key = Never;

    fn has_decryption_key(&self, _recipient_identity: &PublicKey) -> bool {
        false
    }
    fn get_decryption_key(&mut self, _sender_identity: &PublicKey) -> Option<&mut Self::Key> {
        None
    }
}

impl EncryptionKey for Never {
    type TagSize = U0;
    type Error = Infallible;

    fn encrypt(
        &mut self,
        _associated_data: &[u8],
        _buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Self::Error> {
        self.into_any()
    }
}

impl DecryptionKey for Never {
    type TagSize = U0;
    type Error = Infallible;

    fn decrypt(
        &mut self,
        _associated_data: &[u8],
        _buffer: &mut [u8],
        _tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Self::Error> {
        self.into_any()
    }
}

#[cfg_attr(test, derive(Clone))]
pub struct AesGcmEncryptionKey {
    counter: u64,
    key: Aes256Gcm,
}

pub struct AesGcmDecryptionKey {
    counter: u64,
    key: Aes256Gcm,
}

impl AesGcmEncryptionKey {
    #[cfg(test)]
    pub fn new(counter: u64, key: Aes256Gcm) -> Self {
        Self { counter, key }
    }
}

impl AesGcmDecryptionKey {
    #[cfg(test)]
    pub fn new(counter: u64, key: Aes256Gcm) -> Self {
        Self { counter, key }
    }
}

impl EncryptionKey for AesGcmEncryptionKey {
    type TagSize = U16;
    type Error = aes_gcm::Error;

    fn encrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Self::Error> {
        let mut nonce = GenericArray::<u8, U12>::default();
        nonce.as_mut_slice()[..8].copy_from_slice(&self.counter.to_be_bytes());
        self.counter.checked_add(1).expect("counter overflow");
        self.key
            .encrypt_in_place_detached(&nonce, associated_data, buffer)
    }
}

impl DecryptionKey for AesGcmDecryptionKey {
    type TagSize = U16;
    type Error = aes_gcm::Error;

    fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Self::Error> {
        let mut nonce = GenericArray::<u8, U12>::default();
        nonce.as_mut_slice()[..8].copy_from_slice(&self.counter.to_be_bytes());
        self.key
            .decrypt_in_place_detached(&nonce, associated_data, buffer, tag)?;
        self.counter += 1;
        Ok(())
    }
}

#[cfg(test)]
pub fn random_aes_gcm_key() -> (AesGcmEncryptionKey, AesGcmDecryptionKey) {
    use aes_gcm::NewAead;
    use generic_array::typenum::U32;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut key = GenericArray::<u8, U32>::default();
    OsRng.fill_bytes(key.as_mut_slice());
    let encryption_key = AesGcmEncryptionKey {
        counter: 0,
        key: Aes256Gcm::new(&key),
    };
    let decryption_key = AesGcmDecryptionKey {
        counter: 0,
        key: Aes256Gcm::new(&key),
    };
    (encryption_key, decryption_key)
}
