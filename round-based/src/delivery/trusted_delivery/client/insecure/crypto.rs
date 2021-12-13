use std::collections::HashMap;
use std::convert::Infallible;

use never::Never;
use thiserror::Error;

use generic_array::typenum::{U0, U12, U16};
use generic_array::{ArrayLength, GenericArray};
// use secp256k1::PublicKey;

use aes_gcm::{AeadInPlace, Aes256Gcm};
use phantom_type::PhantomType;
use sha2::Digest;
use std::hash::Hash;

pub mod aead;

pub trait CryptoSuite {
    type Digest: Digest<OutputSize = Self::DigestOutputSize>;
    type DigestOutputSize: ArrayLength<u8>;

    type EncryptionScheme: EncryptionScheme<
        EncryptionKey = Self::EncryptionKey,
        DecryptionKey = Self::DecryptionKey,
    >;
    type SigningScheme: SigningScheme<
        PublicKey = Self::VerificationKey,
        SecretKey = Self::SigningKey,
        SignatureSize = Self::SignatureSize,
    >;

    type EncryptionKey: EncryptionKey;
    type DecryptionKey: DecryptionKey;
    type SigningKey: SigningKey<
        VerificationKey = Self::VerificationKey,
        SignatureSize = Self::SignatureSize,
        HashedMessageSize = Self::DigestOutputSize,
    >;
    type VerificationKey: VerificationKey<
        Size = Self::VerificationKeySize,
        HashedMessageSize = Self::DigestOutputSize,
    >;

    type SignatureSize: ArrayLength<u8>;
    type VerificationKeySize: ArrayLength<u8>;
}

// pub const fn signature_size<C: CryptoSuite>() -> usize {
//     C::SignatureSize::USIZE
// }
//
// pub const fn verification_key_size<C: CryptoSuite>() -> usize {
//     C::VerificationKey::Size::USIZE
// }

pub trait KeyExchangeScheme {
    type PublicKey;
    type SecretKey;

    fn generate() -> (Self::PublicKey, Self::SecretKey);
    fn kdf<K: Kdf>(local: &Self::SecretKey, remote: &Self::PublicKey) -> K;
}

pub trait Kdf: Sized {
    fn new(key_material: &[u8]) -> Result<Self, KdfError>;
    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), KdfError>;
}

#[derive(Debug, Error)]
#[error("kdf error")]
pub struct KdfError;

pub trait SigningScheme {
    type PublicKey: VerificationKey;
    type SecretKey: SigningKey<
        VerificationKey = Self::PublicKey,
        SignatureSize = Self::SignatureSize,
        HashedMessageSize = <Self::PublicKey as VerificationKey>::HashedMessageSize,
    >;

    type SignatureSize: ArrayLength<u8>;
}

pub trait SigningKey {
    type VerificationKey: VerificationKey;
    type SignatureSize: ArrayLength<u8>;
    type HashedMessageSize: ArrayLength<u8>;

    fn generate() -> Self;
    fn sign<D>(&self, hashed_message: D) -> GenericArray<u8, Self::SignatureSize>
    where
        D: Digest<OutputSize = Self::HashedMessageSize>;
    fn verification_key(&self) -> Self::VerificationKey;
}

pub trait VerificationKey: PublicKey + Unpin {
    type HashedMessageSize: ArrayLength<u8>;

    fn verify<D>(&self, hashed_message: D, signature: &[u8]) -> Result<(), InvalidSignature>
    where
        D: Digest<OutputSize = Self::HashedMessageSize>;
}

pub trait PublicKey: Clone {
    type Size: ArrayLength<u8>;

    fn to_bytes(&self) -> GenericArray<u8, Self::Size>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidVerificationKey>;
}

#[derive(Error, Debug)]
#[error("verification key is invalid")]
pub struct InvalidVerificationKey;

#[derive(Error, Debug)]
#[error("signature is invalid")]
pub struct InvalidSignature;

pub trait DigestExt: Digest {
    fn verify_signature<K>(
        self,
        verification_key: &K,
        signature: &[u8],
    ) -> Result<(), InvalidSignature>
    where
        K: VerificationKey<HashedMessageSize = Self::OutputSize>;

    fn sign_message<K>(self, secret_key: &K) -> GenericArray<u8, K::SignatureSize>
    where
        K: SigningKey<HashedMessageSize = Self::OutputSize>;
}

impl<D> DigestExt for D
where
    D: Digest,
{
    #[inline(always)]
    fn verify_signature<K>(
        self,
        verification_key: &K,
        signature: &[u8],
    ) -> Result<(), InvalidSignature>
    where
        K: VerificationKey<HashedMessageSize = Self::OutputSize>,
    {
        verification_key.verify(self, signature)
    }

    #[inline(always)]
    fn sign_message<K>(self, secret_key: &K) -> GenericArray<u8, K::SignatureSize>
    where
        K: SigningKey<HashedMessageSize = Self::OutputSize>,
    {
        secret_key.sign(self)
    }
}

pub trait EncryptionScheme {
    type Key: AsMut<[u8]> + Default;
    type EncryptionKey: EncryptionKey;
    type DecryptionKey: DecryptionKey<TagSize = <Self::EncryptionKey as EncryptionKey>::TagSize>;

    fn encryption_key(key: &Self::Key) -> Self::EncryptionKey;
    fn decryption_key(key: &Self::Key) -> Self::DecryptionKey;
}

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
    type Identity;
    type Key: EncryptionKey;

    fn has_encryption_key(&self, recipient_identity: &Self::Identity) -> bool;
    fn get_encryption_key(&mut self, recipient_identity: &Self::Identity)
        -> Option<&mut Self::Key>;
}

pub trait DecryptionKeys {
    type Identity;
    type Key: DecryptionKey;

    fn has_decryption_key(&self, recipient_identity: &Self::Identity) -> bool;
    fn get_decryption_key(&mut self, sender_identity: &Self::Identity) -> Option<&mut Self::Key>;
}

impl<I: Eq + Hash, K: EncryptionKey> EncryptionKeys for HashMap<I, K> {
    type Identity = I;
    type Key = K;

    fn has_encryption_key(&self, recipient_identity: &Self::Identity) -> bool {
        self.contains_key(recipient_identity)
    }
    fn get_encryption_key(&mut self, sender_identity: &Self::Identity) -> Option<&mut Self::Key> {
        self.get_mut(sender_identity)
    }
}

impl<I: Eq + Hash, K: DecryptionKey> DecryptionKeys for HashMap<I, K> {
    type Identity = I;
    type Key = K;

    fn has_decryption_key(&self, recipient_identity: &Self::Identity) -> bool {
        self.contains_key(recipient_identity)
    }
    fn get_decryption_key(&mut self, sender_identity: &Self::Identity) -> Option<&mut Self::Key> {
        self.get_mut(sender_identity)
    }
}

#[derive(Clone, Debug)]
pub struct NoEncryption<I> {
    _ph: PhantomType<I>,
}

impl<I> NoEncryption<I> {
    pub fn new() -> Self {
        Self {
            _ph: PhantomType::new(),
        }
    }
}

impl<I> EncryptionKeys for NoEncryption<I> {
    type Identity = I;
    type Key = Never;

    fn has_encryption_key(&self, _recipient_identity: &Self::Identity) -> bool {
        false
    }
    fn get_encryption_key(
        &mut self,
        _recipient_identity: &Self::Identity,
    ) -> Option<&mut Self::Key> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct NoDecryption<I> {
    _ph: PhantomType<I>,
}

impl<I> NoDecryption<I> {
    pub fn new() -> Self {
        Self {
            _ph: PhantomType::new(),
        }
    }
}

impl<I> DecryptionKeys for NoDecryption<I> {
    type Identity = I;
    type Key = Never;

    fn has_decryption_key(&self, _recipient_identity: &Self::Identity) -> bool {
        false
    }
    fn get_decryption_key(&mut self, _sender_identity: &Self::Identity) -> Option<&mut Self::Key> {
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
