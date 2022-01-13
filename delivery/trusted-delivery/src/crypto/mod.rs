use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use never::Never;
use phantom_type::PhantomType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod default_suite;

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
        Signature = Self::Signature,
        SignatureSize = Self::SignatureSize,
    >;
    type KeyExchangeScheme: KeyExchangeScheme<
        PublicKey = Self::KeyExchangeRemoteShare,
        SecretKey = Self::KeyExchangeLocalShare,
    >;
    type Kdf: Kdf;

    type EncryptionKey: EncryptionKey<TagSize = Self::EncryptionTagSize>
        + Send
        + Sync
        + Unpin
        + 'static;
    type DecryptionKey: DecryptionKey<TagSize = Self::EncryptionTagSize>
        + Send
        + Sync
        + Unpin
        + 'static;
    type SigningKey: SigningKey<
            VerificationKey = Self::VerificationKey,
            Signature = Self::Signature,
            HashedMessageSize = Self::DigestOutputSize,
        > + Send
        + Sync
        + Unpin
        + 'static;
    type VerificationKey: VerificationKey<
            Size = Self::VerificationKeySize,
            Signature = Self::Signature,
            HashedMessageSize = Self::DigestOutputSize,
        > + Eq
        + Ord
        + Hash
        + Clone
        + Send
        + Sync
        + Unpin
        + fmt::Debug
        + 'static;
    type Signature: Serializable<Size = Self::SignatureSize, Error = InvalidSignature>
        + Eq
        + Send
        + Sync
        + Unpin
        + fmt::Debug
        + 'static;
    type KeyExchangeLocalShare: Send + Sync + Unpin + 'static;
    type KeyExchangeRemoteShare: Serializable<Size = Self::KeyExchangeRemoteShareSize, Error = InvalidRemoteShare>
        + Send
        + Sync
        + Unpin
        + 'static;

    type EncryptionTagSize: ArrayLength<u8>;
    type SignatureSize: ArrayLength<u8>;
    type VerificationKeySize: ArrayLength<u8>;
    type KeyExchangeRemoteShareSize: ArrayLength<u8>;
}

pub trait KeyExchangeScheme {
    type PublicKey: Serializable;
    type SecretKey;

    fn generate() -> (Self::PublicKey, Self::SecretKey);
    fn kdf<K: Kdf>(local: &Self::SecretKey, remote: &Self::PublicKey) -> Result<K, KdfError>;
}

#[derive(Debug, Error)]
#[error("remote share of key exchange scheme is invalid")]
pub struct InvalidRemoteShare;

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
        Signature = Self::Signature,
        HashedMessageSize = <Self::PublicKey as VerificationKey>::HashedMessageSize,
    >;
    type Signature: Serializable<Size = Self::SignatureSize>;

    type SignatureSize: ArrayLength<u8>;
}

pub trait SigningKey {
    type VerificationKey: VerificationKey;
    type Signature;
    type HashedMessageSize: ArrayLength<u8>;

    fn generate() -> Self;
    fn sign<D>(&self, hashed_message: D) -> Self::Signature
    where
        D: Digest<OutputSize = Self::HashedMessageSize>;
    fn verification_key(&self) -> Self::VerificationKey;
}

pub trait VerificationKey: Serializable<Error = InvalidVerificationKey> {
    type Signature;
    type HashedMessageSize: ArrayLength<u8>;

    fn verify<D>(
        &self,
        hashed_message: D,
        signature: &Self::Signature,
    ) -> Result<(), InvalidSignature>
    where
        D: Digest<OutputSize = Self::HashedMessageSize>;
}

pub trait Serializable: Clone {
    type Size: ArrayLength<u8>;
    type Error: fmt::Display;

    /// Name of serializable object, e.g. `secp256k1 point`
    ///
    /// It does not affect anything but debug and error messages
    const NAME: &'static str;

    fn to_bytes(&self) -> GenericArray<u8, Self::Size>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}

/// Wraps [`Serializable`] and implements [serde] traits: [`Serialize`] and [`Deserialize`]
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SerdeCompat<S>(pub S);

impl<S: Serializable> Serialize for SerdeCompat<S> {
    fn serialize<M>(&self, serializer: M) -> Result<M::Ok, M::Error>
    where
        M: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.0.to_bytes()))
        } else {
            serializer.serialize_bytes(&self.0.to_bytes())
        }
    }
}

impl<'de, S: Serializable> Deserialize<'de> for SerdeCompat<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use std::marker::PhantomData;

        use serde::de::{Error, Visitor};

        struct TheVisitor<S>(PhantomData<S>);
        impl<'de, S: Serializable> Visitor<'de> for TheVisitor<S> {
            type Value = S;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", S::NAME)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let mut bytes = GenericArray::<u8, S::Size>::default();
                hex::decode_to_slice(v, &mut bytes).map_err(|_| E::custom("invalid hex string"))?;
                S::from_bytes(&bytes).map_err(E::custom)
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                S::from_bytes(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer
                .deserialize_str(TheVisitor(PhantomData))
                .map(Self)
        } else {
            deserializer
                .deserialize_bytes(TheVisitor(PhantomData))
                .map(Self)
        }
    }
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
        signature: &K::Signature,
    ) -> Result<(), InvalidSignature>
    where
        K: VerificationKey<HashedMessageSize = Self::OutputSize>;

    fn sign_message<K>(self, secret_key: &K) -> K::Signature
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
        signature: &K::Signature,
    ) -> Result<(), InvalidSignature>
    where
        K: VerificationKey<HashedMessageSize = Self::OutputSize>,
    {
        verification_key.verify(self, signature)
    }

    #[inline(always)]
    fn sign_message<K>(self, secret_key: &K) -> K::Signature
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

    fn encrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, EncryptionError>;
}

pub trait DecryptionKey {
    type TagSize: ArrayLength<u8>;

    fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), DecryptionError>;
}

#[derive(Debug, Error, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[error("encryption failed")]
pub struct EncryptionError;
#[derive(Debug, Error, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[error("decryption failed")]
pub struct DecryptionError;

pub trait EncryptionKeys {
    type Identity;
    type Key: EncryptionKey<TagSize = Self::TagSize>;
    type TagSize: ArrayLength<u8>;

    fn has_encryption_key(&self, recipient_identity: &Self::Identity) -> bool;
    fn get_encryption_key(&mut self, recipient_identity: &Self::Identity)
        -> Option<&mut Self::Key>;
}

pub trait DecryptionKeys {
    type Identity;
    type Key: DecryptionKey<TagSize = Self::TagSize>;
    type TagSize: ArrayLength<u8>;

    fn has_decryption_key(&self, recipient_identity: &Self::Identity) -> bool;
    fn get_decryption_key(&mut self, sender_identity: &Self::Identity) -> Option<&mut Self::Key>;
}

impl<I: Eq + Hash, K: EncryptionKey> EncryptionKeys for HashMap<I, K> {
    type Identity = I;
    type Key = K;
    type TagSize = K::TagSize;

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
    type TagSize = K::TagSize;

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
    type TagSize = typenum::U0;

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
    type TagSize = typenum::U0;

    fn has_decryption_key(&self, _recipient_identity: &Self::Identity) -> bool {
        false
    }
    fn get_decryption_key(&mut self, _sender_identity: &Self::Identity) -> Option<&mut Self::Key> {
        None
    }
}

impl EncryptionKey for Never {
    type TagSize = typenum::U0;

    fn encrypt(
        &mut self,
        _associated_data: &[u8],
        _buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, EncryptionError> {
        self.into_any()
    }
}

impl DecryptionKey for Never {
    type TagSize = typenum::U0;

    fn decrypt(
        &mut self,
        _associated_data: &[u8],
        _buffer: &mut [u8],
        _tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), DecryptionError> {
        self.into_any()
    }
}
