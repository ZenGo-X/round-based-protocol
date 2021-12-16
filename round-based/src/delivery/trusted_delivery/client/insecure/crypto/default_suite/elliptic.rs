use std::fmt;

use generic_array::typenum::{U32, U33, U64};
use generic_array::GenericArray;
use never::Never;
use phantom_type::PhantomType;
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::SECP256K1;
use sha2::Digest;

use crate::delivery::trusted_delivery::client::insecure::crypto::{
    InvalidRemoteShare, InvalidSignature, InvalidVerificationKey, Kdf, KdfError, KeyExchangeScheme,
    Serializable, SigningKey, SigningScheme, VerificationKey,
};

pub struct Secp256k1 {
    cannot_be_constructed: Never,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Scalar<P> {
    pub scalar: secp256k1::SecretKey,
    _purpose: PhantomType<P>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Point<P> {
    pub point: secp256k1::PublicKey,
    _purpose: PhantomType<P>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(pub secp256k1::Signature);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Signing(Never);
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct KeyExchange(Never);

impl KeyExchangeScheme for Secp256k1 {
    type PublicKey = Point<KeyExchange>;
    type SecretKey = Scalar<KeyExchange>;

    fn generate() -> (Self::PublicKey, Self::SecretKey) {
        let secret = Scalar::random();
        let public = Point::from(&secret);
        (public, secret)
    }

    fn kdf<K: Kdf>(local: &Self::SecretKey, remote: &Self::PublicKey) -> Result<K, KdfError> {
        let mut shared_secret = remote.point;
        shared_secret
            .mul_assign(&SECP256K1, local.scalar.as_ref())
            .expect("local secret key must be valid");
        K::new(&shared_secret.serialize())
    }
}

impl SigningScheme for Secp256k1 {
    type PublicKey = Point<Signing>;
    type SecretKey = Scalar<Signing>;
    type Signature = Signature;
    type SignatureSize = U64;
}

impl Serializable for Point<KeyExchange> {
    type Size = U33;
    type Error = InvalidRemoteShare;
    const NAME: &'static str = "diffie-hellman secp256k1 public key";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut bytes = GenericArray::<u8, Self::Size>::default();
        bytes.copy_from_slice(&self.point.serialize());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        secp256k1::PublicKey::from_slice(bytes)
            .map(|point| Self {
                point,
                _purpose: PhantomType::new(),
            })
            .map_err(|_| InvalidRemoteShare)
    }
}

impl Serializable for Point<Signing> {
    type Size = U33;
    type Error = InvalidVerificationKey;
    const NAME: &'static str = "ecdsa secp256k1 verification key";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut bytes = GenericArray::<u8, Self::Size>::default();
        bytes.copy_from_slice(&self.point.serialize());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        secp256k1::PublicKey::from_slice(bytes)
            .map(|point| Self {
                point,
                _purpose: PhantomType::new(),
            })
            .map_err(|_| InvalidVerificationKey)
    }
}

impl Serializable for Signature {
    type Size = U64;
    type Error = InvalidSignature;
    const NAME: &'static str = "ecdsa secp256k1 compact signature";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut bytes = GenericArray::<u8, Self::Size>::default();
        bytes.copy_from_slice(&self.0.serialize_compact());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        secp256k1::Signature::from_compact(bytes)
            .map(Self)
            .map_err(|_| InvalidSignature)
    }
}

impl VerificationKey for Point<Signing> {
    type Signature = Signature;
    type HashedMessageSize = U32;

    fn verify<D>(
        &self,
        hashed_message: D,
        signature: &Self::Signature,
    ) -> Result<(), InvalidSignature>
    where
        D: Digest<OutputSize = Self::HashedMessageSize>,
    {
        let message = secp256k1::Message::from(AppropriateHashOutput(hashed_message.finalize()));
        SECP256K1
            .verify(&message, &signature.0, &self.point)
            .map_err(|_| InvalidSignature)
    }
}

impl SigningKey for Scalar<Signing> {
    type VerificationKey = Point<Signing>;
    type Signature = Signature;
    type HashedMessageSize = U32;

    fn generate() -> Self {
        Self::random()
    }

    fn sign<D>(&self, hashed_message: D) -> Self::Signature
    where
        D: Digest<OutputSize = Self::HashedMessageSize>,
    {
        let message = secp256k1::Message::from(AppropriateHashOutput(hashed_message.finalize()));
        Signature(SECP256K1.sign(&message, &self.scalar))
    }

    fn verification_key(&self) -> Self::VerificationKey {
        Point::from(self)
    }
}

impl<P> Scalar<P> {
    fn random() -> Self {
        loop {
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            if let Ok(scalar) = secp256k1::SecretKey::from_slice(&secret) {
                break Self {
                    scalar,
                    _purpose: PhantomType::new(),
                };
            }
        }
    }
}

impl<P> From<&Scalar<P>> for Point<P> {
    fn from(s: &Scalar<P>) -> Self {
        Self {
            point: secp256k1::PublicKey::from_secret_key(&SECP256K1, &s.scalar),
            _purpose: PhantomType::new(),
        }
    }
}

impl<P> fmt::Debug for Scalar<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "hidden")
    }
}

/// States that `D` is an appropriate 32 bytes hash output
struct AppropriateHashOutput(GenericArray<u8, U32>);

impl secp256k1::ThirtyTwoByteHash for AppropriateHashOutput {
    fn into_32(self) -> [u8; 32] {
        self.0.into()
    }
}
