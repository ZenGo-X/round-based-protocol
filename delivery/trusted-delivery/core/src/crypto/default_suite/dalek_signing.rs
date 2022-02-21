use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::hash::{Hash, Hasher};

use ed25519_dalek::ExpandedSecretKey;
pub use ed25519_dalek::Signature;

use digest::Digest;
use generic_array::GenericArray;
use never::Never;
use rand_v7::rngs::OsRng;
use typenum::{U32, U64};

use crate::crypto::{
    InvalidSignature, InvalidVerificationKey, Serializable, SigningKey, SigningScheme,
    VerificationKey,
};

const SIGNING_CONTEXT: &[u8] = b"Trusted Delivery signing";

pub struct DalekSigning {
    _cannot_be_constructed: Never,
}

impl SigningScheme for DalekSigning {
    type PublicKey = PublicKey;
    type SecretKey = Keypair;
    type Signature = Signature;
    type SignatureSize = U64;
}

#[derive(Clone, Copy, Debug)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl VerificationKey for PublicKey {
    type Signature = Signature;
    type HashedMessageSize = U64;

    fn verify<D>(
        &self,
        hashed_message: D,
        signature: &Self::Signature,
    ) -> Result<(), InvalidSignature>
    where
        D: Digest<OutputSize = Self::HashedMessageSize>,
    {
        self.0
            .verify_prehashed(hashed_message, Some(SIGNING_CONTEXT), signature)
            .or(Err(InvalidSignature))
    }
}

impl Serializable for PublicKey {
    type Size = U32;
    type Error = InvalidVerificationKey;
    const NAME: &'static str = "ed25519 verification key";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        GenericArray::from(self.0.to_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        ed25519_dalek::PublicKey::from_bytes(bytes)
            .map(PublicKey)
            .or(Err(InvalidVerificationKey))
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().eq(other.0.as_bytes())
    }
}

impl Serializable for Signature {
    type Size = U64;
    type Error = InvalidSignature;

    const NAME: &'static str = "ed25519 signature";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut array = GenericArray::<u8, U64>::default();
        array.copy_from_slice(self.as_ref());
        array
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Signature::from_bytes(bytes).or(Err(InvalidSignature))
    }
}

pub struct Keypair {
    secret_key: ExpandedSecretKey,
    public_key: PublicKey,
}

impl SigningKey for Keypair {
    type VerificationKey = PublicKey;
    type Signature = Signature;
    type HashedMessageSize = U64;

    fn generate() -> Self {
        let keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        Keypair {
            secret_key: (&keypair.secret).into(),
            public_key: PublicKey(keypair.public),
        }
    }

    fn sign<D>(&self, hashed_message: D) -> Self::Signature
    where
        D: Digest<OutputSize = Self::HashedMessageSize>,
    {
        // Correctness: line below returns error only if context
        // exceeds 255 bytes, so `.unwrap()` never panics
        self.secret_key
            .sign_prehashed(hashed_message, &self.public_key.0, Some(SIGNING_CONTEXT))
            .unwrap()
    }

    fn verification_key(&self) -> Self::VerificationKey {
        self.public_key
    }
}

impl Clone for Keypair {
    fn clone(&self) -> Self {
        Keypair {
            secret_key: ExpandedSecretKey::from_bytes(&self.secret_key.to_bytes()).unwrap(),
            public_key: self.public_key,
        }
    }
}

impl Serializable for Keypair {
    type Size = typenum::U64;
    type Error = InvalidKey;
    const NAME: &'static str = "ed25519 signing key";

    fn to_bytes(&self) -> GenericArray<u8, Self::Size> {
        let mut bytes = GenericArray::<u8, typenum::U64>::default();
        bytes.copy_from_slice(&self.secret_key.to_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let secret_key = ExpandedSecretKey::from_bytes(bytes).or(Err(InvalidKey))?;
        let public_key = PublicKey(ed25519_dalek::PublicKey::from(&secret_key));
        Ok(Self {
            public_key,
            secret_key,
        })
    }
}

#[derive(Debug, Error)]
#[error("invalid signing key")]
pub struct InvalidKey;
