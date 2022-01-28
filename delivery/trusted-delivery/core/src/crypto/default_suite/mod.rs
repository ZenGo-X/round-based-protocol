use generic_array::typenum;
use never::Never;

use super::{CryptoSuite, EncryptionKey};

pub mod aead;
pub mod elliptic;
pub mod kdf;

pub struct DefaultSuite {
    _cannot_be_constructed: Never,
}

impl CryptoSuite for DefaultSuite {
    type Digest = sha2::Sha256;
    type DigestOutputSize = typenum::U32;

    type Mac = hmac::Hmac<sha2::Sha256>;
    type MacKeySize = typenum::U64;
    type MacOutputSize = typenum::U32;

    type EncryptionScheme = aead::AeadEncryptionScheme<aes_gcm::Aes256Gcm>;

    type SigningScheme = elliptic::Secp256k1;
    type KeyExchangeScheme = elliptic::Secp256k1;

    type Kdf = hkdf::Hkdf<sha2::Sha256>;

    type EncryptionKey = aead::AeadKey<aes_gcm::Aes256Gcm, aead::Encryption>;
    type DecryptionKey = aead::AeadKey<aes_gcm::Aes256Gcm, aead::Decryption>;

    type SigningKey = elliptic::Scalar<elliptic::Signing>;
    type VerificationKey = elliptic::Point<elliptic::Signing>;
    type Signature = elliptic::Signature;

    type KeyExchangeLocalShare = elliptic::Scalar<elliptic::KeyExchange>;
    type KeyExchangeRemoteShare = elliptic::Point<elliptic::KeyExchange>;

    type EncryptionTagSize = <Self::EncryptionKey as EncryptionKey>::TagSize;
    type SignatureSize = typenum::U64;
    type VerificationKeySize = typenum::U33;
    type KeyExchangeRemoteShareSize = typenum::U33;
}
