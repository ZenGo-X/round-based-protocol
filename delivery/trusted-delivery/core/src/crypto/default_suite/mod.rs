use generic_array::typenum;
use never::Never;

use super::{CryptoSuite, EncryptionKey};

pub mod aead;
pub mod dalek_dh;
pub mod dalek_signing;
pub mod kdf;

pub struct DefaultSuite {
    _cannot_be_constructed: Never,
}

impl CryptoSuite for DefaultSuite {
    type Digest = sha2::Sha512;
    type DigestOutputSize = typenum::U64;

    type Mac = hmac::Hmac<sha2::Sha256>;
    type MacKeySize = typenum::U64;
    type MacOutputSize = typenum::U32;

    type EncryptionScheme = aead::AeadEncryptionScheme<aes_gcm::Aes256Gcm>;

    type SigningScheme = dalek_signing::DalekSigning;
    type KeyExchangeScheme = dalek_dh::DalekEcdh;

    type Kdf = hkdf::Hkdf<sha2::Sha256>;

    type EncryptionKey = aead::AeadKey<aes_gcm::Aes256Gcm, aead::Encryption>;
    type DecryptionKey = aead::AeadKey<aes_gcm::Aes256Gcm, aead::Decryption>;

    type SigningKey = dalek_signing::Keypair;
    type VerificationKey = dalek_signing::PublicKey;
    type Signature = dalek_signing::Signature;

    type KeyExchangeLocalShare = dalek_dh::EphemeralSecret;
    type KeyExchangeRemoteShare = dalek_dh::PublicKey;

    type EncryptionTagSize = <Self::EncryptionKey as EncryptionKey>::TagSize;
    type SignatureSize = typenum::U64;
    type VerificationKeySize = typenum::U32;
    type KeyExchangeRemoteShareSize = typenum::U32;
}
