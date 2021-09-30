use std::convert::Infallible;

use never::Never;

use generic_array::typenum::U0;
use generic_array::{ArrayLength, GenericArray};
use secp256k1::PublicKey;

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

    fn get_encryption_key(&mut self, recipient_identity: &PublicKey) -> Option<&mut Self::Key>;
}

pub trait DecryptionKeys {
    type Key: DecryptionKey;

    fn get_decryption_key(&mut self, sender_identity: &PublicKey) -> Option<&mut Self::Key>;
}

#[derive(Clone, Debug)]
pub struct NoEncryption;

impl EncryptionKeys for NoEncryption {
    type Key = Never;

    fn get_encryption_key(&mut self, _recipient_identity: &PublicKey) -> Option<&mut Self::Key> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct NoDecryption;

impl DecryptionKeys for NoDecryption {
    type Key = Never;

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
