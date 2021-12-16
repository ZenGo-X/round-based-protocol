use generic_array::ArrayLength;
use hkdf::Hkdf;
use sha2::digest::{BlockInput, FixedOutput, Reset, Update};

use crate::delivery::trusted_delivery::client::insecure::crypto::{Kdf, KdfError};

impl<D> Kdf for Hkdf<D>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    fn new(key_material: &[u8]) -> Result<Self, KdfError> {
        Ok(Self::new(Some(b"trusted delivery"), key_material))
    }

    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), KdfError> {
        Self::expand(self, info, output).or(Err(KdfError))
    }
}
