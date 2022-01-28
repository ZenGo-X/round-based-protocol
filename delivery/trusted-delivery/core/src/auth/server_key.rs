use crypto_mac::{Mac, NewMac};
use generic_array::GenericArray;
use rand::rngs::OsRng;
use rand::RngCore;

use thiserror::Error;
use typenum::Unsigned;

use crate::crypto::{CryptoSuite, Serializable};
use crate::generic_array_ext::Sum;

use super::challenge::*;

/// Cryptographic key that can be used to produce cryptographic [authentication token](Witness)
///
/// Intentionally server key cannot be serialized, so any [Witness] get invalidated after server
/// reload.
pub struct ServerKey<C: CryptoSuite>(Box<GenericArray<u8, C::MacKeySize>>);

impl<C: CryptoSuite> ServerKey<C> {
    /// Generates server key from system source of randomness
    pub fn generate() -> Self {
        let mut key = Box::new(GenericArray::<u8, C::MacKeySize>::default());
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Attests that client with `public_key` has signed freshly generated `challenge`
    ///
    /// Returns `Witness` if signature is valid. In any case, `challenge` is consumed and cannot be
    /// reused anymore.
    pub fn attest(
        &self,
        public_key: &C::VerificationKey,
        challenge: Challenge<C>,
        response: &C::Signature,
    ) -> Result<Witness<C>, InvalidResponse> {
        challenge.validate_response(public_key, response)?;

        let tag = self.calc_mac(&public_key.to_bytes()).finalize();

        Ok(Witness::new(public_key, tag))
    }

    fn calc_mac(&self, bytes: &[u8]) -> C::Mac {
        let mut mac = C::Mac::new(&self.0);
        mac.update(bytes);
        mac
    }

    /// Verifies that `witness` is valid and returns public key it was issued for
    pub fn verify(&self, witness: &Witness<C>) -> Result<C::VerificationKey, WitnessNotValid> {
        let public_key_unverified = witness.public_key_bytes_unverified();
        let tag_unverified = witness.tag_bytes_unverified();

        self.calc_mac(public_key_unverified)
            .verify(tag_unverified)
            .or(Err(WitnessNotValid))?;

        let public_key_verified =
            C::VerificationKey::from_bytes(public_key_unverified).or(Err(WitnessNotValid))?;
        Ok(public_key_verified)
    }
}

/// Cryptographic token attesting that client completed authentication
///
/// Token can be [verified] on server-side using [ServerKey]
///
/// [verified]: ServerKey::verify
#[derive(educe::Educe)]
#[educe(Debug, Default)]
pub struct Witness<C: CryptoSuite>(
    GenericArray<u8, Sum![C::VerificationKeySize, C::MacOutputSize]>,
);

impl<C: CryptoSuite> Witness<C> {
    pub fn new(public_key: &C::VerificationKey, tag: crypto_mac::Output<C::Mac>) -> Self {
        let public_key_size = C::VerificationKeySize::USIZE;

        let mut witness: Self = Default::default();
        witness.0[..public_key_size].copy_from_slice(&public_key.to_bytes());
        witness.0[public_key_size..].copy_from_slice(&tag.into_bytes());

        witness
    }

    fn public_key_bytes_unverified(&self) -> &[u8] {
        let public_key_size = C::VerificationKeySize::USIZE;
        &self.0[..public_key_size]
    }

    fn tag_bytes_unverified(&self) -> &[u8] {
        let public_key_size = C::VerificationKeySize::USIZE;
        &self.0[public_key_size..]
    }
}

impl<C: CryptoSuite> hex::FromHex for Witness<C> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut witness: Self = Default::default();
        hex::decode_to_slice(hex, &mut witness.0)?;
        Ok(witness)
    }
}

impl<C: CryptoSuite> AsRef<[u8]> for Witness<C> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Error indicating that witness doesn't match given public key
#[derive(Debug, Error)]
#[error("witness is not valid")]
pub struct WitnessNotValid;
