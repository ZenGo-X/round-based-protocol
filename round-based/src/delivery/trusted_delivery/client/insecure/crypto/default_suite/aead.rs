use aead::{AeadCore, AeadInPlace, NewAead};
use generic_array::{ArrayLength, GenericArray};
use never::Never;
use phantom_type::PhantomType;

use crate::delivery::trusted_delivery::client::insecure::crypto::{
    DecryptionKey, EncryptionKey, EncryptionScheme,
};

pub struct AeadEncryptionScheme<K> {
    cannot_be_constructed: Never,
    _ph: PhantomType<K>,
}

impl<K> EncryptionScheme for AeadEncryptionScheme<K>
where
    K: NewAead + AeadInPlace,
{
    type Key = GenericArray<u8, K::KeySize>;
    type EncryptionKey = AeadKey<K, Encryption>;
    type DecryptionKey = AeadKey<K, Decryption>;

    fn encryption_key(key: &Self::Key) -> Self::EncryptionKey {
        AeadKey {
            counter: Some(Counter::zero()),
            key: K::new(key),
            _purpose: PhantomType::new(),
        }
    }

    fn decryption_key(key: &Self::Key) -> Self::DecryptionKey {
        AeadKey {
            counter: Some(Counter::zero()),
            key: K::new(key),
            _purpose: PhantomType::new(),
        }
    }
}

pub struct Encryption(Never);
pub struct Decryption(Never);

pub struct AeadKey<K: AeadCore, P> {
    counter: Option<Counter<K::NonceSize>>,
    key: K,
    _purpose: PhantomType<P>,
}

#[cfg(test)]
impl<K, P> Clone for AeadKey<K, P>
where
    K: AeadCore + Clone,
{
    fn clone(&self) -> Self {
        Self {
            counter: self.counter.clone(),
            key: self.key.clone(),
            _purpose: PhantomType::new(),
        }
    }
}

impl<K> EncryptionKey for AeadKey<K, Encryption>
where
    K: AeadInPlace,
{
    type TagSize = K::TagSize;
    type Error = aead::Error;

    fn encrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Self::Error> {
        let counter = self.counter.clone().ok_or(aead::Error)?;
        let tag =
            self.key
                .encrypt_in_place_detached(counter.to_bytes(), associated_data, buffer)?;
        self.counter = counter.checked_increment();
        Ok(tag)
    }
}

impl<K> DecryptionKey for AeadKey<K, Decryption>
where
    K: AeadInPlace,
{
    type TagSize = K::TagSize;
    type Error = aead::Error;

    fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Self::Error> {
        let counter = self.counter.clone().ok_or(aead::Error)?;
        self.key
            .decrypt_in_place_detached(counter.to_bytes(), associated_data, buffer, tag)?;
        self.counter = counter.checked_increment();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Counter<S: ArrayLength<u8>> {
    bytes: GenericArray<u8, S>,
}

impl<S: ArrayLength<u8>> Counter<S> {
    pub fn zero() -> Self {
        Self {
            bytes: GenericArray::default(),
        }
    }

    pub fn checked_increment(mut self) -> Option<Self> {
        for (i, byte) in self.bytes.iter_mut().rev().enumerate() {
            let (new_value, overflowed) = byte.overflowing_add(1);
            *byte = new_value;
            if !overflowed {
                break;
            } else if i + 1 == S::USIZE {
                return None;
            }
        }

        Some(self)
    }

    pub fn to_bytes(&self) -> &GenericArray<u8, S> {
        &self.bytes
    }
}

#[cfg(test)]
mod counter_tests {
    use generic_array::GenericArray;

    type Counter = super::Counter<generic_array::typenum::U2>;

    #[test]
    fn counter_increments() {
        let mut i = Counter::zero();
        for j in 1..=257u16 {
            let next_value = i.clone().checked_increment().unwrap();
            assert_ne!(i, next_value);
            assert_ne!(Counter::zero(), next_value);
            assert_eq!(
                next_value.bytes.as_slice()[1],
                (j & 0xFF) as u8,
                "expected {}",
                j
            );
            assert_eq!(
                next_value.bytes.as_slice()[0],
                (j >> 8) as u8,
                "expected {}",
                j
            );

            i = next_value;
        }
    }

    #[test]
    fn overflowing_is_checked() {
        let counter = Counter {
            bytes: GenericArray::from([0xff, 0xff]),
        };
        assert_eq!(counter.checked_increment(), None);
    }
}

#[cfg(test)]
mod aead_key_tests {
    use rand::rngs::OsRng;
    use rand::{Rng, RngCore};

    use crate::delivery::trusted_delivery::client::insecure::crypto::{
        DecryptionKey, EncryptionKey, EncryptionScheme,
    };

    type EncryptionScheme = super::AeadEncryptionScheme<aes_gcm::Aes256Gcm>;

    fn generate_keys<S: EncryptionScheme, R: RngCore>(
        rng: &mut R,
    ) -> (S::EncryptionKey, S::DecryptionKey) {
        let mut key = S::Key::default();
        rng.fill_bytes(key.as_mut());

        let ek = S::encryption_key(&key);
        let dk = S::decryption_key(&key);

        (ek, dk)
    }

    #[test]
    fn encrypts_decrypts() {
        let mut rng = OsRng;

        let (mut ek, mut dk) = generate_keys::<EncryptionScheme, _>(&mut rng);

        let mut plaintext_buffer = vec![0u8; 4096];
        let mut decryption_buffer = vec![0u8; 4096];
        for _ in 0..25 {
            let plaintext_len = rng.gen_range(10..=4096usize);
            let plaintext = &mut plaintext_buffer[0..plaintext_len];
            rng.fill_bytes(plaintext);

            let ciphertext = &mut decryption_buffer[0..plaintext_len];
            ciphertext.copy_from_slice(plaintext);

            let tag = ek.encrypt(&[], ciphertext).unwrap();
            dk.decrypt(&[], ciphertext, &tag).unwrap();

            assert_eq!(plaintext, ciphertext);
        }
    }

    #[test]
    fn two_identical_plaintexts_result_into_different_ciphertext() {
        let mut rng = OsRng;

        let (mut ek, _dk) = generate_keys::<EncryptionScheme, _>(&mut rng);

        let mut msg1 = [0u8; 100];
        let mut msg2 = [0u8; 100];
        rng.fill_bytes(&mut msg1);
        msg2.copy_from_slice(&msg1);

        let _tag1 = ek.encrypt(&[], &mut msg1).unwrap();
        let _tag2 = ek.encrypt(&[], &mut msg2).unwrap();

        assert_ne!(msg1, msg2);
    }

    #[test]
    fn doesnt_decrypt_message_with_mismatching_tag() {
        let mut rng = OsRng;

        let (mut ek, mut dk) = generate_keys::<EncryptionScheme, _>(&mut rng);

        let mut msg1 = [0u8; 100];
        let mut msg2 = [0u8; 100];
        rng.fill_bytes(&mut msg1);
        msg2.copy_from_slice(&msg1);

        let _tag1 = ek.encrypt(&[], &mut msg1).unwrap();
        let tag2 = ek.encrypt(&[], &mut msg2).unwrap();

        let result = dk.decrypt(&[], &mut msg1, &tag2);
        assert!(result.is_err());
    }

    #[test]
    fn doesnt_decrypt_message_with_mismatching_ad() {
        let mut rng = OsRng;

        let (mut ek, mut dk) = generate_keys::<EncryptionScheme, _>(&mut rng);

        let mut msg = [0u8; 100];
        rng.fill_bytes(&mut msg);

        let tag = ek.encrypt(b"additional data", &mut msg).unwrap();

        let result = dk.decrypt(b"different additional data", &mut msg, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn doesnt_decrypt_out_of_order_ciphertext() {
        let mut rng = OsRng;

        let (mut ek, mut dk) = generate_keys::<EncryptionScheme, _>(&mut rng);

        let mut msg1 = [0u8; 100];
        let mut msg2 = [0u8; 100];
        rng.fill_bytes(&mut msg1);
        rng.fill_bytes(&mut msg2);

        let _tag1 = ek.encrypt(&[], &mut msg1).unwrap();
        let tag2 = ek.encrypt(&[], &mut msg2).unwrap();

        let result = dk.decrypt(&[], &mut msg2, &tag2);
        assert!(result.is_err());
    }
}
