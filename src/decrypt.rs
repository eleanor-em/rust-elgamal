// Decryption logic for rust-elgamal.
// Copyright 2021 Eleanor McMurtry
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};

use crate::{Ciphertext, EncryptionKey, random_scalar};
use core::fmt::{Debug, Formatter};

/// An ElGamal decryption key (also called a private key in other implementations).
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize))]
pub struct DecryptionKey {
    pub(crate) secret: Scalar,
    #[cfg_attr(feature = "enable-serde", serde(skip_serializing))]
    pub(crate) ek: EncryptionKey,
}

impl DecryptionKey {
    /// Generate a new ElGamal decryption key using the randomness source `rng`, together with
    /// its corresponding encryption key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use rust_elgamal::DecryptionKey;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let dec_key = DecryptionKey::new(&mut rng);
    /// ```
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let secret = random_scalar(&mut rng);
        let ek = EncryptionKey(&secret * &RISTRETTO_BASEPOINT_TABLE);
        Self { secret, ek }
    }

    /// Decrypt the ciphertext `ct`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use rust_elgamal::{DecryptionKey, GENERATOR_TABLE, Scalar};
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let dec_key = DecryptionKey::new(&mut rng);
    ///
    /// let m = &Scalar::from(5u32) * &GENERATOR_TABLE;
    /// let ct = dec_key.encryption_key().encrypt(m, &mut rng);
    /// let decrypted = dec_key.decrypt(ct);
    /// assert_eq!(m, decrypted);
    /// ```
    pub fn decrypt(&self, ct: Ciphertext) -> RistrettoPoint {
        ct.1 - ct.0 * &self.secret
    }

    /// Retrieve the encryption key corresponding to this decryption key.
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.ek
    }
}

impl Debug for DecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "DecryptionKey({:?})", self.secret)
    }
}

// Conversion traits

impl From<Scalar> for DecryptionKey {
    fn from(secret: Scalar) -> Self {
        let ek = EncryptionKey(&secret * &RISTRETTO_BASEPOINT_TABLE);
        Self { secret, ek }
    }
}

impl AsRef<Scalar> for DecryptionKey {
    fn as_ref(&self) -> &Scalar {
        &self.secret
    }
}

// serde traits

// Here we want to deserialise the decryption key, then create its corresponding encryption key.
#[cfg(feature = "enable-serde")]
impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct DecryptionKeyVisitor;

        impl<'de> Visitor<'de> for DecryptionKeyVisitor {
            type Value = DecryptionKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid ElGamal decryption key")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<DecryptionKey, A::Error>
                where A: serde::de::SeqAccess<'de>
            {
                let secret = seq.next_element()?
                    .ok_or(serde::de::Error::invalid_length(0, &"expected decryption key (32 bytes)"))?;
                let ek = EncryptionKey(&secret * &RISTRETTO_BASEPOINT_TABLE);
                Ok(DecryptionKey { secret, ek })
            }
        }

        deserializer.deserialize_tuple(32, DecryptionKeyVisitor)
    }
}

#[cfg(feature = "enable-serde")]
#[cfg(test)]
mod tests {
    use crate::DecryptionKey;
    use rand::prelude::StdRng;
    use rand_core::SeedableRng;

    #[test]
    fn serde_decryption_key() {
        const N: usize = 100;

        let mut rng = StdRng::from_entropy();

        for _ in 0..N {
            let dk = DecryptionKey::new(&mut rng);
            let encoded = bincode::serialize(&dk).unwrap();

            // Check we aren't accidentally encoding the encryption key as well
            assert_eq!(encoded.len(), 32);

            let decoded = bincode::deserialize(&encoded).unwrap();
            assert_eq!(dk, decoded);
        }
    }
}
