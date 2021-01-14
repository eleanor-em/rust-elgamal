// Encryption logic for rust-elgamal.
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

use core::fmt::{Formatter, Debug};

use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand_core::{RngCore, CryptoRng};

#[cfg(feature = "enable-serde")]
use serde::{Serialize, Deserialize};

use crate::{Ciphertext, DecryptionKey};
use crate::util::random_scalar;

/// An ElGamal encryption key (also called a public key in other implementations).
/// To create a new encryption key, see [DecryptionKey](crate::decrypt::DecryptionKey).
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct EncryptionKey(pub(crate) RistrettoPoint);

impl EncryptionKey {
    /// Encrypt `mG` with a randomly-generated blinding factor, where `G` is the group generator.
    ///
    /// This is computationally intensive to decrypt to the original scalar, and not relevant to
    /// the majority of users. This function takes advantage of a fast implementation for multiple
    /// multiplications in `curve25519-dalek`.
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
    /// let enc_key = dec_key.encryption_key();
    ///
    /// let m = Scalar::from(5u32);
    /// let encrypted = enc_key.exp_encrypt(m, &mut rng);
    /// ```
    pub fn exp_encrypt<R: RngCore + CryptoRng>(&self, m: Scalar, mut rng: R) -> Ciphertext {
        self.exp_encrypt_with(m, random_scalar(&mut rng))
    }

    /// Encrypt `mG` with the blinding factor `r`, where `G` is the group generator.
    ///
    /// This is computationally intensive to decrypt to the original scalar, and not relevant to
    /// the majority of users. This function takes advantage of a fast implementation for multiple
    /// multiplications in `curve25519-dalek`.
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
    /// let enc_key = dec_key.encryption_key();
    ///
    /// let m = Scalar::from(5u32);
    /// let r = Scalar::from(10u32);
    /// let encrypted = enc_key.exp_encrypt_with(m, r);
    /// ```
    pub fn exp_encrypt_with(&self, m: Scalar, r: Scalar) -> Ciphertext {
        let c1 = &r * &RISTRETTO_BASEPOINT_TABLE;
        // mG + rY
        let c2 = RistrettoPoint::multiscalar_mul(&[m, r], &[RISTRETTO_BASEPOINT_POINT, self.0]);
        Ciphertext(c1, c2)
    }

    /// Encrypt the curve point `m` with a randomly-generated blinding factor.
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
    /// let enc_key = dec_key.encryption_key();
    ///
    /// let m = &Scalar::from(5u32) * &GENERATOR_TABLE;
    /// let encrypted = enc_key.encrypt(m, &mut rng);
    /// ```
    pub fn encrypt<R: RngCore + CryptoRng>(&self, m: RistrettoPoint, mut rng: R) -> Ciphertext {
        self.encrypt_with(m, random_scalar(&mut rng))
    }

    /// Encrypt the curve point `m` with the blinding factor `r`.
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
    /// let enc_key = dec_key.encryption_key();
    ///
    /// let m = &Scalar::from(5u32) * &GENERATOR_TABLE;
    /// let r = Scalar::from(10u32);
    /// let encrypted = enc_key.encrypt_with(m, r);
    /// ```
    pub fn encrypt_with(&self, m: RistrettoPoint, r: Scalar) -> Ciphertext {
        let c1 = &r * &RISTRETTO_BASEPOINT_TABLE;
        let c2 = m + r * &self.0;
        Ciphertext(c1, c2)
    }

    /// Re-randomise the ciphertext `ct` with a randomly-generated blinding factor.
    /// This will generate a new encryption of the same curve point.
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
    /// let enc_key = dec_key.encryption_key();
    ///
    /// let m = &Scalar::from(5u32) * &GENERATOR_TABLE;
    /// let ct1 = enc_key.encrypt(m, &mut rng);
    /// let ct2 = enc_key.rerandomise(ct1, &mut rng);
    /// assert_eq!(dec_key.decrypt(ct1), dec_key.decrypt(ct2));
    /// ```
    pub fn rerandomise<R: RngCore + CryptoRng>(&self, ct: Ciphertext, mut rng: R) -> Ciphertext {
        self.rerandomise_with(ct, random_scalar(&mut rng))
    }


    /// Re-randomise the ciphertext `ct` with the provided blinding factor.
    /// This will generate a new encryption of the same curve point.
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
    /// let enc_key = dec_key.encryption_key();
    ///
    /// let m = &Scalar::from(5u32) * &GENERATOR_TABLE;
    /// let ct1 = enc_key.encrypt(m, &mut rng);
    ///
    /// let r = Scalar::from(10u32);
    /// let ct2 = enc_key.rerandomise_with(ct1, r);
    ///
    /// assert_eq!(dec_key.decrypt(ct1), dec_key.decrypt(ct2));
    /// ```
    pub fn rerandomise_with(&self, ct: Ciphertext, r: Scalar) -> Ciphertext {
        let c1 = ct.0 + &r * &RISTRETTO_BASEPOINT_TABLE;
        let c2 = ct.1 + &self.0 * r;
        Ciphertext(c1, c2)
    }
}

impl Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "EncryptionKey({:?})", self.0.compress())
    }
}

// Conversion traits

impl From<DecryptionKey> for EncryptionKey {
    fn from(dk: DecryptionKey) -> Self {
        dk.ek
    }
}

impl From<RistrettoPoint> for EncryptionKey {
    fn from(y: RistrettoPoint) -> Self {
        Self(y)
    }
}

impl AsRef<RistrettoPoint> for EncryptionKey {
    fn as_ref(&self) -> &RistrettoPoint {
        &self.0
    }
}
