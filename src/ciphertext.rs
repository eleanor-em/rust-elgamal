// Ciphertext definitions for rust-elgamal.
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

use core::fmt::{Debug, Formatter};
use core::ops::{Add, Neg, Mul, Sub};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::scalar::Scalar;

#[cfg(feature = "enable-serde")]
use serde::{Serialize, Deserialize};

/// An ElGamal ciphertext.
///
/// Represented as a pair of the form (rG, M + rY) where r is a blinding factor, G is the group
/// generator, M is the message, and Y is the public key.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Ciphertext(pub(crate) RistrettoPoint, pub(crate) RistrettoPoint);

impl Ciphertext {
    /// Returns the pair-of-points representation of the ciphertext. Intended for advanced use only.
    pub fn inner(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.0, self.1)
    }
}

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ciphertext({:?}, {:?})", self.0.compress(), self.1.compress())
    }
}

// Conversion traits

impl From<(RistrettoPoint, RistrettoPoint)> for Ciphertext {
    fn from(pair: (RistrettoPoint, RistrettoPoint)) -> Self {
        Self(pair.0, pair.1)
    }
}

// Arithmetic traits for homomorphisms

impl Identity for Ciphertext {
    fn identity() -> Self {
        Self(RistrettoPoint::identity(), RistrettoPoint::identity())
    }
}

impl Add for Ciphertext {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl Add for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext(&self.0 + &rhs.0, &self.1 + &rhs.1)
    }
}

impl Add<&Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: &Ciphertext) -> Self::Output {
        Ciphertext(self.0 + &rhs.0, self.1 + &rhs.1)
    }
}

impl Add<Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: Ciphertext) -> Self::Output {
        Ciphertext(&self.0 + rhs.0, &self.1 + rhs.1)
    }
}

impl Sub for Ciphertext {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Ciphertext(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl Sub for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, rhs: Self) -> Self::Output {
        Ciphertext(&self.0 - &rhs.0, &self.1 - &rhs.1)
    }
}

impl Sub<&Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn sub(self, rhs: &Ciphertext) -> Self::Output {
        Ciphertext(self.0 - &rhs.0, self.1 - &rhs.1)
    }
}

impl Sub<Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, rhs: Ciphertext) -> Self::Output {
        Ciphertext(&self.0 - rhs.0, &self.1 - rhs.1)
    }
}

impl Neg for Ciphertext {
    type Output = Ciphertext;

    fn neg(self) -> Self::Output {
        Ciphertext(-self.0, -self.1)
    }
}

impl Neg for &Ciphertext {
    type Output = Ciphertext;

    fn neg(self) -> Self::Output {
        Ciphertext(-self.0, -self.1)
    }
}

impl Mul<Scalar> for Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Ciphertext(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul<Scalar> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Ciphertext(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul<&Scalar> for Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Ciphertext(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul<&Scalar> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Ciphertext(self.0 * rhs, self.1 * rhs)
    }
}

#[cfg(feature = "enable-serde")]
#[cfg(test)]
mod tests {
    use rand::prelude::StdRng;
    use rand_core::SeedableRng;

    use crate::{DecryptionKey, RistrettoPoint};

    #[test]
    fn serde_ciphertext() {
        const N: usize = 100;

        let mut rng = StdRng::from_entropy();
        let dk = DecryptionKey::new(&mut rng);

        for _ in 0..N {
            let ct = dk.encryption_key().encrypt(RistrettoPoint::random(&mut rng), &mut rng);
            let encoded = bincode::serialize(&ct).unwrap();
            assert_eq!(encoded.len(), 64);

            let decoded = bincode::deserialize(&encoded).unwrap();
            assert_eq!(ct, decoded);
        }
    }
}
