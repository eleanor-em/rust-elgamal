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
/// Represented as a pair of the form (rG, M + rY) where r is a blinding factor, G is the group
/// generator, M is the message, and Y is the public key.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Ciphertext(pub(crate) RistrettoPoint, pub(crate) RistrettoPoint);

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ciphertext({:?}, {:?})", self.0.compress(), self.1.compress())
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
        Ciphertext(-self.0.clone(), -self.1.clone())
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
