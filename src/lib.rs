// Library definitions for rust-elgamal.
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

#![no_std]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]

mod ciphertext;
mod decrypt;
mod encrypt;

use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_COMPRESSED};
use curve25519_dalek::ristretto::RistrettoBasepointTable;

pub use curve25519_dalek::scalar::Scalar;
pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::ristretto::CompressedRistretto;

pub use curve25519_dalek::traits::Identity;
pub use curve25519_dalek::traits::IsIdentity;
pub use curve25519_dalek::traits::MultiscalarMul;

pub use ciphertext::Ciphertext;
pub use decrypt::DecryptionKey;
pub use encrypt::EncryptionKey;

/// The group generator as a single point.
/// If you're trying to create a scalar multiple of the generator, you probably want
/// [GENERATOR_TABLE](crate::GENERATOR_TABLE) instead.
pub const GENERATOR_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// The group generator as a single point, compressed for transit.
/// If you're trying to create a scalar multiple of the generator, you probably want
/// [GENERATOR_TABLE](crate::GENERATOR_TABLE) instead.
pub const GENERATOR_POINT_COMPRESSED: CompressedRistretto = RISTRETTO_BASEPOINT_COMPRESSED;

/// The group generator as a table of precomputed multiples. This is the most efficient way to
/// produce a scalar multiple of the generator.
pub const GENERATOR_TABLE: RistrettoBasepointTable = RISTRETTO_BASEPOINT_TABLE;

#[cfg(test)]
mod tests {
    use rand::prelude::StdRng;
    use rand_core::SeedableRng;

    use crate::{DecryptionKey, RistrettoPoint};

    // Test that encrypting a point and decrypting the result does not change a point.
    #[test]
    fn encrypt_decrypt() {
        const N: usize = 100;

        let mut rng = StdRng::from_entropy();
        let dk = DecryptionKey::new(&mut rng);
        let ek = dk.encryption_key();

        for _ in 0..N {
            let m = RistrettoPoint::random(&mut rng);
            let ct = ek.encrypt(m, &mut rng);
            let decrypted = dk.decrypt(ct);
            assert_eq!(m, decrypted);
        }
    }

    // Test that re-randomising an encrypted point does not change the decrypted result.
    #[test]
    fn rerandomisation() {
        const N: usize = 100;

        let mut rng = StdRng::from_entropy();
        let dk = DecryptionKey::new(&mut rng);
        let ek = dk.encryption_key();
        let m = RistrettoPoint::random(&mut rng);
        let ct = ek.encrypt(m, &mut rng);

        for _ in 0..N {
            let ct = ek.rerandomise(ct, &mut rng);
            let decrypted = dk.decrypt(ct);
            assert_eq!(m, decrypted);
        }
    }

    // Test that the decrypted sum of two ciphertexts is equal to the sum of the original points.
    #[test]
    fn homomorphism() {
        const N: usize = 100;

        let mut rng = StdRng::from_entropy();
        let dk = DecryptionKey::new(&mut rng);
        let ek = dk.encryption_key();

        for _ in 0..N {
            let m1 = RistrettoPoint::random(&mut rng);
            let m2 = RistrettoPoint::random(&mut rng);
            let sum = m1 + m2;
            let ct1 = ek.encrypt(m1, &mut rng);
            let ct2 = ek.encrypt(m2, &mut rng);
            let ct_sum = ct1 + ct2;
            let decrypted = dk.decrypt(ct_sum);
            assert_eq!(sum, decrypted);
        }
    }
}
