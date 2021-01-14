// Utilities for rust-elgamal.
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

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{RngCore, CryptoRng};

/// Generate a random scalar from the provided randomness source.
///
/// **Note:** Unfortunately [curve25519-dalek](https://docs.rs/curve25519-dalek/3.0.2/curve25519_dalek/)
/// uses an old version of `rand`, so we need to copy its implementation of `Scalar::random`.
/// See also <https://github.com/dalek-cryptography/curve25519-dalek/pull/338>.
///
/// **Source:** <https://github.com/dalek-cryptography/curve25519-dalek/blob/master/src/scalar.rs>
pub fn random_scalar<R: RngCore + CryptoRng>(mut rng: R) -> Scalar {
    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

/// Generate a random curve point from the provided randomness source.
///
/// **Note:** Unfortunately [curve25519-dalek](https://docs.rs/curve25519-dalek/3.0.2/curve25519_dalek/)
/// uses an old version of `rand`, so we need to copy its implementation of `RistrettoPoint::random`.
/// See also <https://github.com/dalek-cryptography/curve25519-dalek/pull/338>.
///
/// **Source:** <https://github.com/dalek-cryptography/curve25519-dalek/blob/master/src/ristretto.rs>
pub fn random_point<R: RngCore + CryptoRng>(mut rng: R) -> RistrettoPoint {
    let mut uniform_bytes = [0u8; 64];
    rng.fill_bytes(&mut uniform_bytes);
    RistrettoPoint::from_uniform_bytes(&uniform_bytes)
}
