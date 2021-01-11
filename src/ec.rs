use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::traits::Identity;
use std::iter::Sum;
use std::ops::{AddAssign, Sub, Add, SubAssign, Mul, Neg};
use crate::ElGamalError;
use rand::{CryptoRng, Rng};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// A scalar from the Ristretto elliptic curve group. Used as blinding factors.
pub type Scalar = curve25519_dalek::scalar::Scalar;

pub(crate) fn random_scalar<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}

/// A curve point from the Ristretto elliptic curve group. These represent messages and ciphertexts.
/// To encrypt a message that is NOT a curve point, it must be encoded using one of the associated
/// functions.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CurvePoint(pub(crate) RistrettoPoint);

impl CurvePoint {
    /// Attempt to encode a byte slice as a curve element as follows. The slice must be 29 bytes
    /// or less: the group order is slightly greater than 252 bits, and we use 16 bits of buffer
    /// leaving 236 bits for data.
    pub fn encode_bytes(input: &[u8]) -> Result<Self, ElGamalError> {
        //
        if input.len() > 29 {
            Err(ElGamalError::TooLarge)
        } else {
            let mut bytes = [0u8; 32];
            bytes[..input.len()].copy_from_slice(input);
            Self::encode(&Scalar::from_bytes_mod_order(bytes))
        }
    }

    /// Attempt to encode an unsigned integer as a curve element, using [encode](#method.encode).
    pub fn encode_uint(x: u128) -> Result<Self, ElGamalError> {
        Self::encode(&Scalar::from(x))
    }

    /// Attempt to encode a scalar as a curve element as follows:
    /// 1. Bit-shift the scalar left by 16 bits
    /// 2. Add 1 to the scalar until it successfully encodes as a compressed curve point.
    /// If we do not succeed in finding a successful encoding (with prob. 1 / 2^16), return error.
    /// 16 bits is chosen due to simplifying the maths.
    ///
    /// Ref: https://crypto.stackexchange.com/questions/62966/how-to-securely-map-messages-to-points-on-an-elliptic-curve
    pub fn encode(s: &Scalar) -> Result<Self, ElGamalError> {
        let mut attempts = 0;

        // Shift left by 2 bytes.
        // 16 bits = 2 bytes of buffer room for easy maths.
        let mut bytes = s.to_bytes();
        bytes.rotate_right(2);
        if bytes[0] != 0 || bytes[1] != 0 {
            return Err(ElGamalError::TooLarge);
        }

        let mut s = Scalar::from_bytes_mod_order(bytes);

        loop {
            if let Some(p) = CompressedRistretto(s.to_bytes()).decompress() {
                return Ok(Self(p));
            }

            s += Scalar::one();
            attempts += 1;

            // In this case, we ran out of candidate encodings.
            if attempts >= 1 << 16 {
                return Err(ElGamalError::Encoding);
            }
        }
    }

    /// Decode the curve element as a scalar.
    pub fn decode(&self) -> Scalar {
        // Shift right by 2 bytes, discarding the buffer room.
        let mut bytes = self.0.compress().to_bytes();
        bytes[0] = 0;
        bytes[1] = 0;
        bytes.rotate_left(2);
        Scalar::from_bytes_mod_order(bytes)
    }

    /// Decode the curve element as a byte array.
    pub fn decode_bytes(&self) -> [u8; 29] {
        // TODO: In theory this could support up to 30 bytes with a cleverer bit-shift algo.
        let input = self.decode().to_bytes();
        let mut bytes = [0; 29];
        bytes.copy_from_slice(&input[..29]);
        bytes
    }

    /// Decode the curve element as a 128-bit unsigned integer.
    /// Returns `None` if the scalar encodes an integer too large to fit.
    pub fn decode_u128(&self) -> Option<u128> {
        let mut bytes = self.decode_bytes().to_vec();
        // Verify the high-order bytes are empty
        for i in 16..bytes.len() {
            if bytes[i] != 0 {
                return None;
            }
        }
        // Convert to integer
        bytes.truncate(16);
        Some(bytes.into_iter()
                 .enumerate()
                 .map(|(i, x)| (x as u128) << (8 * i))
                 .sum())
    }

    /// Decode the curve element as a 64-bit unsigned integer.
    /// Returns `None` if the scalar encodes an integer too large to fit.
    pub fn decode_u64(&self) -> Option<u64> {
        let mut bytes = self.decode_bytes().to_vec();
        // Verify the high-order bytes are empty
        for i in 8..bytes.len() {
            if bytes[i] != 0 {
                return None;
            }
        }
        // Convert to integer
        bytes.truncate(8);
        Some(bytes.into_iter()
            .enumerate()
            .map(|(i, x)| (x as u64) << (8 * i))
            .sum())
    }

    /// Decode the curve element as a 32-bit unsigned integer.
    /// Returns `None` if the scalar encodes an integer too large to fit.
    pub fn decode_u32(&self) -> Option<u32> {
        let mut bytes = self.decode_bytes().to_vec();
        // Verify the high-order bytes are empty
        for i in 4..bytes.len() {
            if bytes[i] != 0 {
                return None;
            }
        }
        // Convert to integer
        bytes.truncate(4);
        Some(bytes.into_iter()
            .enumerate()
            .map(|(i, x)| (x as u32) << (8 * i))
            .sum())
    }

    /// Decode the curve element as a 16-bit unsigned integer.
    /// Returns `None` if the scalar encodes an integer too large to fit.
    pub fn decode_u16(&self) -> Option<u16> {
        let bytes = self.decode_bytes().to_vec();
        // Verify the high-order bytes are empty
        for i in 2..bytes.len() {
            if bytes[i] != 0 {
                return None;
            }
        }
        Some((bytes[0] as u16) + ((bytes[1] as u16) << 8))
    }

    /// Decode the curve element as an 8-bit unsigned integer.
    /// Returns `None` if the scalar encodes an integer too large to fit.
    pub fn decode_u8(&self) -> Option<u8> {
        let bytes = self.decode_bytes().to_vec();
        // Verify the high-order bytes are empty
        for i in 1..bytes.len() {
            if bytes[i] != 0 {
                return None;
            }
        }
        Some(bytes[0])
    }

    /// Returns the group generator.
    /// Should not be relevant to most users.
    pub fn generator() -> Self {
        Self(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
    }
}

// Conversion traits

impl From<RistrettoPoint> for CurvePoint {
    fn from(value: RistrettoPoint) -> Self {
        Self(value)
    }
}

impl Into<RistrettoPoint> for CurvePoint {
    fn into(self) -> RistrettoPoint {
        self.0
    }
}

// Numeric traits

impl Identity for CurvePoint {
    fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
}

impl Add for CurvePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        CurvePoint(self.0 + rhs.0)
    }
}

impl Add for &CurvePoint {
    type Output = CurvePoint;

    fn add(self, rhs: Self) -> Self::Output {
        CurvePoint(self.0 + rhs.0)
    }
}

impl Add<&CurvePoint> for CurvePoint {
    type Output = CurvePoint;

    fn add(self, rhs: &CurvePoint) -> Self::Output {
        CurvePoint(self.0 + rhs.0)
    }
}

impl Add<CurvePoint> for &CurvePoint {
    type Output = CurvePoint;

    fn add(self, rhs: CurvePoint) -> Self::Output {
        CurvePoint(self.0 + rhs.0)
    }
}

impl Sub for CurvePoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        CurvePoint(self.0 - rhs.0)
    }
}

impl Sub for &CurvePoint {
    type Output = CurvePoint;

    fn sub(self, rhs: Self) -> Self::Output {
        CurvePoint(self.0 - rhs.0)
    }
}

impl Sub<&CurvePoint> for CurvePoint {
    type Output = CurvePoint;

    fn sub(self, rhs: &Self) -> Self::Output {
        CurvePoint(self.0 - rhs.0)
    }
}

impl Sub<CurvePoint> for &CurvePoint {
    type Output = CurvePoint;

    fn sub(self, rhs: CurvePoint) -> Self::Output {
        CurvePoint(self.0 - rhs.0)
    }
}

impl AddAssign for CurvePoint {
    fn add_assign(&mut self, rhs: CurvePoint) {
        *self = CurvePoint(self.0 + rhs.0);
    }
}

impl SubAssign for CurvePoint {
    fn sub_assign(&mut self, rhs: CurvePoint) {
        *self = Self(self.0 - rhs.0);
    }
}

impl Sum for CurvePoint {
    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl Neg for CurvePoint {
    type Output = CurvePoint;

    fn neg(self) -> Self::Output {
        CurvePoint(-self.0)
    }
}

impl Neg for &CurvePoint {
    type Output = CurvePoint;

    fn neg(self) -> Self::Output {
        CurvePoint(-self.0)
    }
}

impl Mul<Scalar> for CurvePoint {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Mul<&Scalar> for CurvePoint {
    type Output = Self;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Mul<Scalar> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, rhs: Scalar) -> Self::Output {
        CurvePoint(self.0 * rhs)
    }
}


impl Mul<&Scalar> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        CurvePoint(self.0 * rhs)
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use crate::ec::CurvePoint;
    use curve25519_dalek::scalar::Scalar;

    const N: usize = 1000;

    #[test]
    fn u128_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let x = (rng.next_u64() as u128) * 2u128.pow(64)
                + rng.next_u64() as u128;
            let s = CurvePoint::encode_uint(x.into()).unwrap();
            assert_eq!(x, s.decode_u128().unwrap());
        }
    }

    #[test]
    fn u64_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let x = rng.next_u64();
            let s = CurvePoint::encode_uint(x.into()).unwrap();
            assert_eq!(x, s.decode_u64().unwrap());
        }
    }

    #[test]
    fn u32_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let x = rng.next_u32();
            let s = CurvePoint::encode_uint(x.into()).unwrap();
            assert_eq!(x, s.decode_u32().unwrap());
        }
    }

    #[test]
    fn u16_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let x = (rng.next_u32() >> 16) as u16;
            let s = CurvePoint::encode_uint(x.into()).unwrap();
            assert_eq!(x, s.decode_u16().unwrap());
        }
    }

    #[test]
    fn u8_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let x = (rng.next_u32() >> 24) as u8;
            let s = CurvePoint::encode_uint(x.into()).unwrap();
            assert_eq!(x, s.decode_u8().unwrap());
        }
    }

    #[test]
    fn scalar_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let x = Scalar::from(rng.next_u64());
            let p = CurvePoint::encode(&x).unwrap();
            assert_eq!(x, p.decode());
        }
    }

    #[test]
    fn byte_encoding() {
        let mut rng = rand::thread_rng();
        for _ in 0..N {
            let mut bytes = [0; 29];
            rng.fill_bytes(&mut bytes);
            let p = CurvePoint::encode_bytes(&bytes).unwrap();
            assert_eq!(bytes, p.decode_bytes());
        }
    }
}
