use crate::ec::{CurvePoint, Scalar, random_scalar};
use curve25519_dalek::traits::Identity;
use std::ops::{Add, Sub, Neg};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, Serializer, Deserializer};
#[cfg(feature = "serde")]
use serde::de::Visitor;

use rand::SeedableRng;
use rand::prelude::StdRng;
use std::cell::RefCell;
use std::fmt::Debug;
use std::fmt::Formatter;

/// An ElGamal public key. Contains a secure randomness source for generating ciphertexts.
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) y: CurvePoint,
    rng: RefCell<StdRng>,
}

impl PublicKey {
    /// Create a public key from the curve point and a randomness source.
    pub(crate) fn new(y: CurvePoint, rng: StdRng) -> Self {
        Self {
            y,
            rng: RefCell::new(rng),
        }
    }

    /// Returns the curve point that the key represents.
    ///
    /// Should not be relevant to most users.
    pub fn curve_point(&self) -> &CurvePoint {
        &self.y
    }

    /// Encrypt the provided curve point with a randomly-generated blinding factor.
    /// Not thread-safe.
    pub fn encrypt(&self, m: CurvePoint) -> Ciphertext {
        let mut rng = self.rng.borrow_mut();
        self.encrypt_with(m, random_scalar(&mut *rng))
    }

    /// Encrypt the provided curve point with the provided blinding factor.
    /// Not thread-safe.
    pub fn encrypt_with(&self, m: CurvePoint, r: Scalar) -> Ciphertext {
        let c1 = CurvePoint::generator() * r;
        let c2 = m + &self.y * r;
        Ciphertext(c1, c2)
    }

    /// Re-randomise the provided ciphertext with a randomly-generated blinding factor.
    /// This will generate a new encryption of the same message.
    /// Not thread-safe.
    pub fn rerand(&self, ct: Ciphertext) -> Ciphertext {
        let mut rng = self.rng.borrow_mut();
        self.rerand_with(ct, random_scalar(&mut *rng))
    }


    /// Re-randomise the provided ciphertext with the provided blinding factor.
    /// This will generate a new encryption of the same message.
    /// Not thread-safe.
    pub fn rerand_with(&self, ct: Ciphertext, r: Scalar) -> Ciphertext {
        let c1 = &ct.0 + CurvePoint::generator() * r;
        let c2 = &ct.1 + &self.y * r;
        Ciphertext(c1, c2)
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:?})", self.y)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.y == other.y
    }
}

impl Eq for PublicKey {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrivateKey(pub(crate) Scalar);

impl PrivateKey {
    pub(crate) fn new(x: Scalar) -> Self {
        Self(x)
    }

    pub fn decrypt(&self, ct: Ciphertext) -> CurvePoint {
        ct.1 - ct.0 * &self.0
    }

    pub fn secret(&self) -> &Scalar {
        &self.0
    }
}

/// An ElGamal key-pair.
/// Contains a public key (for encryption) and a private key (for decryption).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl Keypair {
    /// Generate a new key-pair with a randomly-generated scalar for the secret.
    /// This should be used in the majority of cases.
    pub fn new() -> Self {
        let mut rng = StdRng::from_entropy();
        let secret = random_scalar(&mut rng);
        Self {
            public: PublicKey::new(CurvePoint::generator() * secret, rng),
            private: PrivateKey::new(secret),
        }
    }

    /// Generate a new key-pair with a provided secret.
    /// Useful for e.g. reconstructing a key-pair from a known secret.
    pub fn from_secret(secret: Scalar) -> Self {
        let rng = StdRng::from_entropy();
        Self {
            public: PublicKey::new(CurvePoint::generator() * secret, rng),
            private: PrivateKey::new(secret),
        }
    }
}

/// An ElGamal ciphertext, represented as a pair of the form (rG, M + rY) where G is the generator,
/// M is the message, Y is the public key, and r is a blinding factor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext(pub(crate) CurvePoint, pub(crate) CurvePoint);

// Arithmetic traits for homomorphism

impl Identity for Ciphertext {
    fn identity() -> Self {
        Self(CurvePoint::identity(), CurvePoint::identity())
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

// serde traits

// This stuff is really just boilerplate to tell serde "we only want to serialise the public key".
#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        tup.serialize_element(&self.y)?;
        tup.end()
    }
}

// Here we want to deserialise the public key, then create a secure RNG to attach to it.
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid ElGamal public key")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<PublicKey, A::Error>
                where A: serde::de::SeqAccess<'de>
            {
                let y = seq.next_element()?
                    .ok_or(serde::de::Error::invalid_length(0, &"expected public key (32 bytes)"))?;
                let rng = RefCell::new(StdRng::from_entropy());
                Ok(PublicKey { y, rng })
            }
        }

        deserializer.deserialize_tuple(32, PublicKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::Keypair;
    use crate::ec::CurvePoint;

    #[test]
    fn encrypt_decrypt() {
        let keypair = Keypair::new();
        let point = CurvePoint::encode_uint(2385617246146141).unwrap();
        let encrypted = keypair.public.encrypt(point.clone());
        let decrypted = keypair.private.decrypt(encrypted);

        assert_eq!(point, decrypted);
    }

    #[test]
    fn point_homomorphism() {
        let keypair = Keypair::new();

        let a = 82165714325264u128;
        let b = 12844615235731u128;

        let point_a = CurvePoint::encode_uint(a).unwrap();
        let point_b = CurvePoint::encode_uint(b).unwrap();
        let point_c = &point_a + &point_b;

        let encrypted_a = keypair.public.encrypt(point_a);
        let encrypted_b = keypair.public.encrypt(point_b);
        let encrypted_c = encrypted_a + encrypted_b;

        let decrypted = keypair.private.decrypt(encrypted_c);

        assert_eq!(point_c, decrypted);
    }

    #[test]
    fn rerandomisation() {
        let keypair = Keypair::new();
        let point = CurvePoint::encode_uint(2385617246146141).unwrap();
        let encrypted = keypair.public.encrypt(point.clone());
        let re_encrypted = keypair.public.rerand(encrypted.clone());
        let decrypted = keypair.private.decrypt(re_encrypted.clone());

        assert_ne!(encrypted, re_encrypted);
        assert_eq!(point, decrypted);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_pubkey() {
        use bincode;

        let keypair = Keypair::new();
        let encoded = bincode::serialize(&keypair.public).unwrap();
        let decoded = bincode::deserialize(&encoded).unwrap();

        assert_eq!(keypair.public, decoded);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_keypair() {
        use bincode;

        let keypair = Keypair::new();
        let encoded = bincode::serialize(&keypair).unwrap();
        let decoded = bincode::deserialize(&encoded).unwrap();

        assert_eq!(keypair, decoded);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_ciphertext() {
        use crate::elgamal::Keypair;
        use bincode;

        let keypair = Keypair::new();
        let elem = CurvePoint::encode_uint(2385617246146141).unwrap();
        let encrypted = keypair.public.encrypt(elem.clone());

        let encoded = bincode::serialize(&encrypted).unwrap();
        let decoded = bincode::deserialize(&encoded).unwrap();

        assert_eq!(encrypted, decoded);
    }
}
