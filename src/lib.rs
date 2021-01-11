pub mod ec;
pub mod elgamal;

use std::fmt::{Formatter, Display};
use std::error::Error;

/// Error states for ElGamal operations
#[derive(Clone, Copy, Debug)]
pub enum ElGamalError {
    Encoding,
    Decoding,
    TooLarge,
}

impl Display for ElGamalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for ElGamalError {}
