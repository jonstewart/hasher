//! The canonical 36-byte TLSH digest and its hex transport form.

use crate::error::Result;

/// Length of a canonical digest in bytes.
pub const DIGEST_LENGTH: usize = 36;

/// Length of the hex transport form: `"T1"` and 70 hex digits.
pub const HEX_LENGTH: usize = 72;

/// A TLSH digest in canonical form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TlshDigest(pub [u8; DIGEST_LENGTH]);

impl TlshDigest {
    /// The null digest.
    pub const NULL: Self = Self([0; DIGEST_LENGTH]);

    /// Parse the hex transport form.
    pub fn from_hex(_s: &str) -> Result<Self> {
        Ok(Self::NULL)
    }

    /// The hex transport form.
    pub fn to_hex(&self) -> String {
        String::new()
    }
}
