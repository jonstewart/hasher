//! Hash algorithm identifiers.
//!
//! The numeric values are bit flags and match the C `SFHASH_HashAlgorithm`
//! enum of libhasher, so the on-disk `HHnn` chunk tags (which encode
//! `log2(type)`) are interoperable.

use std::fmt;

use crate::error::{Error, Result};

/// A hash (or hash-like) field type that can appear in an `.hset` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
pub enum HashType {
    Md5 = 1 << 0,
    Sha1 = 1 << 1,
    Sha2_224 = 1 << 2,
    Sha2_256 = 1 << 3,
    Sha2_384 = 1 << 4,
    Sha2_512 = 1 << 5,
    Sha3_224 = 1 << 6,
    Sha3_256 = 1 << 7,
    Sha3_384 = 1 << 8,
    Sha3_512 = 1 << 9,
    Blake3 = 1 << 10,
    /// ssdeep fuzzy hash (variable length, not storable in a hash set).
    Fuzzy = 1 << 11,
    /// Shannon entropy (8-byte double).
    Entropy = 1 << 12,
    /// File size, 8-byte little-endian unsigned integer.
    Size = 1 << 13,
    QuickMd5 = 1 << 14,
    /// TLSH locality-sensitive digest in libhasher's 36-byte canonical form
    /// (see [`crate::tlsh::TlshDigest`]).
    Tlsh = 1 << 15,
}

impl HashType {
    /// Every type, in ascending bit order.
    pub const ALL: [HashType; 16] = [
        HashType::Md5,
        HashType::Sha1,
        HashType::Sha2_224,
        HashType::Sha2_256,
        HashType::Sha2_384,
        HashType::Sha2_512,
        HashType::Sha3_224,
        HashType::Sha3_256,
        HashType::Sha3_384,
        HashType::Sha3_512,
        HashType::Blake3,
        HashType::Fuzzy,
        HashType::Entropy,
        HashType::Size,
        HashType::QuickMd5,
        HashType::Tlsh,
    ];

    /// The bit-flag value.
    pub const fn bits(self) -> u32 {
        self as u32
    }

    /// `log2(bits)`, the value stored in `HHnn` tags and `RHDR` field types.
    pub const fn log2(self) -> u16 {
        (self as u32).trailing_zeros() as u16
    }

    /// Inverse of [`HashType::bits`].
    pub fn from_bits(bits: u32) -> Option<HashType> {
        HashType::ALL.iter().copied().find(|t| t.bits() == bits)
    }

    /// Inverse of [`HashType::log2`].
    pub fn from_log2(log2: u16) -> Option<HashType> {
        if log2 >= 32 {
            return None;
        }
        HashType::from_bits(1u32 << log2)
    }

    /// Human-readable name (`"SHA-1"`, `"MD5"`, ...).
    pub const fn name(self) -> &'static str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA-1",
            HashType::Sha2_224 => "SHA-2-224",
            HashType::Sha2_256 => "SHA-2-256",
            HashType::Sha2_384 => "SHA-2-384",
            HashType::Sha2_512 => "SHA-2-512",
            HashType::Sha3_224 => "SHA-3-224",
            HashType::Sha3_256 => "SHA-3-256",
            HashType::Sha3_384 => "SHA-3-384",
            HashType::Sha3_512 => "SHA-3-512",
            HashType::Blake3 => "BLAKE3",
            HashType::Fuzzy => "Fuzzy",
            HashType::Entropy => "Entropy",
            HashType::Size => "Size",
            HashType::QuickMd5 => "Quick MD5",
            HashType::Tlsh => "TLSH",
        }
    }

    /// The field name written into `RHDR`/`HHnn` chunks by the reference
    /// encoder (`"md5"`, `"sha1"`, `"sizes"`, ...).
    pub const fn field_name(self) -> &'static str {
        match self {
            HashType::Md5 => "md5",
            HashType::Sha1 => "sha1",
            HashType::Sha2_224 => "sha2_224",
            HashType::Sha2_256 => "sha2_256",
            HashType::Sha2_384 => "sha2_384",
            HashType::Sha2_512 => "sha2_512",
            HashType::Sha3_224 => "sha3_224",
            HashType::Sha3_256 => "sha3_256",
            HashType::Sha3_384 => "sha3_384",
            HashType::Sha3_512 => "sha3_512",
            HashType::Blake3 => "blake3",
            HashType::Fuzzy => "fuzzy",
            HashType::Entropy => "entropy",
            HashType::Size => "sizes",
            HashType::QuickMd5 => "quick_md5",
            HashType::Tlsh => "tlsh",
        }
    }

    /// Byte length of a value of this type; `None` for variable-length types.
    pub const fn length(self) -> Option<usize> {
        match self {
            HashType::Md5 | HashType::QuickMd5 => Some(16),
            HashType::Sha1 => Some(20),
            HashType::Sha2_224 | HashType::Sha3_224 => Some(28),
            HashType::Sha2_256 | HashType::Sha3_256 | HashType::Blake3 => Some(32),
            HashType::Sha2_384 | HashType::Sha3_384 => Some(48),
            HashType::Sha2_512 | HashType::Sha3_512 => Some(64),
            HashType::Entropy | HashType::Size => Some(8),
            HashType::Tlsh => Some(36),
            HashType::Fuzzy => None,
        }
    }

    /// Whether values of this type are cryptographic digests, i.e. uniformly
    /// distributed, which is what makes position prediction worthwhile.
    /// TLSH rows are not: they cluster by their (L, Q) header, and their
    /// sections use the cell index hint instead.
    pub const fn is_digest(self) -> bool {
        !matches!(
            self,
            HashType::Fuzzy | HashType::Entropy | HashType::Size | HashType::Tlsh
        )
    }

    /// Whether this type can be stored as a fixed-width field in an `.hset`.
    pub const fn is_storable(self) -> bool {
        self.length().is_some()
    }

    /// Parse a user-supplied name. Case, hyphens, underscores, and
    /// whitespace are ignored, so `"SHA-1"`, `"sha1"`, `"Sha_1"`, and the
    /// display name `"Quick MD5"` all parse.
    pub fn parse(name: &str) -> Result<HashType> {
        let norm: String = name
            .chars()
            .filter(|c| *c != '-' && *c != '_' && !c.is_whitespace())
            .flat_map(char::to_lowercase)
            .collect();
        let t = match norm.as_str() {
            "md5" => HashType::Md5,
            "sha1" => HashType::Sha1,
            "sha2224" | "sha224" => HashType::Sha2_224,
            "sha2256" | "sha256" => HashType::Sha2_256,
            "sha2384" | "sha384" => HashType::Sha2_384,
            "sha2512" | "sha512" => HashType::Sha2_512,
            "sha3224" => HashType::Sha3_224,
            "sha3256" => HashType::Sha3_256,
            "sha3384" => HashType::Sha3_384,
            "sha3512" => HashType::Sha3_512,
            "blake3" => HashType::Blake3,
            "fuzzy" => HashType::Fuzzy,
            "entropy" => HashType::Entropy,
            "size" | "sizes" => HashType::Size,
            "quickmd5" => HashType::QuickMd5,
            "tlsh" => HashType::Tlsh,
            _ => return Err(Error::input(format!("unknown hash type '{name}'"))),
        };
        Ok(t)
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for HashType {
    type Err = Error;

    fn from_str(s: &str) -> Result<HashType> {
        HashType::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_roundtrip() {
        for t in HashType::ALL {
            assert_eq!(HashType::from_bits(t.bits()), Some(t));
            assert_eq!(HashType::from_log2(t.log2()), Some(t));
            assert_eq!(1u32 << t.log2(), t.bits());
        }
        assert_eq!(HashType::from_bits(0), None);
        assert_eq!(HashType::from_bits(3), None);
        assert_eq!(HashType::from_log2(31), None);
        assert_eq!(HashType::from_log2(40), None);
    }

    #[test]
    fn parse_is_lenient() {
        assert_eq!(HashType::parse("SHA-1").unwrap(), HashType::Sha1);
        assert_eq!(HashType::parse("sha_1").unwrap(), HashType::Sha1);
        assert_eq!(HashType::parse("Sha2-256").unwrap(), HashType::Sha2_256);
        assert_eq!(HashType::parse("sizes").unwrap(), HashType::Size);
        assert_eq!("md5".parse::<HashType>().unwrap(), HashType::Md5);
        assert!(HashType::parse("crc32").is_err());
    }

    #[test]
    fn lengths_match_reference() {
        assert_eq!(HashType::Md5.length(), Some(16));
        assert_eq!(HashType::Sha1.length(), Some(20));
        assert_eq!(HashType::Sha2_512.length(), Some(64));
        assert_eq!(HashType::Size.length(), Some(8));
        assert_eq!(HashType::Fuzzy.length(), None);
        assert!(!HashType::Fuzzy.is_storable());
        for t in HashType::ALL {
            assert_eq!(t.is_storable(), t != HashType::Fuzzy, "{t:?}");
        }
        assert!(!HashType::Size.is_digest());
        assert!(HashType::Blake3.is_digest());
    }

    #[test]
    fn tlsh_is_type_2_15_of_36_bytes() {
        assert_eq!(HashType::from_log2(15), Some(HashType::Tlsh));
        assert_eq!(HashType::from_bits(1 << 15), Some(HashType::Tlsh));
        assert_eq!(HashType::Tlsh.length(), Some(36));
        assert_eq!(HashType::Tlsh.name(), "TLSH");
        assert_eq!(HashType::Tlsh.field_name(), "tlsh");
        assert_eq!(HashType::parse("tlsh").ok(), Some(HashType::Tlsh));
        assert_eq!(HashType::parse("TLSH").ok(), Some(HashType::Tlsh));
        assert!(HashType::Tlsh.is_storable());
        assert!(!HashType::Tlsh.is_digest());
        assert_eq!(HashType::ALL.len(), 16);
        assert_eq!(HashType::ALL.last(), Some(&HashType::Tlsh));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Shrunk case of `roundtrip_over_all`: the display name `"Quick MD5"`
    /// (the C reference's name) contains a space, which `parse` rejected.
    #[test]
    fn quick_md5_display_name_parses() {
        assert_eq!(HashType::parse("Quick MD5").ok(), Some(HashType::QuickMd5));
        assert_eq!(
            HashType::parse(&HashType::QuickMd5.to_string()).ok(),
            Some(HashType::QuickMd5)
        );
    }

    proptest! {
        #[test]
        fn roundtrip_over_all(t in prop::sample::select(&HashType::ALL[..])) {
            prop_assert_eq!(HashType::from_bits(t.bits()), Some(t));
            prop_assert_eq!(HashType::from_log2(t.log2()), Some(t));
            prop_assert_eq!(HashType::parse(t.name()).ok(), Some(t));
            prop_assert_eq!(HashType::parse(t.field_name()).ok(), Some(t));
            prop_assert_eq!(HashType::parse(&t.to_string()).ok(), Some(t));
        }

        #[test]
        fn from_bits_rejects_non_members(bits in any::<u32>()) {
            prop_assert_eq!(
                HashType::from_bits(bits).is_some(),
                HashType::ALL.iter().any(|t| t.bits() == bits)
            );
        }

        #[test]
        fn from_log2_rejects_out_of_range(v in 16u16..) {
            prop_assert_eq!(HashType::from_log2(v), None);
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Over one minute: about 63 s of verification under Kani 0.68.
    #[kani::proof]
    #[kani::unwind(17)]
    fn from_log2_and_from_bits_invert_accessors() {
        for t in HashType::ALL {
            assert!(HashType::from_log2(t.log2()) == Some(t));
            assert!(HashType::from_bits(t.bits()) == Some(t));
        }
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn from_log2_none_out_of_range() {
        let v: u16 = kani::any();
        kani::assume(v >= 16);
        assert!(HashType::from_log2(v).is_none());
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn from_bits_none_for_non_members() {
        let bits: u32 = kani::any();
        kani::assume(bits.count_ones() != 1 || bits >= 1 << 16);
        assert!(HashType::from_bits(bits).is_none());
    }
}
