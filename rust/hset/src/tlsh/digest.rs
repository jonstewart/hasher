//! The canonical 36-byte TLSH digest and its hex transport form.
//!
//! libhasher stores a TLSH digest (128 buckets, 1-byte checksum) in a fixed
//! 36-byte form chosen so that bytewise order is the canonical sort order
//! of hash sets (L, Q1, Q2, body, checksum):
//!
//! ```text
//! offset  0  L          log-scaled input length
//! offset  1  Q          (Q1 << 4) | Q2
//! offset  2  plane hi   16 bytes; bit i = bit 1 of bucket code i
//! offset 18  plane lo   16 bytes; bit i = bit 0 of bucket code i
//! offset 34  checksum
//! offset 35  reserved   always 0
//! ```
//!
//! Bit i of a plane is bit `i % 8` of byte `i / 8`. The all-zero digest is
//! the null digest (`"TNULL"`), which the hasher yields for inputs it
//! cannot hash. C++: `include/tlsh_digest.h`, `include/hasher/tlsh.h`,
//! `src/lib/tlsh.cpp`.
//!
//! The hex form is the reference implementation's `"T1"` string: 35 bytes
//! as 70 hex digits, the checksum and L nibble-swapped, then Q, then the 32
//! body bytes in reverse order, each holding four bucket codes from its
//! low bits up.

use std::fmt;
use std::io;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Length of a canonical digest in bytes.
pub const DIGEST_LENGTH: usize = 36;

/// Length of the hex transport form: `"T1"` and 70 hex digits.
pub const HEX_LENGTH: usize = 72;

/// Number of buckets (2-bit codes) in the body.
pub const BUCKETS: usize = 128;

/// Offset of the high bit plane.
pub(crate) const HI: usize = 2;
/// Offset of the low bit plane.
pub(crate) const LO: usize = 18;
const CHECKSUM: usize = 34;
const RESERVED: usize = 35;

/// Hex digits of the 35 bytes after `"T1"`.
const RAW_LENGTH: usize = 35;

const NULL_HEX: &str = "TNULL";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// A TLSH digest in canonical form (see the [module docs](self)).
///
/// Ordering is bytewise, which is the hash-set row order. The field is
/// public so rows can be wrapped without a check; [`TlshDigest::from_bytes`]
/// is the checked constructor.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlshDigest(pub [u8; DIGEST_LENGTH]);

fn swap_nibbles(b: u8) -> u8 {
    b.rotate_left(4)
}

impl TlshDigest {
    /// The null digest: 36 zero bytes, `"TNULL"` in hex.
    pub const NULL: Self = Self([0; DIGEST_LENGTH]);

    /// Build a digest from the reference implementation's fields; `codes[i]`
    /// is the 2-bit code of bucket i. As `make_tlsh_digest` in C++, only the
    /// low 4 bits of `q1` and `q2` and the low 2 bits of each code are used.
    pub fn from_parts(l: u8, q1: u8, q2: u8, checksum: u8, codes: &[u8; BUCKETS]) -> Self {
        let mut d = [0u8; DIGEST_LENGTH];
        d[0] = l;
        d[1] = ((q1 & 0x0F) << 4) | (q2 & 0x0F);
        for (i, &c) in codes.iter().enumerate() {
            d[HI + (i >> 3)] |= ((c >> 1) & 1) << (i & 7);
            d[LO + (i >> 3)] |= (c & 1) << (i & 7);
        }
        d[CHECKSUM] = checksum;
        Self(d)
    }

    /// Wrap a raw 36-byte digest, rejecting a non-zero reserved byte
    /// (offset 35) with [`Error::Input`].
    pub fn from_bytes(bytes: &[u8; DIGEST_LENGTH]) -> Result<Self> {
        if bytes[RESERVED] != 0 {
            return Err(Error::input(format!(
                "TLSH digest has reserved byte 0x{:02x}, must be 0",
                bytes[RESERVED]
            )));
        }
        Ok(Self(*bytes))
    }

    /// Parse the hex transport form: `"T1"` and 70 hex digits, or the 70
    /// digits alone, in either case; `"TNULL"` is the null digest. The
    /// whole string must be the digest: unlike C++'s `tlsh_from_hex`,
    /// nothing may follow the 70th digit. 70 zero digits also decode to
    /// the null digest. Errors are [`Error::Input`].
    pub fn from_hex(s: &str) -> Result<Self> {
        if s == NULL_HEX {
            return Ok(Self::NULL);
        }
        let digits = s.strip_prefix("T1").unwrap_or(s).as_bytes();
        let mut raw = [0u8; RAW_LENGTH];
        if digits.len() != 2 * RAW_LENGTH {
            return Err(bad_hex(s, "wrong length"));
        }
        if !crate::hex::scalar::decode_into(digits, &mut raw) {
            return Err(bad_hex(s, "not a hex digit"));
        }
        // The hex form nibble-swaps checksum and L and emits the body bytes
        // in reverse order; raw[2] is already our Q layout.
        let mut codes = [0u8; BUCKETS];
        for (i, quad) in codes.chunks_exact_mut(4).enumerate() {
            let code_byte = raw[3 + 31 - i];
            for (j, c) in quad.iter_mut().enumerate() {
                *c = (code_byte >> (2 * j)) & 3;
            }
        }
        Ok(Self::from_parts(
            swap_nibbles(raw[1]),
            raw[2] >> 4,
            raw[2] & 0x0F,
            swap_nibbles(raw[0]),
            &codes,
        ))
    }

    /// Write the hex form into `buf` and return the bytes written: `"T1"`
    /// and 70 uppercase hex digits, or `"TNULL"` for the null digest.
    fn hex_into<'b>(&self, buf: &'b mut [u8; HEX_LENGTH]) -> &'b [u8] {
        if self.is_null() {
            buf[..NULL_HEX.len()].copy_from_slice(NULL_HEX.as_bytes());
            return &buf[..NULL_HEX.len()];
        }
        let mut raw = [0u8; RAW_LENGTH];
        raw[0] = swap_nibbles(self.checksum());
        raw[1] = swap_nibbles(self.l());
        raw[2] = self.q();
        for i in 0..32 {
            let mut code_byte = 0u8;
            for j in 0..4 {
                code_byte |= self.bucket(4 * i + j) << (2 * j);
            }
            raw[3 + 31 - i] = code_byte;
        }
        buf[0] = b'T';
        buf[1] = b'1';
        for (b, out) in raw.iter().zip(buf[2..].chunks_exact_mut(2)) {
            out[0] = HEX_UPPER[(b >> 4) as usize];
            out[1] = HEX_UPPER[(b & 0x0F) as usize];
        }
        &buf[..]
    }

    /// The hex form: `"T1"` and 70 uppercase hex digits, or `"TNULL"`.
    pub fn to_hex(&self) -> String {
        let mut buf = [0u8; HEX_LENGTH];
        let hex = self.hex_into(&mut buf);
        String::from_utf8(hex.to_vec()).expect("hex digits are ASCII")
    }

    /// Write the hex form (as [`TlshDigest::to_hex`]) to `w` without
    /// allocating.
    pub fn write_hex<W: io::Write + ?Sized>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; HEX_LENGTH];
        w.write_all(self.hex_into(&mut buf))
    }

    /// The 36 canonical bytes.
    pub fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// True for the null digest (all 36 bytes zero).
    pub fn is_null(&self) -> bool {
        self.0 == [0; DIGEST_LENGTH]
    }

    /// The length byte L.
    pub fn l(&self) -> u8 {
        self.0[0]
    }

    /// The quartile byte, `(Q1 << 4) | Q2`.
    pub fn q(&self) -> u8 {
        self.0[1]
    }

    /// Q1, the high nibble of [`TlshDigest::q`].
    pub fn q1(&self) -> u8 {
        self.0[1] >> 4
    }

    /// Q2, the low nibble of [`TlshDigest::q`].
    pub fn q2(&self) -> u8 {
        self.0[1] & 0x0F
    }

    /// The checksum byte.
    pub fn checksum(&self) -> u8 {
        self.0[CHECKSUM]
    }

    /// The 2-bit code of bucket `i`, numbered as the reference's internal
    /// bucket index (not the hex string's order).
    ///
    /// # Panics
    ///
    /// If `i >= 128`.
    pub fn bucket(&self, i: usize) -> u8 {
        assert!(i < BUCKETS, "TLSH bucket {i} out of range");
        let h = (self.0[HI + (i >> 3)] >> (i & 7)) & 1;
        let l = (self.0[LO + (i >> 3)] >> (i & 7)) & 1;
        (h << 1) | l
    }

    /// The cell, `(L << 8) | Q`: the first two bytes as a big-endian `u16`.
    pub fn cell(&self) -> u16 {
        u16::from_be_bytes([self.0[0], self.0[1]])
    }
}

fn bad_hex(s: &str, why: &str) -> Error {
    Error::input(format!(
        "{s:?} is not a TLSH digest ({why}; expected T1 and 70 hex digits, or TNULL)"
    ))
}

impl fmt::Display for TlshDigest {
    /// The hex form, as [`TlshDigest::to_hex`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; HEX_LENGTH];
        let hex = self.hex_into(&mut buf);
        f.write_str(std::str::from_utf8(hex).expect("hex digits are ASCII"))
    }
}

impl fmt::Debug for TlshDigest {
    /// The hex form, and the reserved byte when it is not zero (the hex
    /// form does not carry it).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut t = f.debug_tuple("TlshDigest");
        t.field(&format_args!("{self}"));
        if self.0[RESERVED] != 0 {
            t.field(&format_args!("reserved=0x{:02x}", self.0[RESERVED]));
        }
        t.finish()
    }
}

impl FromStr for TlshDigest {
    type Err = Error;

    /// As [`TlshDigest::from_hex`].
    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}
