//! TLSH distance: header and body costs and the popcount body kernel.
//!
//! [`diff`] equals the reference implementation's
//! `Tlsh::totalDiff(other, include_length)`:
//!
//! ```text
//! header = (checksum_a != checksum_b)
//!        + l_cost(mod_diff(L_a, L_b, 256))       (only with include_length)
//!        + q_cost(mod_diff(Q1_a, Q1_b, 16))
//!        + q_cost(mod_diff(Q2_a, Q2_b, 16))
//! body   = sum over buckets of 0, 1, 2, 6 for |code_a - code_b| = 0, 1, 2, 3
//! ```
//!
//! The body is computed over the bit planes 64 buckets at a time. Per
//! little-endian `u64` word of the planes, with `X = lo_a ^ lo_b`,
//! `Y = hi_a ^ hi_b` and `S = !(lo_a ^ hi_a)`:
//!
//! ```text
//! popcount(X ^ Y) + popcount(Y) + W * popcount(X & Y & S)
//! ```
//!
//! `W = 5` gives the TLSH body cost; `W = 4` gives the squared distance
//! between the body embeddings (per bucket 0, 1, 2, 5), the BISECT build's
//! and the TIVF search's metric. C++: `include/tlsh_digest.h`.

use super::digest::{DIGEST_LENGTH, HI, LO, TlshDigest};

/// Cost of a (mod 256) L difference of `k`: 0, 1, then `12 k`.
pub const fn l_cost(k: u32) -> u32 {
    match k {
        0 => 0,
        1 => 1,
        _ => 12 * k,
    }
}

/// Cost of a (mod 16) Q1 or Q2 difference of `k`: 0, 1, then
/// `12 (k - 1)`.
pub const fn q_cost(k: u32) -> u32 {
    if k <= 1 { k } else { 12 * (k - 1) }
}

/// Distance between `x` and `y` on a circle of `r` values:
/// `min(|x - y|, r - |x - y|)`, for `x, y < r`.
pub const fn mod_diff(x: u32, y: u32, r: u32) -> u32 {
    let d = x.abs_diff(y);
    if d < r - d { d } else { r - d }
}

/// The header part of the distance: checksum, L (when `include_length`),
/// Q1 and Q2 costs. Null digests are not special here.
pub fn header_diff(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> u32 {
    let mut d = u32::from(a.checksum() != b.checksum());
    if include_length {
        d += l_cost(mod_diff(a.l().into(), b.l().into(), 256));
    }
    d += q_cost(mod_diff(a.q1().into(), b.q1().into(), 16));
    d + q_cost(mod_diff(a.q2().into(), b.q2().into(), 16))
}

/// The body part of the distance over the 128 buckets.
pub fn body_diff(a: &TlshDigest, b: &TlshDigest) -> u32 {
    BodyQuery::new(a).body(&b.0)
}

/// The TLSH distance, `header_diff + body_diff`, or `None` when either
/// digest is null (where `sfhash_tlsh_diff` returns -1).
pub fn diff(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> Option<u32> {
    if a.is_null() || b.is_null() {
        return None;
    }
    Some(header_diff(a, b, include_length) + body_diff(a, b))
}

/// Squared Euclidean distance between the body embeddings of `a` and `b`
/// (C++ `tlsh_embed_body_dist2`): per bucket 0, 1, 2, 5 for
/// `|code_a - code_b|` = 0, 1, 2, 3.
pub fn emb_body_dist2(a: &TlshDigest, b: &TlshDigest) -> u32 {
    BodyQuery::new(a).emb_body(&b.0)
}

/// Little-endian `u64` word `w` (0 or 1) of the plane at `plane`.
#[inline(always)]
fn word(d: &[u8; DIGEST_LENGTH], plane: usize, w: usize) -> u64 {
    let at = plane + 8 * w;
    u64::from_le_bytes(d[at..at + 8].try_into().expect("8 bytes"))
}

/// One query digest's body planes, precomputed for scanning many rows
/// (C++ `TlshBodyQuery`): `body(r) == body_diff(q, r)` and
/// `emb_body(r) == emb_body_dist2(q, r)` for every row `r`.
///
/// Rows are taken as raw 36-byte arrays, the shape of an `HDAT` section.
/// The kernel is portable scalar `u64::count_ones`; the planes are held as
/// words and the fields are private, so a kernel compiled for the POPCNT
/// instruction can be chosen at construction without changing this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyQuery {
    lo: [u64; 2],
    hi: [u64; 2],
    /// `!(lo ^ hi)`: set where the query's code is 0 or 3.
    s: [u64; 2],
}

impl BodyQuery {
    /// Precompute the planes of `q`.
    pub fn new(q: &TlshDigest) -> Self {
        let lo = [word(&q.0, LO, 0), word(&q.0, LO, 1)];
        let hi = [word(&q.0, HI, 0), word(&q.0, HI, 1)];
        Self {
            lo,
            hi,
            s: [!(lo[0] ^ hi[0]), !(lo[1] ^ hi[1])],
        }
    }

    /// `popcount(X ^ Y) + popcount(Y) + W * popcount(X & Y & S)` over both
    /// words.
    #[inline(always)]
    fn weighted<const W: u32>(&self, row: &[u8; DIGEST_LENGTH]) -> u32 {
        let mut d = 0;
        for i in 0..2 {
            let x = self.lo[i] ^ word(row, LO, i);
            let y = self.hi[i] ^ word(row, HI, i);
            d += (x ^ y).count_ones() + y.count_ones() + W * (x & y & self.s[i]).count_ones();
        }
        d
    }

    /// TLSH body distance from the query to `row`.
    #[inline]
    pub fn body(&self, row: &[u8; DIGEST_LENGTH]) -> u32 {
        self.weighted::<5>(row)
    }

    /// Squared body-embedding distance from the query to `row`.
    #[inline]
    pub fn emb_body(&self, row: &[u8; DIGEST_LENGTH]) -> u32 {
        self.weighted::<4>(row)
    }
}
