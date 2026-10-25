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
//!
//! # Popcount dispatch
//!
//! Rust targets baseline x86-64, where `count_ones` is a bit-twiddling
//! sequence; the C++ library is built with `-mpopcnt`. Every scan loop in
//! the crate (the kNN searches, the BISECT build, the merge's coalescing,
//! TIVF validation) therefore runs through one dispatcher that compiles it
//! a second time with the POPCNT target feature and picks that copy when
//! the CPU has the instruction ([`Popcount::detected`]). [`with_popcount`]
//! forces a choice on a thread, for tests and benchmarks. On other
//! architectures there is one copy (aarch64's `count_ones` is NEON `cnt`).

use std::cell::Cell;

use super::digest::{DIGEST_LENGTH, HI, LO, TlshDigest};

/// The popcount instructions the TLSH scans (kNN searches, index builds,
/// merges and validation) are compiled for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Popcount {
    /// `u64::count_ones` for the build target: a bit-twiddling sequence on
    /// baseline x86-64, NEON `cnt` on aarch64. Always available.
    Portable,
    /// The x86-64 `POPCNT` instruction, used only on a CPU that has it.
    Popcnt,
}

impl Popcount {
    /// The fastest kind this CPU runs (`std`'s feature detection, which
    /// queries CPUID once per process).
    pub fn detected() -> Self {
        if Self::Popcnt.is_available() {
            Self::Popcnt
        } else {
            Self::Portable
        }
    }

    /// Whether this CPU runs this kind.
    pub fn is_available(self) -> bool {
        match self {
            Self::Portable => true,
            #[cfg(target_arch = "x86_64")]
            Self::Popcnt => std::arch::is_x86_feature_detected!("popcnt"),
            #[cfg(not(target_arch = "x86_64"))]
            Self::Popcnt => false,
        }
    }

    /// Run the scan `f` compiled for this kind (the portable kind when the
    /// CPU lacks it). Every TLSH scan loop goes through here.
    ///
    /// Code is compiled for POPCNT only where it is inlined into the
    /// `#[target_feature]` context, so `f` must be an `#[inline(always)]`
    /// closure holding the whole loop, or calling `#[inline(always)]`
    /// functions that do: a call into code compiled without the feature
    /// gets the portable `count_ones`, and a dispatched kernel call per
    /// row would cost a function call per row.
    #[inline(always)]
    pub(crate) fn scan<R>(self, f: impl FnOnce() -> R) -> R {
        #[cfg(target_arch = "x86_64")]
        if self == Self::Popcnt && self.is_available() {
            // SAFETY: `popcnt_context` is safe apart from its
            // `#[target_feature(enable = "popcnt")]`, and calling it is
            // sound exactly when the CPU has POPCNT, which was checked just
            // above. This is the crate's only use of a target feature.
            return unsafe { popcnt_context(f) };
        }
        f()
    }
}

/// `f()`, with `f` (and what is inlined into it) compiled for POPCNT, so
/// `u64::count_ones` there is one `popcnt` instruction.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
fn popcnt_context<R>(f: impl FnOnce() -> R) -> R {
    f()
}

thread_local! {
    /// The [`with_popcount`] choice on this thread, if any.
    static CHOICE: Cell<Option<Popcount>> = const { Cell::new(None) };
}

/// The kind the TLSH scans started on this thread use now:
/// [`Popcount::detected`] unless [`with_popcount`] chose another.
pub fn popcount() -> Popcount {
    CHOICE.get().unwrap_or_else(Popcount::detected)
}

/// Run `f` with the TLSH scans it starts on this thread (and the worker
/// threads of an index build it starts) compiled for `p`, or for
/// [`Popcount::Portable`] when this CPU lacks `p`; the previous choice is
/// restored afterwards, also when `f` panics. Results never depend on the
/// choice: this is the hook to test and measure each kernel.
pub fn with_popcount<R>(p: Popcount, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Popcount>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CHOICE.set(self.0);
        }
    }
    let p = if p.is_available() {
        p
    } else {
        Popcount::Portable
    };
    let _restore = Restore(CHOICE.replace(Some(p)));
    f()
}

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
/// The kernel is `u64::count_ones`, always inlined, so it compiles to the
/// instructions of the loop it lands in: the crate's scans run under
/// [`Popcount`] dispatch and get the POPCNT instruction where the CPU has
/// it; a caller's own loop over [`body`](Self::body) gets the build
/// target's `count_ones` (on baseline x86-64 a bit-twiddling sequence,
/// about half the speed).
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
    #[inline(always)]
    pub fn body(&self, row: &[u8; DIGEST_LENGTH]) -> u32 {
        self.weighted::<5>(row)
    }

    /// Squared body-embedding distance from the query to `row`.
    #[inline(always)]
    pub fn emb_body(&self, row: &[u8; DIGEST_LENGTH]) -> u32 {
        self.weighted::<4>(row)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `mod_diff` on a circle of `r <= 256` values (the L circle is 256,
    /// Q1 and Q2 are 16) is symmetric, at most `r / 2`, zero only for equal
    /// arguments, and the shorter of the two arcs. Rules out a one-sided
    /// difference (`x - y` wrapping, or `|x - y|` without the wrap-around
    /// arc), which makes `header_diff` asymmetric or over-charges L.
    #[kani::proof]
    #[kani::unwind(1)]
    fn mod_diff_is_the_shorter_arc() {
        let r: u32 = kani::any();
        let x: u32 = kani::any();
        let y: u32 = kani::any();
        kani::assume(r >= 1 && r <= 256 && x < r && y < r);
        let d = mod_diff(x, y, r);
        assert!(d == mod_diff(y, x, r));
        assert!(d <= r / 2);
        assert!((d == 0) == (x == y));
        // d is one of the two arcs from x to y.
        assert!((x + d) % r == y || (y + d) % r == x);
    }

    /// `l_cost` and `q_cost` are non-decreasing over their whole domain
    /// (`k <= 128` for L, `k <= 8` for Q, the largest `mod_diff` values),
    /// start 0, 1, and never overflow there. Rules out an off-by-one in the
    /// `12 k` / `12 (k - 1)` branches, which would let a farther header
    /// cost less and break the header order's early exits.
    #[kani::proof]
    #[kani::unwind(1)]
    fn l_and_q_costs_are_monotone() {
        assert!(l_cost(0) == 0 && l_cost(1) == 1 && l_cost(2) == 24);
        assert!(q_cost(0) == 0 && q_cost(1) == 1 && q_cost(2) == 12);
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        kani::assume(a <= b && b <= 128);
        assert!(l_cost(a) <= l_cost(b));
        assert!(l_cost(b) <= 12 * 128);
        if b <= 8 {
            assert!(q_cost(a) <= q_cost(b));
            assert!(q_cost(b) <= 12 * 7);
        }
    }

    fn any_digest() -> TlshDigest {
        TlshDigest(kani::any())
    }

    /// `header_diff` is symmetric, zero for equal headers, and at most
    /// `1 + 12 * 128 + 2 * 12 * 7 = 1705`. Rules out an asymmetric
    /// distance (k-NN of `a` from `b` differing from `b` from `a`) and a
    /// header cost large enough to overflow `diff`'s sum.
    #[kani::proof]
    #[kani::unwind(1)]
    fn header_diff_is_symmetric_and_bounded() {
        let a = any_digest();
        let b = any_digest();
        let include_length: bool = kani::any();
        let d = header_diff(&a, &b, include_length);
        assert!(d == header_diff(&b, &a, include_length));
        assert!(d <= 1705);
        assert!(header_diff(&a, &a, include_length) == 0);
    }

    /// Per-bucket costs of a code difference of 0, 1, 2, 3: the TLSH body
    /// distance (6 for 3, as in `totalDiff`) and the squared embedding
    /// distance (5 for 3).
    const BODY_COST: [u32; 4] = [0, 1, 2, 6];
    const EMB_COST: [u32; 4] = [0, 1, 2, 5];

    /// A digest that is zero except for its header and trailer bytes (L,
    /// Q, checksum, reserved) and the body byte `j` of each plane, all
    /// arbitrary.
    fn one_body_byte(j: usize) -> TlshDigest {
        let mut d = [0u8; DIGEST_LENGTH];
        for at in [0, 1, 34, 35, HI + j, LO + j] {
            d[at] = kani::any();
        }
        TlshDigest(d)
    }

    /// The popcount kernel equals the per-bucket sum over the 128 two-bit
    /// codes read with `bucket`, for pairs of digests whose bodies differ
    /// from zero in one byte position `j` of each plane (any `j`, any
    /// values, any header and trailer bytes). Every term of the kernel is a
    /// popcount of bitwise operations on the planes, so it is a sum of
    /// independent per-byte terms, and per-byte correctness at every
    /// position is correctness for all digests. Rules out a wrong plane
    /// offset (one that reads L, Q or the checksum), a swapped hi/lo plane,
    /// a dropped word, and a wrong weight for the `|0 - 3|` case, all of
    /// which the bit-parallel form would hide from a spot check. (Fully
    /// symbolic 36-byte pairs did not finish in 11 minutes: the solver has
    /// to prove two popcount formulations equal, which SAT handles badly.)
    ///
    /// Over one minute: about 125 s of verification under Kani 0.68.
    #[kani::proof]
    #[kani::unwind(9)]
    fn body_kernel_matches_per_bucket_costs() {
        let j: usize = kani::any();
        kani::assume(j < 16);
        let a = one_body_byte(j);
        let b = one_body_byte(j);
        let mut body = 0;
        let mut emb = 0;
        // Buckets outside 8j..8j + 8 are code 0 in both: cost 0.
        for i in 8 * j..8 * j + 8 {
            let k = a.bucket(i).abs_diff(b.bucket(i)) as usize;
            body += BODY_COST[k];
            emb += EMB_COST[k];
        }
        let q = BodyQuery::new(&a);
        assert!(q.body(&b.0) == body);
        assert!(q.emb_body(&b.0) == emb);
    }
}
