//! Membership lookup over a sorted array of fixed-width hashes.
//!
//! A [`Lookup`] is built from the hash data plus an optional on-disk hint
//! table ([`crate::format::Hint`]). Hints only narrow the search window;
//! correctness never depends on them being tight or on the data being
//! uniformly distributed.

pub mod block;
pub mod hull;
pub mod model;
pub mod search;

use std::ops::Range;

use crate::error::{Error, Result};
use crate::format::{
    BLOCK_ENTRY_LEN, HULL_ENTRY_LEN, Hint, MAX_HINT_BITS, hint_tag_block, hint_tag_hull,
};
use model::{FlatBlocks, Full, HullBlocks};
use search::{DynBasic, Strategy};

/// Exact membership queries over a sorted hash array.
pub trait Lookup: Send + Sync {
    /// Bytes per hash.
    fn hash_length(&self) -> usize;
    /// Number of hashes.
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Is `hash` (at least `hash_length` bytes) in the set?
    fn contains(&self, hash: &[u8]) -> bool;
    /// Index of the first stored hash equal to `hash`.
    fn find(&self, hash: &[u8]) -> Option<usize>;
    /// Indices of all stored hashes equal to `hash` (duplicates are possible
    /// when several records share a hash).
    fn equal_range(&self, hash: &[u8]) -> Range<usize>;
    /// Membership of `out.len()` contiguous hashes; identical answers to
    /// calling [`Lookup::contains`] on each.
    fn contains_batch(&self, hashes: &[u8], out: &mut [bool]);
    /// The index window the model would search for `hash` (diagnostics).
    fn window(&self, hash: &[u8]) -> Range<usize>;
    /// Human-readable strategy description.
    fn describe(&self) -> String;
    /// Auxiliary memory held by the strategy.
    fn table_bytes(&self) -> usize;
}

/// How single lookups search inside the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SingleMode {
    /// `Recursive` for digest-length hashes without a bounding hint, `KAry`
    /// otherwise (default).
    #[default]
    Auto,
    /// 8-ary search: seven overlapping loads per step.
    KAry,
    /// Branchless binary search, one dependent load per step.
    Binary,
    /// Recursive dictionary search: fetch a region around the model's
    /// prediction, re-aim from its edge keys using the model's density, and
    /// repeat; falls back to 8-ary search if the bracket stays wide.
    Recursive,
}

/// How batched lookups overlap memory accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BatchMode {
    /// Staged pipeline when the model keeps windows small, lanes otherwise (default).
    #[default]
    Auto,
    /// Three-stage prefetch pipeline over the query stream.
    Staged,
    /// Many interleaved binary searches, each prefetching its next probe.
    Lanes,
    /// Struct-of-arrays passes over sub-batches: keys and table touches,
    /// then window evaluation and prefetch, then searches.
    Passes,
}

/// Tunables for [`make_lookup_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchConfig {
    pub single: SingleMode,
    pub batch: BatchMode,
    /// Windows spanning at most this many bytes are prefetched whole and
    /// scanned; wider ones are narrowed first. About the number of cache
    /// lines the core can keep in flight.
    pub window_prefetch_bytes: usize,
    /// Largest region (in bytes) one level of the recursive search fetches.
    pub region_bytes: usize,
    /// Queries per sub-batch of the `Passes` batch mode (at most 256).
    pub passes_sub_batch: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        SearchConfig {
            single: SingleMode::Auto,
            batch: BatchMode::Auto,
            window_prefetch_bytes: 1024,
            region_bytes: 512,
            passes_sub_batch: 32,
        }
    }
}

/// Which hint to build for a hash set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintSpec {
    /// No hint; plain binary search.
    None,
    /// Flat per-block deviation bounds over the top `bits` bits.
    Block { bits: u8 },
    /// Convex-hull fitted lines over the top `bits` bits.
    Hull { bits: u8 },
}

impl HintSpec {
    /// The legacy hint written by the reference C++ encoder.
    pub const LEGACY: HintSpec = HintSpec::Block { bits: 8 };
}

/// Policy for choosing block bits from the data size.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BitsPolicy {
    /// Maximum table size as a fraction of the hash data size.
    pub budget: f64,
    pub min_bits: u8,
    pub max_bits: u8,
}

impl Default for BitsPolicy {
    fn default() -> Self {
        BitsPolicy {
            budget: 0.02,
            min_bits: 4,
            max_bits: 20,
        }
    }
}

impl BitsPolicy {
    /// Largest `bits` whose table (`entry_len << bits` bytes) stays within
    /// `budget * n * hash_length`, clamped to `[min_bits, max_bits]`.
    pub fn choose(&self, n: usize, hash_length: usize, entry_len: usize) -> u8 {
        let data = (n as f64) * (hash_length as f64) * self.budget;
        let mut bits = self.min_bits;
        while bits < self.max_bits && ((entry_len as f64) * 2f64.powi(i32::from(bits) + 1)) <= data
        {
            bits += 1;
        }
        bits.clamp(self.min_bits, self.max_bits)
    }
}

/// Dispatch a const-generic function over the supported hash lengths.
macro_rules! dispatch_len {
    ($hlen:expr, |$L:ident| $body:expr, $fallback:expr) => {
        match $hlen {
            4 => {
                const $L: usize = 4;
                $body
            }
            8 => {
                const $L: usize = 8;
                $body
            }
            16 => {
                const $L: usize = 16;
                $body
            }
            20 => {
                const $L: usize = 20;
                $body
            }
            28 => {
                const $L: usize = 28;
                $body
            }
            32 => {
                const $L: usize = 32;
                $body
            }
            48 => {
                const $L: usize = 48;
                $body
            }
            64 => {
                const $L: usize = 64;
                $body
            }
            _ => $fallback,
        }
    };
}

fn check_data(hash_length: usize, data: &[u8]) -> Result<usize> {
    if hash_length == 0 {
        return Err(Error::input("hash length must be positive"));
    }
    if !data.len().is_multiple_of(hash_length) {
        return Err(Error::format("hash data is not a whole number of hashes"));
    }
    let n = data.len() / hash_length;
    if n >= (1usize << 32) {
        return Err(Error::format(
            "hash sets with 2^32 or more hashes are not supported",
        ));
    }
    Ok(n)
}

/// Build a lookup strategy for sorted `data` using `hint` if it is usable.
pub fn make_lookup<'a>(
    hash_length: usize,
    data: &'a [u8],
    hint: Option<&Hint<'_>>,
) -> Result<Box<dyn Lookup + 'a>> {
    make_lookup_with(hash_length, data, hint, SearchConfig::default())
}

/// [`make_lookup`] with explicit search tunables.
pub fn make_lookup_with<'a>(
    hash_length: usize,
    data: &'a [u8],
    hint: Option<&Hint<'_>>,
    cfg: SearchConfig,
) -> Result<Box<dyn Lookup + 'a>> {
    check_data(hash_length, data)?;
    let boxed: Box<dyn Lookup + 'a> = dispatch_len!(
        hash_length,
        |L| match hint {
            Some(Hint::Hull { bits, table }) => {
                Box::new(Strategy::<L, _>::new(
                    data,
                    HullBlocks::from_bytes(*bits, table),
                    cfg,
                ))
            }
            Some(Hint::Block { bits, table }) if L >= 4 => {
                Box::new(Strategy::<L, _>::new(
                    data,
                    FlatBlocks::from_bytes(*bits, table),
                    cfg,
                ))
            }
            _ => Box::new(Strategy::<L, _>::new(data, Full, cfg)),
        },
        Box::new(DynBasic::new(data, hash_length))
    );
    Ok(boxed)
}

/// Build the hint table bytes for `spec`, returning `(tag, table)`.
pub fn build_hint(
    hash_length: usize,
    data: &[u8],
    spec: HintSpec,
) -> Result<Option<(u16, Vec<u8>)>> {
    let n = check_data(hash_length, data)?;
    let check_bits = |bits: u8| {
        if bits > MAX_HINT_BITS {
            Err(Error::input(format!(
                "block bits {bits} exceeds maximum {MAX_HINT_BITS}"
            )))
        } else {
            Ok(())
        }
    };
    match spec {
        HintSpec::None => Ok(None),
        HintSpec::Block { bits } => {
            check_bits(bits)?;
            if bits == 0 {
                return Err(Error::input("flat block hints need at least 1 bit"));
            }
            if hash_length < 4 {
                return Err(Error::input(
                    "flat block hints need hashes of at least 4 bytes",
                ));
            }
            let _ = n;
            let table = dispatch_len!(
                hash_length,
                |L| block::table_to_bytes(&block::build_table::<L>(data, bits)),
                return Err(Error::input(format!(
                    "unsupported hash length {hash_length} for hints"
                )))
            );
            Ok(Some((hint_tag_block(bits), table)))
        }
        HintSpec::Hull { bits } => {
            check_bits(bits)?;
            if n > i32::MAX as usize {
                return Err(Error::input("hull hints support at most 2^31 - 1 hashes"));
            }
            let table = dispatch_len!(
                hash_length,
                |L| hull::table_to_bytes(&hull::build_table::<L>(data, bits)),
                return Err(Error::input(format!(
                    "unsupported hash length {hash_length} for hints"
                )))
            );
            Ok(Some((hint_tag_hull(bits), table)))
        }
    }
}

/// Resolve an "automatic" bit count for `spec` using `policy`.
pub fn resolve_bits(spec: HintSpec, n: usize, hash_length: usize, policy: &BitsPolicy) -> HintSpec {
    match spec {
        HintSpec::Block { bits: 0 } => HintSpec::Block {
            bits: policy.choose(n, hash_length, BLOCK_ENTRY_LEN).max(1),
        },
        HintSpec::Hull { bits: u8::MAX } => HintSpec::Hull {
            bits: policy.choose(n, hash_length, HULL_ENTRY_LEN),
        },
        other => other,
    }
}

/// Decode a hint table into its model and wrap a borrowed `Hint` for
/// convenience in tests and tools.
pub fn hint_from_parts<'a>(tag: u16, table: &'a [u8]) -> Hint<'a> {
    let bits = (tag & 0xff) as u8;
    match tag >> 8 {
        0x62 if table.len() == BLOCK_ENTRY_LEN << bits => Hint::Block { bits, table },
        0x68 if table.len() == HULL_ENTRY_LEN << bits => Hint::Hull { bits, table },
        _ => Hint::Unknown { tag, data: table },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;

    fn oracle(data: &[u8], hlen: usize, h: &[u8]) -> Option<usize> {
        let n = data.len() / hlen;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if data[mid * hlen..(mid + 1) * hlen] < h[..hlen] {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        (lo < n && data[lo * hlen..(lo + 1) * hlen] == h[..hlen]).then_some(lo)
    }

    fn strategies<'a>(
        hlen: usize,
        data: &'a [u8],
        hints: &'a [Option<(u16, Vec<u8>)>],
    ) -> Vec<Box<dyn Lookup + 'a>> {
        let mut v = Vec::new();
        for cfg in [
            SearchConfig::default(),
            SearchConfig {
                single: SingleMode::Binary,
                batch: BatchMode::Lanes,
                ..SearchConfig::default()
            },
            SearchConfig {
                single: SingleMode::KAry,
                batch: BatchMode::Staged,
                ..SearchConfig::default()
            },
            SearchConfig {
                single: SingleMode::Recursive,
                batch: BatchMode::Staged,
                window_prefetch_bytes: 256,
                region_bytes: 128,
                ..SearchConfig::default()
            },
            SearchConfig {
                single: SingleMode::Recursive,
                batch: BatchMode::Lanes,
                ..SearchConfig::default()
            },
            SearchConfig {
                single: SingleMode::KAry,
                batch: BatchMode::Passes,
                ..SearchConfig::default()
            },
        ] {
            for hint in hints {
                let h = hint.as_ref().map(|(t, b)| hint_from_parts(*t, b));
                v.push(make_lookup_with(hlen, data, h.as_ref(), cfg).unwrap());
            }
        }
        v
    }

    fn all_hints(hlen: usize, data: &[u8]) -> Vec<Option<(u16, Vec<u8>)>> {
        let mut specs = vec![
            HintSpec::None,
            HintSpec::Hull { bits: 0 },
            HintSpec::Hull { bits: 7 },
            HintSpec::Hull { bits: 12 },
        ];
        if hlen >= 4 {
            specs.push(HintSpec::LEGACY);
            specs.push(HintSpec::Block { bits: 12 });
        }
        specs
            .into_iter()
            .map(|s| build_hint(hlen, data, s).unwrap())
            .collect()
    }

    fn exercise(hlen: usize, data: &[u8], queries: &[u8]) {
        let hints = all_hints(hlen, data);
        let m = queries.len() / hlen;
        let mut batch = vec![false; m];
        for s in strategies(hlen, data, &hints) {
            assert_eq!(s.len(), data.len() / hlen);
            assert_eq!(s.hash_length(), hlen);
            s.contains_batch(queries, &mut batch);
            for q in 0..m {
                let h = &queries[q * hlen..(q + 1) * hlen];
                let expect = oracle(data, hlen, h);
                assert_eq!(
                    s.find(h),
                    expect,
                    "{} find {}",
                    s.describe(),
                    crate::hex::encode(h)
                );
                assert_eq!(s.contains(h), expect.is_some(), "{} contains", s.describe());
                assert_eq!(batch[q], expect.is_some(), "{} batch", s.describe());
                let w = s.window(h);
                if let Some(i) = expect {
                    assert!(
                        w.contains(&i),
                        "{}: window {w:?} misses index {i}",
                        s.describe()
                    );
                }
            }
        }
    }

    #[test]
    fn matches_oracle_on_uniform_data() {
        for hlen in [4usize, 8, 16, 20, 32, 64] {
            let data = synth::sorted_unique_hashes(3000, hlen, 100 + hlen as u64);
            let queries = synth::queries(&data, hlen, 2000, 0.5, 7);
            exercise(hlen, &data, &queries);
        }
    }

    #[test]
    fn matches_oracle_on_adversarial_data() {
        let hlen = 20;
        let data = synth::adversarial_hashes(5000, hlen, 42);
        let queries = synth::queries(&data, hlen, 3000, 0.5, 8);
        exercise(hlen, &data, &queries);
    }

    #[test]
    fn handles_duplicates_and_shared_prefixes() {
        // Several hashes share the same leading 8 bytes; some are duplicated.
        let hlen = 20;
        let mut rows: Vec<[u8; 20]> = Vec::new();
        for i in 0..50u8 {
            let mut h = [0xAB; 20];
            h[19] = i;
            rows.push(h);
            if i % 7 == 0 {
                rows.push(h);
            }
        }
        for i in 0..50u8 {
            let mut h = [0x10; 20];
            h[0] = i;
            rows.push(h);
        }
        rows.sort();
        let data: Vec<u8> = rows.iter().flatten().copied().collect();
        let hints = all_hints(hlen, &data);
        for s in strategies(hlen, &data, &hints) {
            for (i, r) in rows.iter().enumerate() {
                let f = s.find(r).unwrap();
                assert!(
                    rows[f] == *r && (f == 0 || rows[f - 1] != *r),
                    "{} first-equal",
                    s.describe()
                );
                let er = s.equal_range(r);
                assert!(er.contains(&i));
                assert!(er.clone().all(|j| rows[j] == *r));
            }
            let mut missing = [0xABu8; 20];
            missing[19] = 200;
            assert!(!s.contains(&missing));
            let mut missing = [0xABu8; 20];
            missing[10] = 1;
            assert!(!s.contains(&missing));
        }
    }

    #[test]
    fn empty_and_tiny_sets() {
        let hlen = 16;
        let empty: Vec<u8> = Vec::new();
        let hints = all_hints(hlen, &empty);
        for s in strategies(hlen, &empty, &hints) {
            assert!(s.is_empty());
            assert!(!s.contains(&[0u8; 16]));
            let mut out = [true; 2];
            s.contains_batch(&[0u8; 32], &mut out);
            assert_eq!(out, [false, false]);
        }
        let one = synth::sorted_unique_hashes(1, hlen, 1);
        let hints = all_hints(hlen, &one);
        for s in strategies(hlen, &one, &hints) {
            assert_eq!(s.find(&one), Some(0));
            assert!(!s.contains(&[0xffu8; 16]));
            assert!(!s.contains(&[0u8; 16]));
        }
    }

    #[test]
    fn unsupported_lengths_fall_back_to_generic_search() {
        let hlen = 12;
        let data = synth::sorted_unique_hashes(500, hlen, 3);
        let s = make_lookup(hlen, &data, None).unwrap();
        for i in 0..500 {
            assert_eq!(s.find(&data[i * hlen..(i + 1) * hlen]), Some(i));
        }
        assert!(build_hint(hlen, &data, HintSpec::Hull { bits: 4 }).is_err());
    }

    #[test]
    fn bits_policy_scales_with_size() {
        let p = BitsPolicy::default();
        assert_eq!(p.choose(0, 20, 12), p.min_bits);
        let small = p.choose(10_000, 20, 12);
        let large = p.choose(40_000_000, 20, 12);
        assert!(small < large);
        assert!(large <= p.max_bits);
        // 2% of 800 MB = 16 MB; 12 B << 20 = 12 MB fits, 24 MB does not.
        assert_eq!(large, 20);
        assert_eq!(
            resolve_bits(HintSpec::Hull { bits: u8::MAX }, 10_000, 20, &p),
            HintSpec::Hull { bits: small }
        );
        assert_eq!(
            resolve_bits(HintSpec::Block { bits: 8 }, 10_000, 20, &p),
            HintSpec::Block { bits: 8 }
        );
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(make_lookup(0, &[], None).is_err());
        assert!(make_lookup(20, &[0u8; 21], None).is_err());
        assert!(build_hint(20, &[0u8; 20], HintSpec::Hull { bits: 40 }).is_err());
        assert!(build_hint(20, &[0u8; 20], HintSpec::Block { bits: 0 }).is_err());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(26)]
    fn bits_policy_choose_within_bounds() {
        let p = BitsPolicy {
            budget: kani::any(),
            min_bits: kani::any(),
            max_bits: kani::any(),
        };
        kani::assume(p.min_bits <= p.max_bits && p.max_bits <= 24);
        kani::assume(p.budget.is_finite() && p.budget >= 0.0);
        let n: usize = kani::any();
        let hash_length: usize = kani::any();
        let entry_len: usize = kani::any();
        let bits = p.choose(n, hash_length, entry_len);
        assert!((p.min_bits..=p.max_bits).contains(&bits));
    }
}
