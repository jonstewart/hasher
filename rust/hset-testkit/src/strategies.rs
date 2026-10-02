//! Proptest strategies over the document model and the lookup engine, plus
//! the shared [`LookupCase`] type and the deterministic [`queries`] builder
//! (shared with the fuzz `lookup` target).
//!
//! Every hint a strategy produces has at most 12 bits.

use hset::lookup::{BatchMode, BitsPolicy, HintSpec, SearchConfig, SingleMode};
use hset::synth::{SplitMix64, adversarial_hashes, sort_unique_rows};
use hset::{HashType, SetOp};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;

use crate::doc::{Doc, Field, Opts, STORABLE_TYPES};

/// Hash lengths the lookup engine supports.
pub const SUPPORTED_LENGTHS: [usize; 8] = [4, 8, 16, 20, 28, 32, 48, 64];
/// A length with no hint support: only `HintSpec::None` applies.
pub const UNSUPPORTED_LENGTH: usize = 12;

/// Every single-lookup mode.
pub(crate) const SINGLE_MODES: [SingleMode; 4] = [
    SingleMode::Auto,
    SingleMode::KAry,
    SingleMode::Binary,
    SingleMode::Recursive,
];
/// Every batch-lookup mode.
pub(crate) const BATCH_MODES: [BatchMode; 4] = [
    BatchMode::Auto,
    BatchMode::Staged,
    BatchMode::Lanes,
    BatchMode::Passes,
];
/// Document timestamps: a normal one, the epoch, and empty.
pub(crate) const TIMESTAMPS: [&str; 3] = ["2024-01-01T00:00:00Z", "1970-01-01T00:00:00Z", ""];
/// Bits-policy budgets: none, the default, and unbounded.
pub(crate) const BUDGETS: [f64; 3] = [0.0, 0.02, 1.0];
/// Bytes that make dense shared prefixes.
pub(crate) const DENSE_BYTES: [u8; 3] = [0x00, 0x80, 0xFF];

/// One lookup scenario: sorted rows (duplicates allowed), the hint to build,
/// the search tunables and the queries to run.
#[derive(Debug, Clone, PartialEq)]
pub struct LookupCase {
    pub hlen: usize,
    pub data: Vec<u8>,
    pub hint: HintSpec,
    pub cfg: SearchConfig,
    pub queries: Vec<u8>,
}

/// A supported length or the unsupported one.
pub fn hash_lengths() -> BoxedStrategy<usize> {
    let mut lengths = SUPPORTED_LENGTHS.to_vec();
    lengths.push(UNSUPPORTED_LENGTH);
    select(lengths).boxed()
}

/// Hints valid for `hlen`: only `None` for the unsupported length; `Block`
/// (1..=12 bits) only when `hlen >= 4`; `Hull` (0..=12 bits).
pub fn hint_specs(hlen: usize) -> BoxedStrategy<HintSpec> {
    if hlen == UNSUPPORTED_LENGTH {
        return Just(HintSpec::None).boxed();
    }
    let hull = (0..=12u8).prop_map(|bits| HintSpec::Hull { bits });
    if hlen >= 4 {
        prop_oneof![
            Just(HintSpec::None),
            (1..=12u8).prop_map(|bits| HintSpec::Block { bits }),
            hull,
        ]
        .boxed()
    } else {
        prop_oneof![Just(HintSpec::None), hull].boxed()
    }
}

/// Every mode pair, with prefetch/region sizes down to a single hash and
/// sub-batch sizes including the 0 and 1000 edges.
pub fn search_configs() -> BoxedStrategy<SearchConfig> {
    (
        select(SINGLE_MODES.to_vec()),
        select(BATCH_MODES.to_vec()),
        1..=4096usize,
        1..=4096usize,
        prop_oneof![1..=256usize, Just(0), Just(1000)],
    )
        .prop_map(
            |(single, batch, window_prefetch_bytes, region_bytes, passes_sub_batch)| SearchConfig {
                single,
                batch,
                window_prefetch_bytes,
                region_bytes,
                passes_sub_batch,
            },
        )
        .boxed()
}

/// Sorted, unique `hlen`-byte rows (at most `max_n`): uniform random,
/// adversarially clustered, or drawn from a three-byte alphabet.
pub fn sorted_rows(hlen: usize, max_n: usize) -> BoxedStrategy<Vec<u8>> {
    let sorted = move |mut data: Vec<u8>| {
        sort_unique_rows(&mut data, hlen);
        data
    };
    prop_oneof![
        (0..=max_n)
            .prop_flat_map(move |n| vec(any::<u8>(), n * hlen))
            .prop_map(sorted),
        (0..=max_n, any::<u64>())
            .prop_map(move |(count, seed)| adversarial_hashes(count, hlen, seed)),
        (0..=max_n)
            .prop_flat_map(move |n| vec(select(DENSE_BYTES.to_vec()), n * hlen))
            .prop_map(sorted),
    ]
    .boxed()
}

/// `rows` with row `i` repeated once when `dup_mask[i % dup_mask.len()]`;
/// order is kept. An empty mask adds nothing.
pub fn with_duplicates(rows: Vec<u8>, hlen: usize, dup_mask: &[bool]) -> Vec<u8> {
    if dup_mask.is_empty() {
        return rows;
    }
    let mut out = Vec::with_capacity(rows.len() * 2);
    for (i, row) in rows.chunks_exact(hlen).enumerate() {
        out.extend_from_slice(row);
        if dup_mask[i % dup_mask.len()] {
            out.extend_from_slice(row);
        }
    }
    out
}

/// `row - 1` as a big-endian integer, saturating at all zeros.
fn be_dec(row: &[u8]) -> Vec<u8> {
    let mut out = row.to_vec();
    if let Some(i) = out.iter().rposition(|&b| b != 0) {
        out[i] -= 1;
        out[i + 1..].fill(0xFF);
    }
    out
}

/// `row + 1` as a big-endian integer, saturating at all `0xFF`.
fn be_inc(row: &[u8]) -> Vec<u8> {
    let mut out = row.to_vec();
    if let Some(i) = out.iter().rposition(|&b| b != 0xFF) {
        out[i] += 1;
        out[i + 1..].fill(0);
    }
    out
}

/// Deterministic queries against the sorted rows `set`: the boundary hashes
/// all `0x00` and all `0xFF`, then (when `set` is non-empty) first-1,
/// first+1, last-1 and last+1 as big-endian integers (saturating), then `m`
/// hashes mixing hits, random misses and one-bit near misses drawn by
/// `SplitMix64(seed)`.
pub fn queries(set: &[u8], hlen: usize, seed: u64, m: usize) -> Vec<u8> {
    let n = set.len() / hlen;
    let mut out = vec![0x00; hlen];
    out.resize(2 * hlen, 0xFF);
    if n > 0 {
        let first = &set[..hlen];
        let last = &set[(n - 1) * hlen..n * hlen];
        for b in [be_dec(first), be_inc(first), be_dec(last), be_inc(last)] {
            out.extend_from_slice(&b);
        }
    }
    let mut rng = SplitMix64::new(seed);
    let mut q = vec![0u8; hlen];
    for _ in 0..m {
        let kind = if n == 0 { 1 } else { rng.below(3) };
        if kind == 1 {
            rng.fill(&mut q);
        } else {
            let i = rng.below(n as u64) as usize;
            q.copy_from_slice(&set[i * hlen..(i + 1) * hlen]);
            if kind == 2 {
                let bit = rng.below(8 * hlen as u64) as usize;
                q[bit / 8] ^= 1 << (bit % 8);
            }
        }
        out.extend_from_slice(&q);
    }
    out
}

/// A field of `htype` named canonically, from a broad ASCII set, or with
/// a non-ASCII letter (at most 32 bytes either way).
pub fn field(htype: HashType) -> BoxedStrategy<Field> {
    prop_oneof![
        Just(htype.field_name().to_string()),
        "[a-zA-Z0-9_ -]{0,32}",
        "[a-zé]{0,16}",
    ]
    .prop_map(move |name| Field { htype, name })
    .boxed()
}

/// `1..=max_fields` fields of distinct storable types.
pub fn fields(max_fields: usize) -> BoxedStrategy<Vec<Field>> {
    (Just(STORABLE_TYPES.to_vec()).prop_shuffle(), 1..=max_fields)
        .prop_flat_map(|(types, k)| types[..k].iter().map(|&t| field(t)).collect::<Vec<_>>())
        .boxed()
}

/// A value of `htype`: digests uniform or from a three-byte alphabet; sizes
/// any `u64` LE; entropies any finite `f64` LE (so text round-trips).
pub fn value(htype: HashType) -> BoxedStrategy<Vec<u8>> {
    match htype {
        HashType::Size => any::<u64>().prop_map(|v| v.to_le_bytes().to_vec()).boxed(),
        HashType::Entropy => any::<f64>()
            .prop_filter("finite", |v| v.is_finite())
            .prop_map(|v| v.to_le_bytes().to_vec())
            .boxed(),
        _ => {
            let len = htype.length().expect("storable type");
            prop_oneof![
                vec(any::<u8>(), len),
                vec(select(DENSE_BYTES.to_vec()), len),
            ]
            .boxed()
        }
    }
}

/// One record over `fields`, each value present with weight 3:1.
pub fn record(fields: &[Field]) -> BoxedStrategy<Vec<Option<Vec<u8>>>> {
    fields
        .iter()
        .map(|f| prop::option::weighted(0.75, value(f.htype)))
        .collect::<Vec<_>>()
        .boxed()
}

/// Bits policies with bits at most 12.
fn bits_policies() -> BoxedStrategy<BitsPolicy> {
    (select(BUDGETS.to_vec()), 0..=4u8)
        .prop_flat_map(|(budget, min_bits)| {
            (min_bits..=12u8).prop_map(move |max_bits| BitsPolicy {
                budget,
                min_bits,
                max_bits,
            })
        })
        .boxed()
}

/// Build options; never both records and hash sets off.
pub fn opts() -> BoxedStrategy<Opts> {
    (
        "[ -~]{0,32}",
        "[ -~]{0,32}",
        select(TIMESTAMPS.to_vec()),
        select(vec![(true, true), (true, false), (false, true)]),
        prop_oneof![
            hint_specs(8),
            Just(HintSpec::Hull { bits: u8::MAX }),
            Just(HintSpec::Block { bits: 0 }),
        ],
        bits_policies(),
    )
        .prop_map(
            |(name, desc, timestamp, (with_records, with_hashsets), hint, bits_policy)| Opts {
                name,
                desc,
                timestamp: timestamp.to_string(),
                with_records,
                with_hashsets,
                hint,
                bits_policy,
            },
        )
        .boxed()
}

/// A document with at most `max_fields` fields and `max_records` records.
pub fn doc_with(max_fields: usize, max_records: usize) -> BoxedStrategy<Doc> {
    fields(max_fields)
        .prop_flat_map(move |fields| (vec(record(&fields), 0..=max_records), opts(), Just(fields)))
        .prop_map(|(records, opts, fields)| Doc {
            fields,
            records,
            opts,
        })
        .boxed()
}

/// A document with at most 4 fields and 64 records.
pub fn doc() -> BoxedStrategy<Doc> {
    doc_with(4, 64)
}

/// Two documents over the same field types: `b` keeps `a`'s fields in order
/// or reversed, holds a masked subset of `a`'s records (values permuted to
/// its field order) plus up to 16 fresh records, and has fresh options.
pub fn doc_pair() -> BoxedStrategy<(Doc, Doc)> {
    doc()
        .prop_flat_map(|a| {
            let n = a.records.len();
            (
                any::<bool>(),
                vec(any::<bool>(), n),
                vec(record(&a.fields), 0..=16),
                opts(),
                Just(a),
            )
        })
        .prop_map(|(reverse, keep, fresh, opts, a)| {
            fn permute<T>(mut v: Vec<T>, reverse: bool) -> Vec<T> {
                if reverse {
                    v.reverse();
                }
                v
            }
            let records = a
                .records
                .iter()
                .zip(&keep)
                .filter(|(_, k)| **k)
                .map(|(r, _)| r.clone())
                .chain(fresh)
                .map(|r| permute(r, reverse))
                .collect();
            let b = Doc {
                fields: permute(a.fields.clone(), reverse),
                records,
                opts,
            };
            (a, b)
        })
        .boxed()
}

/// Two documents whose field type sets differ.
pub fn doc_pair_mismatched() -> BoxedStrategy<(Doc, Doc)> {
    (doc(), doc())
        .prop_filter("field type sets differ", |(a, b)| {
            let types = |d: &Doc| {
                let mut t: Vec<HashType> = d.fields.iter().map(|f| f.htype).collect();
                t.sort();
                t
            };
            types(a) != types(b)
        })
        .boxed()
}

/// A document `hset make` can express: canonical names, records and hash
/// sets, and the default bits policy apart from the budget.
pub fn cli_doc() -> BoxedStrategy<Doc> {
    doc()
        .prop_map(|mut d| {
            for f in &mut d.fields {
                *f = Field::canonical(f.htype);
            }
            d.opts.with_records = true;
            d.opts.with_hashsets = true;
            d.opts.bits_policy = BitsPolicy {
                budget: d.opts.bits_policy.budget,
                ..BitsPolicy::default()
            };
            d
        })
        .boxed()
}

pub fn set_op() -> BoxedStrategy<SetOp> {
    select(vec![SetOp::Union, SetOp::Intersect, SetOp::Subtract]).boxed()
}

/// Sorted rows (up to 2000, some duplicated), a hint valid for the length,
/// any search config and up to 300 queries after the boundaries.
pub fn lookup_case() -> BoxedStrategy<LookupCase> {
    hash_lengths()
        .prop_flat_map(|hlen| {
            (
                Just(hlen),
                sorted_rows(hlen, 2000),
                vec(any::<bool>(), 0..=8),
                hint_specs(hlen),
                search_configs(),
                any::<u64>(),
                0..=300usize,
            )
        })
        .prop_map(|(hlen, set, mask, hint, cfg, seed, m)| LookupCase {
            hlen,
            queries: queries(&set, hlen, seed, m),
            data: with_duplicates(set, hlen, &mask),
            hint,
            cfg,
        })
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use std::collections::BTreeSet;

    fn type_set(d: &Doc) -> BTreeSet<HashType> {
        d.fields.iter().map(|f| f.htype).collect()
    }

    #[test]
    fn hint_specs_for_unsupported_length_is_none() {
        let mut runner = TestRunner::deterministic();
        let s = hint_specs(UNSUPPORTED_LENGTH);
        for _ in 0..50 {
            let h = s.new_tree(&mut runner).unwrap().current();
            assert_eq!(h, HintSpec::None);
        }
    }

    #[test]
    fn hint_specs_bits_stay_at_most_12() {
        let mut runner = TestRunner::deterministic();
        let s = hint_specs(20);
        for _ in 0..200 {
            match s.new_tree(&mut runner).unwrap().current() {
                HintSpec::None => {}
                HintSpec::Block { bits } => assert!((1..=12).contains(&bits), "block bits {bits}"),
                HintSpec::Hull { bits } => assert!(bits <= 12, "hull bits {bits}"),
            }
        }
    }

    proptest! {
        #[test]
        fn sorted_rows_are_sorted(rows in sorted_rows(20, 500)) {
            prop_assert_eq!(rows.len() % 20, 0);
            let (chunks, _) = rows.as_chunks::<20>();
            for w in chunks.windows(2) {
                prop_assert!(w[0] < w[1], "rows not strictly increasing");
            }
        }
    }

    #[test]
    fn with_duplicates_keeps_order() {
        let rows = vec![1, 1, 2, 2, 3, 3];
        let out = with_duplicates(rows, 2, &[true, false, true]);
        assert_eq!(out, vec![1, 1, 1, 1, 2, 2, 3, 3, 3, 3]);
    }

    #[test]
    fn queries_start_with_boundaries() {
        let set = [
            [0x10, 0x00, 0x00, 0x05],
            [0x20, 0x00, 0x00, 0x00],
            [0x30, 0xff, 0xff, 0xff],
        ]
        .concat();
        let m = 7;
        let q = queries(&set, 4, 42, m);
        assert_eq!(q.len(), (6 + m) * 4);
        let (rows, _) = q.as_chunks::<4>();
        assert_eq!(rows[0], [0x00; 4]);
        assert_eq!(rows[1], [0xff; 4]);
        assert_eq!(rows[2], [0x10, 0x00, 0x00, 0x04]);
        assert_eq!(rows[3], [0x10, 0x00, 0x00, 0x06]);
        assert_eq!(rows[4], [0x30, 0xff, 0xff, 0xfe]);
        assert_eq!(rows[5], [0x31, 0x00, 0x00, 0x00]);

        let empty = queries(&[], 4, 42, m);
        assert_eq!(empty.len(), (2 + m) * 4);
        assert_eq!(&empty[..4], [0x00; 4]);
        assert_eq!(&empty[4..8], [0xff; 4]);
    }

    #[test]
    fn queries_carry_across_bytes() {
        let set = [[0x00, 0x00, 0x01, 0x00], [0xff, 0xff, 0xff, 0xff]].concat();
        let q = queries(&set, 4, 1, 0);
        let (rows, _) = q.as_chunks::<4>();
        assert_eq!(rows[2], [0x00, 0x00, 0x00, 0xff]);
        assert_eq!(rows[3], [0x00, 0x00, 0x01, 0x01]);
        assert_eq!(rows[4], [0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(rows[5], [0xff; 4]);
    }

    proptest! {
        #[test]
        fn doc_pair_shares_types((a, b) in doc_pair()) {
            prop_assert_eq!(type_set(&a), type_set(&b));
            prop_assert!(b.records.len() <= a.records.len() + 16);
        }

        #[test]
        fn doc_pair_mismatched_differs((a, b) in doc_pair_mismatched()) {
            prop_assert_ne!(type_set(&a), type_set(&b));
        }

        #[test]
        fn cli_doc_is_canonical(d in cli_doc()) {
            for f in &d.fields {
                prop_assert_eq!(f.name.as_str(), f.htype.field_name());
            }
            prop_assert!(d.opts.with_records && d.opts.with_hashsets);
        }

        #[test]
        fn entropy_values_are_finite(v in value(HashType::Entropy)) {
            let bytes: [u8; 8] = v.as_slice().try_into().unwrap();
            prop_assert!(f64::from_le_bytes(bytes).is_finite());
        }
    }
}
