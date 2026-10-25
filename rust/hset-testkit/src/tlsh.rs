//! TLSH test data: the reference implementation's example digests and
//! distance scores (vendored from `vendors/tlsh/Testing/exp/` into
//! `rust/hset/tests/data/tlsh/`, so `cargo-mutants`' copy of the workspace
//! has them), and the text fixture the C++ TLSH hash-set tests build from.
//!
//! Everything here is plain strings and numbers read from the files or
//! written out by hand, not values computed with `hset::tlsh`.
//!
//! The second half is digest-space test data and oracles for the kNN
//! searches and index builders: seeded, deterministic corpora of random
//! digests, near-digest families and perturbations (C++ `tlsh_corpus.cpp`'s
//! `perturb_tlsh_corpus`; the hashed-content families need the TLSH hasher,
//! which is not ported, so families here are perturbations of a random
//! base), a bucket-by-bucket reference distance [`ref_diff`], the naive kNN
//! oracle [`naive_knn`] and a counting cell index [`naive_cell_index`].
//! These use only [`TlshDigest`]'s field accessors and constructor, never
//! `hset::tlsh`'s distance kernel or search code.

use std::fs;
use std::path::PathBuf;

use hset::synth::SplitMix64;
use hset::tlsh::TlshDigest;
use hset::tlsh::knn::TlshMatch;

/// The first example digest (`example_data/021106_yossivassa.txt`), the
/// C++ tests' `VEC_HEX`.
pub const VEC_HEX: &str =
    "T11FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE";

/// Directory holding the vendored reference files.
pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hset/tests/data/tlsh")
}

fn read_data(name: &str) -> String {
    let path = data_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The 80 `(hex digest, file name)` pairs of
/// `example_data.128.1.len.out_EXP`, in file order.
///
/// Read as the C++ tests read it (`in >> hex >> path`): whitespace-separated
/// tokens taken two at a time.
pub fn example_entries() -> Vec<(String, String)> {
    let text = read_data("example_data.128.1.len.out_EXP");
    let tokens: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(tokens.len() % 2, 0, "len.out_EXP has an odd token count");
    let v: Vec<(String, String)> = tokens
        .chunks(2)
        .map(|p| (p[0].to_string(), p[1].to_string()))
        .collect();
    assert_eq!(v.len(), 80);
    v
}

/// The 80 example hex digests, in file order (`read_example_digests` in
/// `test_hset_tlsh.cpp`).
pub fn example_digests() -> Vec<String> {
    example_entries().into_iter().map(|(hex, _)| hex).collect()
}

/// Hex digest of an example file by name, as in the entries.
pub fn example_digest_of(path: &str) -> String {
    example_entries()
        .into_iter()
        .find(|(_, p)| p == path)
        .map(|(hex, _)| hex)
        .unwrap_or_else(|| panic!("no example digest for {path}"))
}

/// The 80 `(file a, file b, score)` triples of the reference's distance
/// scores: `example_data.128.1.len.scores_EXP` (`include_length` true) or
/// `example_data.128.1.xlen.scores_EXP` (false). Read as the C++ test does
/// (`in >> a >> b >> score`).
pub fn example_scores(include_length: bool) -> Vec<(String, String, u32)> {
    let name = if include_length {
        "example_data.128.1.len.scores_EXP"
    } else {
        "example_data.128.1.xlen.scores_EXP"
    };
    let text = read_data(name);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(
        tokens.len() % 3,
        0,
        "{name} has a token count not a multiple of 3"
    );
    let v: Vec<(String, String, u32)> = tokens
        .chunks(3)
        .map(|t| {
            let score = t[2]
                .parse()
                .unwrap_or_else(|_| panic!("{name}: bad score {:?}", t[2]));
            (t[0].to_string(), t[1].to_string(), score)
        })
        .collect();
    assert_eq!(v.len(), 80);
    v
}

/// A distinct, deterministic 32-digit hex "md5" per index, as `fake_md5` in
/// `test_hset_tlsh.cpp`: `i * 2654435761 + 0x9E3779B9` (wrapping `u64`)
/// zero-padded to 32 lowercase hex digits.
pub fn fake_md5(i: u64) -> String {
    format!(
        "{:032x}",
        i.wrapping_mul(2_654_435_761).wrapping_add(0x9E37_79B9)
    )
}

/// The two-column text of `make_fixture` in `test_hset_tlsh.cpp`, one
/// `"<md5> <tlsh>\n"` line per record (`"<tlsh> <md5>\n"` with
/// `tlsh_first`): the 80 example digests with `fake_md5(0..80)`, then
/// `fake_md5(80)` with `TNULL`, `fake_md5(81)` with an empty TLSH column
/// (the line keeps its separating space), and `fake_md5(82)` with
/// example digest 7 again. 83 records, 81 TLSH rows, 80 distinct digests.
pub fn example_text(tlsh_first: bool) -> String {
    let digests = example_digests();
    let mut tlsh: Vec<&str> = digests.iter().map(String::as_str).collect();
    tlsh.push("TNULL");
    tlsh.push("");
    tlsh.push(&digests[7]);
    let mut out = String::new();
    for (i, t) in tlsh.iter().enumerate() {
        let md5 = fake_md5(i as u64);
        if tlsh_first {
            out.push_str(&format!("{t} {md5}\n"));
        } else {
            out.push_str(&format!("{md5} {t}\n"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Reference distance and the naive kNN oracle
// ---------------------------------------------------------------------------

/// Circular distance of `x` and `y` modulo `r`.
fn circ(x: u8, y: u8, r: u32) -> u32 {
    let d = u32::from(x.abs_diff(y));
    d.min(r - d)
}

fn ref_l_cost(k: u32) -> u32 {
    match k {
        0 => 0,
        1 => 1,
        _ => 12 * k,
    }
}

fn ref_q_cost(k: u32) -> u32 {
    if k <= 1 { k } else { 12 * (k - 1) }
}

/// Per-bucket body cost for `|code_a - code_b|` = 0, 1, 2, 3.
const REF_BODY_COST: [u32; 4] = [0, 1, 2, 6];

/// The TLSH distance written bucket by bucket from the reference
/// implementation's `totalDiff` rules, without the null check: checksum
/// mismatch, L cost (with `include_length`), Q1 and Q2 costs, and per
/// bucket 0, 1, 2, 6 for a code difference of 0, 1, 2, 3. This is what
/// the searches compute for every row, null or not.
pub fn ref_distance(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> u32 {
    let l = if include_length {
        ref_l_cost(circ(a.l(), b.l(), 256))
    } else {
        0
    };
    let body: u32 = (0..128)
        .map(|i| REF_BODY_COST[usize::from(a.bucket(i).abs_diff(b.bucket(i)))])
        .sum();
    u32::from(a.checksum() != b.checksum())
        + l
        + ref_q_cost(circ(a.q1(), b.q1(), 16))
        + ref_q_cost(circ(a.q2(), b.q2(), 16))
        + body
}

/// [`ref_distance`], or `None` when either digest is null (as
/// `sfhash_tlsh_diff` returns -1).
pub fn ref_diff(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> Option<u32> {
    if a.is_null() || b.is_null() {
        None
    } else {
        Some(ref_distance(a, b, include_length))
    }
}

/// The kNN specification, computed the slow way (`naive_knn` in
/// `test_hset_tlsh.cpp`): every row's [`ref_distance`] from `q`, those at
/// most `max_distance`, sorted by `(distance, index)`, the first `k`.
/// Empty for a null query.
pub fn naive_knn(
    rows: &[[u8; 36]],
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
) -> Vec<TlshMatch> {
    if q.is_null() {
        return Vec::new();
    }
    let mut all: Vec<TlshMatch> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| TlshMatch {
            index: i as u64,
            distance: ref_distance(q, &TlshDigest(*r), include_length),
        })
        .filter(|m| m.distance <= max_distance)
        .collect();
    all.sort_by_key(|m| (m.distance, m.index));
    all.truncate(k);
    all
}

/// The 65,537-entry cell index of sorted `rows`, by counting: entry `c` is
/// the number of rows whose cell (`(L << 8) | Q`, the first two bytes big
/// endian) is below `c`.
///
/// # Panics
///
/// If `rows` is not sorted.
pub fn naive_cell_index(rows: &[[u8; 36]]) -> Vec<u64> {
    assert!(rows.is_sorted(), "cell index of unsorted rows");
    let mut cells = vec![0u64; 65537];
    for r in rows {
        cells[usize::from(r[0]) << 8 | usize::from(r[1])] += 1;
    }
    let mut sum = 0;
    for c in &mut cells {
        let count = *c;
        *c = sum;
        sum += count;
    }
    cells
}

// ---------------------------------------------------------------------------
// Digest-space corpora
// ---------------------------------------------------------------------------

/// Uniform in `[0, 1)` from the top 53 bits of one draw.
fn unit(rng: &mut SplitMix64) -> f64 {
    (rng.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
}

fn chance(rng: &mut SplitMix64, p: f64) -> bool {
    unit(rng) < p
}

/// Replace the null digest by the same digest with checksum 1, so
/// generated rows are never absent.
fn non_null(d: TlshDigest) -> TlshDigest {
    if d.is_null() {
        let mut b = d.0;
        b[34] = 1;
        TlshDigest(b)
    } else {
        d
    }
}

/// A digest with the given header, uniformly random bucket codes and a
/// random checksum; never null.
pub fn random_digest_with_header(rng: &mut SplitMix64, l: u8, q1: u8, q2: u8) -> TlshDigest {
    let mut codes = [0u8; 128];
    for chunk in codes.as_chunks_mut::<32>().0 {
        let mut bits = rng.next_u64();
        for c in chunk {
            *c = (bits & 3) as u8;
            bits >>= 2;
        }
    }
    let checksum = rng.next_u64() as u8;
    non_null(TlshDigest::from_parts(l, q1, q2, checksum, &codes))
}

/// A uniformly random digest (L, Q1, Q2, checksum and codes); never null.
pub fn random_digest(rng: &mut SplitMix64) -> TlshDigest {
    let h = rng.next_u64();
    random_digest_with_header(rng, h as u8, (h >> 8) as u8 & 0x0F, (h >> 12) as u8 & 0x0F)
}

/// How [`perturb`] moves a digest.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Perturbation {
    /// Probability that each bucket code moves by +-1 (clamped to 0..=3).
    pub bucket_flip_prob: f64,
    /// Probability of each header move: L by +-1 or +-2 (clamped to
    /// 0..=255), Q1 by +-1 (mod 16), Q2 by +-1 (mod 16). Zero keeps the
    /// digest in its cell.
    pub header_prob: f64,
    /// Draw a fresh random checksum (else keep the seed's).
    pub random_checksum: bool,
}

impl Default for Perturbation {
    /// C++ `perturb_tlsh_corpus`'s defaults: bucket moves at 0.05, header
    /// moves at 0.1, random checksum.
    fn default() -> Self {
        Self {
            bucket_flip_prob: 0.05,
            header_prob: 0.1,
            random_checksum: true,
        }
    }
}

impl Perturbation {
    /// Bucket moves at `bucket_flip_prob` only: same header and checksum,
    /// so the result stays in the seed's cell.
    pub fn body_only(bucket_flip_prob: f64) -> Self {
        Self {
            bucket_flip_prob,
            header_prob: 0.0,
            random_checksum: false,
        }
    }
}

/// A near copy of `seed` (C++ `perturb` in `tlsh_corpus.cpp`, with its
/// probabilities as parameters); never null. Duplicates of the seed are
/// possible.
pub fn perturb(rng: &mut SplitMix64, seed: &TlshDigest, p: &Perturbation) -> TlshDigest {
    let mut codes = [0u8; 128];
    for (b, c) in codes.iter_mut().enumerate() {
        let mut v = i32::from(seed.bucket(b));
        if chance(rng, p.bucket_flip_prob) {
            v += if chance(rng, 0.5) { 1 } else { -1 };
            v = v.clamp(0, 3);
        }
        *c = v as u8;
    }

    let mut l = i32::from(seed.l());
    if chance(rng, p.header_prob) {
        let step = 1 + rng.below(2) as i32;
        l += if chance(rng, 0.5) { step } else { -step };
        l = l.clamp(0, 255);
    }
    let mut q1 = seed.q1();
    if chance(rng, p.header_prob) {
        q1 = (q1 + if chance(rng, 0.5) { 1 } else { 15 }) & 0x0F;
    }
    let mut q2 = seed.q2();
    if chance(rng, p.header_prob) {
        q2 = (q2 + if chance(rng, 0.5) { 1 } else { 15 }) & 0x0F;
    }
    let checksum = if p.random_checksum {
        rng.next_u64() as u8
    } else {
        seed.checksum()
    };
    non_null(TlshDigest::from_parts(l as u8, q1, q2, checksum, &codes))
}

/// A base digest and near copies of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlshFamily {
    pub base: TlshDigest,
    pub variants: Vec<TlshDigest>,
}

/// `families` families, each a [`random_digest`] base and
/// `variants_per_family` [`perturb`]ations of it. Deterministic in `seed`.
pub fn families(
    seed: u64,
    families: usize,
    variants_per_family: usize,
    p: &Perturbation,
) -> Vec<TlshFamily> {
    let mut rng = SplitMix64::new(seed);
    (0..families)
        .map(|_| {
            let base = random_digest(&mut rng);
            let variants = (0..variants_per_family)
                .map(|_| perturb(&mut rng, &base, p))
                .collect();
            TlshFamily { base, variants }
        })
        .collect()
}

/// [`families`], flattened: base then variants, family by family.
pub fn family_corpus(
    seed: u64,
    families: usize,
    variants_per_family: usize,
    p: &Perturbation,
) -> Vec<TlshDigest> {
    self::families(seed, families, variants_per_family, p)
        .into_iter()
        .flat_map(|f| std::iter::once(f.base).chain(f.variants))
        .collect()
}

/// `n` perturbations of digests drawn uniformly from `seeds` (C++
/// `perturb_tlsh_corpus`). Empty if `seeds` is.
pub fn perturb_corpus(
    seed: u64,
    seeds: &[TlshDigest],
    n: usize,
    p: &Perturbation,
) -> Vec<TlshDigest> {
    if seeds.is_empty() {
        return Vec::new();
    }
    let mut rng = SplitMix64::new(seed);
    (0..n)
        .map(|_| {
            let s = seeds[rng.below(seeds.len() as u64) as usize];
            perturb(&mut rng, &s, p)
        })
        .collect()
}

/// Exactly `n` digests in families of 10 under the default
/// [`Perturbation`]: clusters of near digests spread over many cells,
/// with neighbouring cells populated by the header moves.
pub fn corpus(seed: u64, n: usize) -> Vec<TlshDigest> {
    let mut v = family_corpus(seed, n.div_ceil(10), 9, &Perturbation::default());
    v.truncate(n);
    v
}

/// Exactly `n` digests all in the cell of header `(l, q1, q2)`:
/// `families` random bases with that header, each perturbed
/// [`body_only`](Perturbation::body_only) at `bucket_flip_prob`, with
/// rows assigned to families round robin. For tests of builds and
/// searches inside one large cell.
///
/// # Panics
///
/// If `families` is 0 and `n` is not.
pub fn cell_corpus(
    seed: u64,
    n: usize,
    (l, q1, q2): (u8, u8, u8),
    families: usize,
    bucket_flip_prob: f64,
) -> Vec<TlshDigest> {
    assert!(n == 0 || families > 0, "cell_corpus needs a family");
    let mut rng = SplitMix64::new(seed);
    let bases: Vec<TlshDigest> = (0..families)
        .map(|_| random_digest_with_header(&mut rng, l, q1, q2))
        .collect();
    let p = Perturbation::body_only(bucket_flip_prob);
    (0..n)
        .map(|i| perturb(&mut rng, &bases[i % families], &p))
        .collect()
}

/// The digests as sorted rows (the shape of a TLSH section's `HDAT`),
/// duplicates kept, as in a records file.
pub fn sorted_rows(digests: &[TlshDigest]) -> Vec<[u8; 36]> {
    let mut rows: Vec<[u8; 36]> = digests.iter().map(|d| d.0).collect();
    rows.sort_unstable();
    rows
}

// ---------------------------------------------------------------------------
// Values of generated documents
// ---------------------------------------------------------------------------

/// The kinds of [`doc_value`]: random, family base, three of near copies in
/// the base's cell, near copies with header moves.
pub const DOC_VALUE_KINDS: u8 = 6;
/// The families [`doc_value`] draws from.
pub const DOC_FAMILIES: u8 = 4;
/// The seeds a near copy of [`doc_value`] takes, per family and kind.
pub const DOC_VARIANTS: u64 = 8;

/// A TLSH value for a generated document, canonical and never null: kind 0
/// a random digest (seeded by `variant`); 1 the base of family
/// `family % DOC_FAMILIES`; 2..=4 a near copy of that base in its cell
/// (bucket moves only); 5 a near copy with header moves too, often in a
/// neighbouring cell. A near copy is seeded by `variant % DOC_VARIANTS`, so
/// equal draws are equal rows. With so few families and seeds the records
/// of one document, and of a document pair, share cells and rows: cells
/// hold several rows (and so several `TIVF` lists), and rows repeat.
pub fn doc_value(kind: u8, family: u8, variant: u64) -> TlshDigest {
    if kind == 0 {
        return random_digest(&mut SplitMix64::new(variant));
    }
    let family = u64::from(family % DOC_FAMILIES);
    let base = random_digest(&mut SplitMix64::new(DOC_FAMILY_SEED + family));
    let (class, p) = match kind {
        1 => return base,
        2..=4 => (0, Perturbation::body_only(0.05)),
        _ => (1, Perturbation::default()),
    };
    let seed = DOC_FAMILY_SEED ^ (family << 8) ^ (class << 16) ^ (variant % DOC_VARIANTS);
    perturb(&mut SplitMix64::new(seed), &base, &p)
}

/// The seed space of [`doc_value`]'s families.
const DOC_FAMILY_SEED: u64 = 0x7154_0000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_md5_matches_hand_values() {
        // 0 * 2654435761 + 0x9E3779B9; 1 * 2654435761 = 0x9E3779B1.
        assert_eq!(fake_md5(0), "0000000000000000000000009e3779b9");
        assert_eq!(fake_md5(1), "0000000000000000000000013c6ef36a");
    }

    #[test]
    fn example_text_has_83_lines_and_the_special_rows() {
        let t = example_text(false);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 83);
        assert_eq!(lines[0], format!("{} {VEC_HEX}", fake_md5(0)));
        assert_eq!(lines[80], format!("{} TNULL", fake_md5(80)));
        assert_eq!(lines[81], format!("{} ", fake_md5(81)));
        assert_eq!(lines[82].split(' ').nth(1), lines[7].split(' ').nth(1));
        let f = example_text(true);
        assert_eq!(
            f.lines().nth(81),
            Some(format!(" {}", fake_md5(81)).as_str())
        );
        assert_eq!(
            f.lines().next(),
            Some(format!("{VEC_HEX} {}", fake_md5(0)).as_str())
        );
    }

    fn digest(hex: &str) -> TlshDigest {
        TlshDigest::from_hex(hex).unwrap()
    }

    #[test]
    fn ref_diff_matches_the_reference_scores() {
        for include_length in [true, false] {
            for (a, b, score) in example_scores(include_length) {
                let (a, b) = (
                    digest(&example_digest_of(&a)),
                    digest(&example_digest_of(&b)),
                );
                assert_eq!(ref_diff(&a, &b, include_length), Some(score));
                assert_eq!(ref_diff(&b, &a, include_length), Some(score));
            }
        }
        let v = digest(VEC_HEX);
        assert_eq!(ref_diff(&v, &TlshDigest::NULL, true), None);
        assert_eq!(ref_diff(&TlshDigest::NULL, &v, false), None);
        assert_eq!(ref_diff(&v, &v, true), Some(0));
    }

    /// `d` with byte `at` replaced by `v`.
    fn with_byte(d: TlshDigest, at: usize, v: u8) -> TlshDigest {
        let mut b = d.0;
        b[at] = v;
        TlshDigest(b)
    }

    #[test]
    fn naive_knn_filters_sorts_and_truncates() {
        let q = digest(VEC_HEX);
        let other_cs = with_byte(q, 34, q.checksum() ^ 1);
        let longer = with_byte(q, 0, q.l().wrapping_add(1));
        // distances from q with length: 1, 0, 1, 0; without: 1, 0, 0, 0
        let rows = [other_cs.0, q.0, longer.0, q.0];
        let m = |distance, index| TlshMatch { index, distance };
        assert_eq!(
            naive_knn(&rows, &q, 3, 1, true),
            vec![m(0, 1), m(0, 3), m(1, 0)]
        );
        assert_eq!(naive_knn(&rows, &q, 10, 0, true), vec![m(0, 1), m(0, 3)]);
        assert_eq!(
            naive_knn(&rows, &q, 10, 0, false),
            vec![m(0, 1), m(0, 2), m(0, 3)]
        );
        assert_eq!(naive_knn(&rows, &q, 0, 100, true), vec![]);
        assert_eq!(naive_knn(&rows, &TlshDigest::NULL, 4, 100, true), vec![]);
        assert_eq!(naive_knn(&[], &q, 4, 100, true), vec![]);
    }

    #[test]
    fn naive_cell_index_counts_rows_below_each_cell() {
        // cells 0x0000 x2, 0x0102 x2, 0xFFFF x1 (test_hset_tlsh.cpp's
        // tlsh_cell_index case)
        let mut rows = [[0u8; 36]; 5];
        rows[0][34] = 1;
        rows[1][34] = 2;
        rows[2][..2].copy_from_slice(&[1, 2]);
        rows[3][..2].copy_from_slice(&[1, 2]);
        rows[3][34] = 1;
        rows[4][..2].copy_from_slice(&[0xFF, 0xFF]);
        let cells = naive_cell_index(&rows);
        assert_eq!(cells.len(), 65537);
        assert_eq!(cells[0], 0);
        assert_eq!(cells[1], 2);
        assert_eq!(cells[0x0102], 2);
        assert_eq!(cells[0x0103], 4);
        assert_eq!(cells[0xFFFF], 4);
        assert_eq!(cells[0x10000], 5);
    }

    #[test]
    fn generators_are_deterministic_in_the_seed() {
        let p = Perturbation::default();
        let a = family_corpus(7, 6, 4, &p);
        assert_eq!(a.len(), 6 * 5);
        assert_eq!(a, family_corpus(7, 6, 4, &p));
        assert_ne!(a, family_corpus(8, 6, 4, &p));
        assert_eq!(corpus(1, 2500), corpus(1, 2500));
        assert_ne!(corpus(1, 2500), corpus(2, 2500));
        assert_eq!(
            perturb_corpus(99, &a, 100, &p),
            perturb_corpus(99, &a, 100, &p)
        );
        assert_ne!(
            perturb_corpus(99, &a, 100, &p),
            perturb_corpus(100, &a, 100, &p)
        );
        assert_eq!(
            cell_corpus(3, 50, (1, 2, 3), 4, 0.1),
            cell_corpus(3, 50, (1, 2, 3), 4, 0.1)
        );
    }

    #[test]
    fn generated_digests_are_canonical_and_never_null() {
        let mut all = corpus(5, 1003);
        assert_eq!(all.len(), 1003);
        all.extend(perturb_corpus(
            6,
            &all.clone(),
            500,
            &Perturbation::default(),
        ));
        all.extend(cell_corpus(7, 200, (0, 0, 0), 3, 0.5));
        for d in &all {
            assert!(!d.is_null());
            assert_eq!(d.0[35], 0, "reserved byte");
            assert_eq!(TlshDigest::from_hex(&d.to_hex()).unwrap(), *d);
        }
        assert_eq!(corpus(1, 0), vec![]);
        assert_eq!(perturb_corpus(1, &[], 10, &Perturbation::default()), vec![]);
        assert_eq!(perturb_corpus(1, &all, 0, &Perturbation::default()), vec![]);
    }

    #[test]
    fn variants_cluster_with_their_base() {
        let fams = families(3, 20, 6, &Perturbation::default());
        assert_eq!(fams.len(), 20);
        for (i, f) in fams.iter().enumerate() {
            assert_eq!(f.variants.len(), 6);
            for v in &f.variants {
                let own = ref_distance(v, &f.base, true);
                // ~6 bucket moves, a checksum mismatch, and the occasional
                // L/Q nudge (C++ tlsh_corpus_perturb bounds the mean by 30)
                assert!(own < 80, "family {i}: variant at {own}");
                for (j, g) in fams.iter().enumerate() {
                    if j != i {
                        assert!(ref_distance(v, &g.base, true) > own);
                    }
                }
            }
        }
    }

    #[test]
    fn perturbations_stay_near_their_seed() {
        let seeds = family_corpus(5, 4, 3, &Perturbation::default());
        let p = perturb_corpus(99, &seeds, 1000, &Perturbation::default());
        let total: u32 = p
            .iter()
            .map(|d| {
                seeds
                    .iter()
                    .map(|s| ref_distance(d, s, true))
                    .min()
                    .unwrap()
            })
            .sum();
        assert!(f64::from(total) / 1000.0 < 30.0, "mean {total}/1000");
    }

    #[test]
    fn body_only_perturbation_keeps_the_cell_and_checksum() {
        let mut rng = SplitMix64::new(11);
        let s = random_digest(&mut rng);
        let p = Perturbation::body_only(0.3);
        let mut moved = 0;
        for _ in 0..100 {
            let d = perturb(&mut rng, &s, &p);
            assert_eq!(d.cell(), s.cell());
            assert_eq!(d.checksum(), s.checksum());
            moved += u32::from(d != s);
        }
        assert!(moved > 90);
        for d in cell_corpus(12, 300, (0xAB, 0xC, 0xD), 5, 0.05) {
            assert_eq!(d.cell(), 0xABCD);
        }
    }

    #[test]
    fn sorted_rows_sorts_and_keeps_duplicates() {
        let c = corpus(9, 40);
        let mut with_dup = c.clone();
        with_dup.push(c[3]);
        let rows = sorted_rows(&with_dup);
        assert_eq!(rows.len(), 41);
        assert!(rows.is_sorted());
        assert_eq!(rows.iter().filter(|r| **r == c[3].0).count(), 2);
    }

    #[test]
    fn doc_values_are_canonical_share_family_cells_and_repeat() {
        let mut cells = std::collections::BTreeSet::new();
        for family in 0..DOC_FAMILIES {
            let base = doc_value(1, family, 12345);
            assert_eq!(
                base,
                doc_value(1, family + DOC_FAMILIES, 0),
                "family modulo"
            );
            cells.insert(base.cell());
            let mut distinct = std::collections::BTreeSet::new();
            for variant in 0..2 * DOC_VARIANTS {
                for kind in 0..DOC_VALUE_KINDS {
                    let d = doc_value(kind, family, variant);
                    assert!(!d.is_null());
                    assert_eq!(d.0[35], 0, "reserved byte");
                    if (2..=4).contains(&kind) {
                        assert_eq!(d.cell(), base.cell(), "kind {kind} leaves the cell");
                        assert_eq!(d, doc_value(2, family, variant + DOC_VARIANTS));
                        distinct.insert(d);
                    }
                    if kind == 5 {
                        assert_eq!(d, doc_value(5, family, variant + DOC_VARIANTS));
                        assert!(ref_distance(&d, &base, true) < 80);
                    }
                }
            }
            assert!(
                distinct.len() > 4,
                "family {family}: {} near copies",
                distinct.len()
            );
        }
        assert_eq!(
            cells.len(),
            usize::from(DOC_FAMILIES),
            "one cell per family"
        );
        assert_ne!(doc_value(0, 0, 1), doc_value(0, 0, 2));
        assert_eq!(
            doc_value(0, 0, 1),
            doc_value(0, 3, 1),
            "random ignores the family"
        );
    }

    #[test]
    fn scores_name_example_files() {
        for include_length in [true, false] {
            for (a, b, _) in example_scores(include_length) {
                example_digest_of(&a);
                example_digest_of(&b);
            }
        }
    }
}
