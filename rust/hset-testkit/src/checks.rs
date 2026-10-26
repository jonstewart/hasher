//! Shared checks used by `hset`'s tests and (in later tasks) its fuzz
//! targets.
//!
//! [`exercise_loaded`] is the robustness exerciser: once a `Hashset` loads,
//! hammer every query and record-access path the kit knows about. Panics
//! are the failure signal — nothing there distinguishes a correctness bug
//! from a crash beyond that.
//!
//! [`check_corruption`] is the robustness property: a corrupted [`Doc`]
//! file never panics [`exercise_loaded`], and never passes the digest
//! unless the corruption changed nothing.
//!
//! [`check_doc_roundtrip`] is the format property: a [`Doc`] builds,
//! decodes to its oracle, verifies, answers lookups per the oracle, builds
//! deterministically and rebuilds from its own decoded records.
//!
//! [`check_lookup`] is the lookup property: every strategy (hint kind,
//! search config, hash length) answers like the linear-scan [`NaiveSet`].
//!
//! [`check_set_op`] is the set-algebra property: `merge::merge` writes the
//! file [`set_op_expected`] models from the C++ merge semantics, or fails
//! with the refusal it names; [`set_op_content`] reads an output back for
//! the algebraic laws.
//!
//! [`check_hex`] and [`check_hex_rows`] are the hex-codec properties: every
//! [`simd_levels`] level agrees with [`hex_oracle`] and rejects a bad
//! digit, and the row APIs agree with it over whole rows.
//!
//! [`check_text_input`] is the text-parsing property: `Builder::add_text`
//! never panics and accepts exactly what [`text_oracle_accepts`] does.
//!
//! [`check_tlsh_knn`] is the TLSH search property, run by all of the
//! above on every TLSH section they load: brute force answers like
//! [`naive_knn`], an index that passes `check_index` like brute force, and
//! any other index without a panic.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use hset::format::decode;
use hset::hashset::{KnnStrategy, VerifyReport};
use hset::lookup::{HintSpec, Lookup, build_hint, hint_from_parts, make_lookup_with};
use hset::merge::merge;
use hset::synth::SplitMix64;
use hset::tlsh::{TlshDigest, check_index};
use hset::{Builder, Error, HashType, Hashset, SetOp};

use hset::builder::parse_value;
use hset::hex;

use crate::corrupt::Corruption;
use crate::doc::{Doc, Expected, Opts, set_op_expected};
use crate::oracle::{NaiveSet, hex_oracle};
use crate::strategies::{LookupCase, UNSUPPORTED_LENGTH, queries};
use crate::tlsh::{Perturbation, naive_knn, perturb, random_digest};

/// Build `doc`, decode and check it against `doc.expected()`, load and
/// verify it, check `records_for`/`equal_range` per section against the
/// oracle, rebuild it for determinism and, when it has records, rebuild it
/// from its decoded records. Any failure panics with the doc's `Debug`.
pub fn check_doc_roundtrip(doc: &Doc) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| roundtrip(doc))) {
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied());
        match msg {
            Some(m) => panic!("{m}\ndoc: {doc:?}"),
            None => resume_unwind(payload),
        }
    }
}

fn roundtrip(doc: &Doc) {
    // 1. Build, decode, compare with the oracle.
    let bytes = doc.build().expect("build");
    let file = decode(&bytes).expect("decode");
    let expected = doc.expected();
    expected.assert_matches(&file);

    // 2. Load, digest, verify.
    let hs = Hashset::load(&bytes).expect("load");
    assert!(hs.verify_digest(), "verify_digest");
    let report = hs.verify();
    assert!(report.is_ok(), "verify: {:?}", report.problems);
    check_tlsh_sections(&hs, &report, &expected);

    // 3. Review Focus 5: records_for and equal_range per distinct stored
    //    hash, against the oracle's hashes and ridx.
    let rows = expected.records.as_deref().unwrap_or(&[]);
    for (idx, e) in expected.sections.iter().enumerate() {
        let mut distinct = e.hashes.clone();
        distinct.dedup();
        for h in &distinct {
            let multiplicity = e.hashes.iter().filter(|x| *x == h).count();
            let range = hs.equal_range(idx, h);
            assert_eq!(
                range.len(),
                multiplicity,
                "section {idx} equal_range({h:02x?}) = {range:?}"
            );
            let mut want: Vec<&[u8]> = match &e.ridx {
                Some(ridx) => e
                    .hashes
                    .iter()
                    .zip(ridx)
                    .filter(|(x, _)| *x == h)
                    .map(|(_, &r)| rows[r as usize].as_slice())
                    .collect(),
                None => Vec::new(),
            };
            want.sort_unstable();
            let mut got = hs.records_for(idx, h);
            got.sort_unstable();
            assert_eq!(got, want, "section {idx} records_for({h:02x?})");
        }
    }

    // 4. Determinism.
    assert!(
        doc.build().expect("second build") == bytes,
        "rebuild differs"
    );

    // 5. Rebuild from the decoded records.
    if doc.opts.with_records {
        let rhdr = file.rhdr.as_ref().expect("rhdr");
        let mut b = Builder::with_fields(rhdr.fields.clone());
        for i in 0..file.record_count() {
            let rec = file.record(i).expect("record");
            b.add_raw_record(rec).expect("add_raw_record");
        }
        let rebuilt = b
            .build(&doc.opts.build_options())
            .expect("build from decoded records");
        assert!(rebuilt == bytes, "build from decoded records differs");
    }
}

/// Cap on probes per section/record sweep: enough to cover interesting
/// structure (first, middle, last, duplicates) without making corruption
/// and truncation sweeps slow.
const MAX_PROBES: usize = 64;

/// Seed for the deterministic boundary queries. Any fixed value works:
/// only the first six outputs of `strategies::queries` (or two, for an
/// empty section) are used, and those don't depend on the seed.
const BOUNDARY_SEED: u64 = 0;

/// Load `bytes`; if that succeeds, run every query, record access and
/// `verify()` the kit knows (panics are the failure signal). Returns
/// whether it loaded.
pub fn exercise_loaded(bytes: &[u8]) -> bool {
    let Ok(hs) = Hashset::load(bytes) else {
        return false;
    };
    let _ = hs.verify();
    for i in 0..hs.section_count() {
        exercise_section(&hs, i);
        if hs.tlsh_rows(i).is_ok() {
            check_tlsh_knn(&hs, i);
        }
    }
    exercise_records(&hs);
    true
}

/// Longest hash [`exercise_section`] builds queries for. A query must be
/// a whole hash, and the format bounds `hash_length` only through the
/// section's data (`hash_count * hash_length` bytes), so an empty section
/// can claim any length (a corrupt one claimed 601295421460). Every
/// non-empty section of a fuzz input is far below this bound.
const MAX_QUERY_HASH_LENGTH: usize = 1 << 20;

/// Probe section `idx`: the original smoke-test queries, the boundary
/// hashes around its stored data, and a sample of its own stored hashes.
/// Skipped when the hash length exceeds [`MAX_QUERY_HASH_LENGTH`].
fn exercise_section(hs: &Hashset<'_>, idx: usize) {
    let s = hs.section(idx);
    let hl = s.hash_length();
    if hl > MAX_QUERY_HASH_LENGTH {
        return;
    }

    // The probes `robustness.rs::exercise` ran before this module existed.
    let probe = vec![0x5au8; hl];
    let _ = hs.contains(idx, &probe);
    let _ = hs.find(idx, &probe);
    let _ = hs.records_for(idx, &probe);
    if !s.is_empty() {
        let h = s.hash(s.len() / 2).to_vec();
        let _ = hs.records_for(idx, &h);
    }
    let mut out = vec![false; 5];
    hs.contains_batch(idx, &vec![0xa5u8; hl * 5], &mut out);

    // The six boundary hashes (all-0x00, all-0xFF, first-1/+1, last-1/+1),
    // computed over every hash this section actually stores.
    let stored: Vec<u8> = (0..s.len()).flat_map(|i| s.hash(i).to_vec()).collect();
    for q in queries(&stored, hl, BOUNDARY_SEED, 0).chunks_exact(hl) {
        exercise_hash(hs, idx, q);
    }

    // Up to MAX_PROBES of the section's own stored hashes.
    let n = s.len().min(MAX_PROBES);
    for i in 0..n {
        exercise_hash(hs, idx, s.hash(i));
    }

    // `contains_batch` over the first MAX_PROBES stored hashes.
    if n > 0 {
        let mut out = vec![false; n];
        hs.contains_batch(idx, &stored[..n * hl], &mut out);
    }
}

/// `find`, `contains`, `equal_range`, `records_for` and `window` for one
/// query hash against section `idx`.
fn exercise_hash(hs: &Hashset<'_>, idx: usize, hash: &[u8]) {
    let _ = hs.find(idx, hash);
    let _ = hs.contains(idx, hash);
    let _ = hs.equal_range(idx, hash);
    let _ = hs.records_for(idx, hash);
    let _ = hs.lookup(idx).window(hash);
}

/// The original 10-record `record_fields` sweep, plus `record_fields` and
/// `field_value` (every `HashType::ALL`) over up to MAX_PROBES records.
fn exercise_records(hs: &Hashset<'_>) {
    for r in hs.records().take(10) {
        let _ = hs.record_fields(r);
    }
    for r in hs.records().take(MAX_PROBES) {
        let _ = hs.record_fields(r);
        for t in HashType::ALL {
            let _ = hs.field_value(r, t);
        }
    }
}

/// Build `doc`, corrupt it with `c` and [`exercise_loaded`] the result. If
/// the corrupted file still loads and its SHA-256 digest verifies, it must
/// equal the original: the digest catches any real change.
pub fn check_corruption(doc: &Doc, c: &Corruption) {
    let bytes = doc.build().expect("build");
    let m = c.apply(&bytes);
    exercise_loaded(&m);
    if let Ok(hs) = Hashset::load(&m)
        && hs.verify_digest()
    {
        assert!(
            m == bytes,
            "corrupted file ({} of {} bytes) passed verify_digest",
            m.len(),
            bytes.len()
        );
    }
}

/// `contains_batch` sizes tried by [`check_lookup`] (each one that fits in
/// the case's query count, plus the full count): around the 8-lane SIMD
/// width and the 256-query sub-batch cap.
const BATCH_SIZES: [usize; 8] = [0, 1, 7, 8, 9, 255, 256, 257];

/// Bytes appended to a query to check that a longer query is answered by
/// its `hlen`-byte prefix (Review Focus 3).
const EXTRA_BYTES: [u8; 5] = [0xA5; 5];

/// How many queries get the long-query check.
const LONG_QUERIES: usize = 8;

/// Build the case's hint and lookup, then check `find`, `contains`,
/// `equal_range`, `window` and `contains_batch` against [`NaiveSet`] for
/// every query and every stored hash. For the unsupported hash length a
/// requested hint must be an error.
pub fn check_lookup(case: &LookupCase) {
    let hlen = case.hlen;
    let data = &case.data;

    // 1. The hint; unsupported for UNSUPPORTED_LENGTH.
    let built = build_hint(hlen, data, case.hint);
    if hlen == UNSUPPORTED_LENGTH && case.hint != HintSpec::None {
        assert!(
            built.is_err(),
            "build_hint({hlen}, {:?}) should fail: {built:?}",
            case.hint
        );
        return;
    }
    let hint = built.expect("build_hint");

    // 2. The lookup and the oracle.
    let parts = hint.as_ref().map(|(t, b)| hint_from_parts(*t, b));
    let lk = make_lookup_with(hlen, data, parts.as_ref(), case.cfg).expect("make_lookup_with");
    let naive = NaiveSet::from_bytes(data, hlen);

    // 3. Every query.
    let queries: Vec<&[u8]> = case.queries.chunks_exact(hlen).collect();
    for q in &queries {
        check_query(lk.as_ref(), &naive, q);
    }

    // 4. Every stored hash lies inside its own window.
    for (i, h) in data.chunks_exact(hlen).enumerate() {
        let w = lk.window(h);
        assert!(
            w.contains(&i),
            "stored hash {i} {h:02x?} outside window {w:?}"
        );
        assert_eq!(lk.find(h), naive.find(h), "find(stored {i} {h:02x?})");
    }

    // 5. Batches of each size that fits, and the whole query list.
    let m = queries.len();
    let want: Vec<bool> = queries.iter().map(|q| naive.contains(q)).collect();
    for size in BATCH_SIZES.into_iter().chain([m]).filter(|&s| s <= m) {
        let mut out = vec![false; size];
        lk.contains_batch(&case.queries[..size * hlen], &mut out);
        assert_eq!(out, want[..size], "contains_batch of {size}");
    }

    // 6. Review Focus 3: a longer query is answered by its prefix.
    for q in queries.iter().take(LONG_QUERIES) {
        let long = [*q, &EXTRA_BYTES[..]].concat();
        assert_eq!(
            lk.contains(&long),
            lk.contains(q),
            "contains(long {long:02x?})"
        );
        assert_eq!(lk.find(&long), lk.find(q), "find(long {long:02x?})");
        assert_eq!(
            lk.equal_range(&long),
            lk.equal_range(q),
            "equal_range(long {long:02x?})"
        );
    }
}

/// `find`, `contains`, `equal_range` and (when found) `window` for one
/// exact-length query.
fn check_query(lk: &dyn Lookup, naive: &NaiveSet, q: &[u8]) {
    let found = lk.find(q);
    assert_eq!(found, naive.find(q), "find({q:02x?})");
    assert_eq!(lk.contains(q), naive.contains(q), "contains({q:02x?})");
    assert_eq!(
        lk.equal_range(q),
        naive.equal_range(q),
        "equal_range({q:02x?})"
    );
    if let Some(i) = found {
        let w = lk.window(q);
        assert!(
            w.contains(&i),
            "found {i} for {q:02x?} outside window {w:?}"
        );
    }
}

/// kNN parameters [`check_tlsh_knn`] tries per query, `(k, max_distance,
/// include_length)`; a `k` of `usize::MAX` stands for every row.
const KNN_PARAMS: [(usize, u32, bool); 5] = [
    (1, 144, true),
    (4, 400, false),
    (usize::MAX, u32::MAX, true),
    (usize::MAX, 0, true),
    (0, u32::MAX, true),
];

/// Stored rows [`check_tlsh_knn`] queries with (each also near-copied).
const TLSH_QUERY_ROWS: usize = 3;

/// The kNN property of TLSH section `idx` of `hs`: for a few queries (the
/// first, middle and last rows, a near copy of each, a random digest and
/// the null digest) and [`KNN_PARAMS`], brute force equals [`naive_knn`].
/// When the section's index passes [`check_index`], the index search and
/// `tlsh_knn` equal brute force. When it does not (a corrupt file), they
/// return without panicking: an `Error::Format` where the search read the
/// index out of bounds, or matches that may be inexact where it read it
/// within bounds (as C++ does). Returns whether the index passed
/// `check_index` (`None` when there is none).
///
/// # Panics
///
/// When `idx` is not a TLSH section, or on any disagreement.
pub fn check_tlsh_knn(hs: &Hashset<'_>, idx: usize) -> Option<bool> {
    let rows = hs.tlsh_rows(idx).expect("a TLSH section");
    let n = rows.len();
    let index = hs.tlsh_index(idx).expect("a TLSH section");
    let has_index = hs.tlsh_knn_strategies(idx).expect("strategies").index;
    assert_eq!(has_index, index.is_some(), "strategies: index");
    let sound = index.map(|ivf| check_index(&ivf, rows).is_ok());

    let mut rng = SplitMix64::new(idx as u64);
    let mut qs: Vec<TlshDigest> = Vec::new();
    let picks = [0, n / 2, n.saturating_sub(1)];
    for &i in picks.iter().take(TLSH_QUERY_ROWS.min(n)) {
        let r = TlshDigest(rows[i]);
        qs.push(r);
        qs.push(perturb(&mut rng, &r, &Perturbation::default()));
    }
    qs.push(random_digest(&mut rng));
    qs.push(TlshDigest::NULL);

    for q in &qs {
        for (k, max_distance, include_length) in KNN_PARAMS {
            let k = k.min(n + 1);
            let want = naive_knn(rows, q, k, max_distance, include_length);
            let with = |s| hs.tlsh_knn_with(idx, q, k, max_distance, include_length, s, None);
            let ctx = || {
                format!(
                    "section {idx}, query {q:?}, k {k}, max {max_distance}, length {include_length}"
                )
            };
            let brute = with(KnnStrategy::Brute).expect("brute force");
            assert_eq!(brute, want, "brute force kNN, {}", ctx());
            let auto = hs.tlsh_knn(idx, q, k, max_distance, include_length);
            match sound {
                Some(true) => {
                    let got = with(KnnStrategy::Index).expect("index kNN");
                    assert_eq!(got, want, "index kNN, {}", ctx());
                    assert_eq!(auto.expect("tlsh_knn"), want, "tlsh_knn, {}", ctx());
                }
                None => {
                    assert!(
                        matches!(with(KnnStrategy::Index), Err(Error::Input(_))),
                        "{}",
                        ctx()
                    );
                    assert_eq!(auto.expect("tlsh_knn"), want, "tlsh_knn, {}", ctx());
                }
                Some(false) => {
                    // any answer, but a format error is the only error
                    for got in [with(KnnStrategy::Index), auto] {
                        if let Err(e) = got {
                            assert!(matches!(e, Error::Format(_)), "{e}, {}", ctx());
                        }
                    }
                }
            }
        }
    }
    sound
}

/// The TLSH checks of a file built or merged from a model: per expected
/// TLSH section, [`verify`](Hashset::verify) found the cell hint exact and
/// the index (present iff expected) valid, and [`check_tlsh_knn`] holds.
fn check_tlsh_sections(hs: &Hashset<'_>, report: &VerifyReport, expected: &Expected) {
    for (idx, e) in expected.sections.iter().enumerate() {
        if e.htype != HashType::Tlsh {
            continue;
        }
        let t = report.sections[idx].tlsh.as_ref().expect("a TLSH report");
        assert_eq!(t.cells_exact, Some(true), "section {idx}: cell hint");
        assert_eq!(
            t.index.map(|i| i.valid),
            e.tivf.then_some(true),
            "section {idx}: TIVF"
        );
        assert_eq!(
            check_tlsh_knn(hs, idx),
            e.tivf.then_some(true),
            "section {idx}: kNN"
        );
    }
}

/// A record as its present fields, `(type, value)` in ascending type
/// order: the same record whatever the field order or the absent fields of
/// the file that holds it.
pub type OpRecord = Vec<(HashType, Vec<u8>)>;

/// What a set operation's output holds, independently of its field order
/// and section names: its records (when it has a record table) and the
/// distinct `(type, value)` rows of its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpContent {
    pub records: Option<BTreeSet<OpRecord>>,
    pub values: BTreeSet<(HashType, Vec<u8>)>,
}

/// Build both docs, load them and [`merge`] them with `out`'s merge options
/// ([`Opts::merge_options`]); the output's bytes or `merge`'s error.
fn merged(op: SetOp, a: &Doc, b: &Doc, out: &Opts) -> hset::Result<Vec<u8>> {
    let (ab, bb) = (a.build().expect("build a"), b.build().expect("build b"));
    let ha = Hashset::load(&ab).expect("load a");
    let hb = Hashset::load(&bb).expect("load b");
    merge(op, &ha, &hb, &out.merge_options())
}

/// Merge `a` and `b` writing everything ([`Opts::default_for_tests`]) and
/// read the output back as [`OpContent`]; `None` when `merge` refuses.
pub fn set_op_content(op: SetOp, a: &Doc, b: &Doc) -> Option<OpContent> {
    let out = merged(op, a, b, &Opts::default_for_tests()).ok()?;
    let hs = Hashset::load(&out).expect("load result");
    let records = hs.record_header().map(|_| {
        hs.records()
            .map(|r| {
                let mut rec: OpRecord = hs
                    .record_fields(r)
                    .into_iter()
                    .filter_map(|(f, v)| Some((f.htype, v?.to_vec())))
                    .collect();
                rec.sort();
                rec
            })
            .collect()
    });
    let values = hs
        .sections()
        .iter()
        .flat_map(|s| (0..s.len()).map(|i| (s.header.htype, s.hash(i).to_vec())))
        .collect();
    Some(OpContent { records, values })
}

/// The set-algebra property of [`merge`]: for every write-flag choice
/// (both, records only, hash sections only, over `a`'s other options), the
/// output decodes to [`set_op_expected`]'s file and loads and verifies, or
/// `merge` fails with an `Error::Input` naming the model's refusal.
pub fn check_set_op(op: SetOp, a: &Doc, b: &Doc) {
    for (with_records, with_hashsets) in [(true, true), (true, false), (false, true)] {
        let out = Opts {
            with_records,
            with_hashsets,
            ..a.opts.clone()
        };
        let ctx = || format!("{op:?} writing {out:?}\na: {a:?}\nb: {b:?}");
        match (merged(op, a, b, &out), set_op_expected(op, a, b, &out)) {
            (Ok(bytes), Ok(want)) => {
                let file = decode(&bytes).unwrap_or_else(|e| panic!("decode: {e}\n{}", ctx()));
                if let Err(p) = catch_unwind(AssertUnwindSafe(|| want.assert_matches(&file))) {
                    let msg = p.downcast_ref::<String>().cloned().unwrap_or_default();
                    panic!("{msg}\n{}", ctx());
                }
                let hs = Hashset::load(&bytes).unwrap_or_else(|e| panic!("load: {e}\n{}", ctx()));
                let report = hs.verify();
                assert!(report.is_ok(), "verify: {:?}\n{}", report.problems, ctx());
                if let Err(p) = catch_unwind(AssertUnwindSafe(|| {
                    check_tlsh_sections(&hs, &report, &want)
                })) {
                    let msg = p.downcast_ref::<String>().cloned().unwrap_or_default();
                    panic!("{msg}\n{}", ctx());
                }
            }
            (Err(e), Err(refusal)) => {
                assert!(matches!(e, Error::Input(_)), "error kind {e:?}\n{}", ctx());
                assert!(
                    e.to_string().contains(refusal),
                    "error {e}, expected {refusal}\n{}",
                    ctx()
                );
            }
            (Ok(_), Err(refusal)) => panic!("merged, expected {refusal}\n{}", ctx()),
            (Err(e), Ok(_)) => panic!("failed unexpectedly: {e}\n{}", ctx()),
        }
    }
}

/// Every SIMD level hex checks should run at: the portable baseline the
/// binary is compiled for (SSE2 on x86_64) and whatever runtime detection
/// picks for this CPU (identical to the baseline when nothing better is
/// available).
pub fn simd_levels() -> Vec<fearless_simd::Level> {
    vec![
        fearless_simd::Level::baseline(),
        fearless_simd::Level::new(),
    ]
}

/// Bytes substituted for one hex digit to check rejection: past the digit
/// range ('g'), the ASCII neighbours of the digit class ('/' just below
/// '0', ':' just above '9') and a non-ASCII lead byte (0xC3, the first
/// byte of a two-byte UTF-8 sequence).
const BAD_HEX_DIGITS: [u8; 4] = [b'g', b'/', b':', 0xC3];

/// For every [`simd_levels`] level: `encode_into_at` matches
/// [`hex_oracle::encode`], `decode_into_at` inverts it for both the
/// lowercase and uppercase encoding, and each of [`BAD_HEX_DIGITS`]
/// substituted for one digit — at up to [`MAX_PROBES`] positions — is
/// rejected by `decode_into_at` and by `hex::decode`. Also: `hex::decode`
/// of the encoding with its last character dropped is an error (odd
/// length), when the encoding is non-empty.
pub fn check_hex(bytes: &[u8]) {
    let encoded = hex_oracle::encode(bytes);

    for level in simd_levels() {
        let mut enc = vec![0u8; bytes.len() * 2];
        hex::simd::encode_into_at(level, bytes, &mut enc);
        assert_eq!(enc, encoded.as_bytes(), "encode_into_at at {level:?}");

        let mut back = vec![0xAAu8; bytes.len()];
        assert!(
            hex::simd::decode_into_at(level, &enc, &mut back),
            "decode_into_at should accept its own encoding at {level:?}"
        );
        assert_eq!(back, bytes, "decode_into_at roundtrip at {level:?}");

        let upper = enc.to_ascii_uppercase();
        let mut back_upper = vec![0xAAu8; bytes.len()];
        assert!(
            hex::simd::decode_into_at(level, &upper, &mut back_upper),
            "decode_into_at should accept uppercase at {level:?}"
        );
        assert_eq!(back_upper, bytes, "uppercase roundtrip at {level:?}");

        let n = enc.len().min(MAX_PROBES);
        for pos in 0..n {
            for &bad in &BAD_HEX_DIGITS {
                let mut mutated = enc.clone();
                mutated[pos] = bad;
                let mut scratch = vec![0u8; bytes.len()];
                assert!(
                    !hex::simd::decode_into_at(level, &mutated, &mut scratch),
                    "decode_into_at should reject {bad:#04x} at position {pos} ({level:?})"
                );
            }
        }
    }

    // `hex::decode` (the `&str` API) rejects the same bad digits. b'g',
    // b'/' and b':' are ASCII, so substituting one into the (all-ASCII)
    // encoding keeps it valid UTF-8 at the same length, which exercises
    // the bad-digit path directly. 0xC3 is the lead byte of a two-byte
    // UTF-8 sequence and cannot stand alone in a `&str`, so it is paired
    // with a valid continuation byte (0xA9, i.e. "é") to keep the string
    // valid UTF-8; that widens the string by one byte, so this case is
    // still rejected, but by the odd-length check rather than the
    // bad-digit one. `decode_into_at` above already covers 0xC3 as a raw,
    // length-preserving invalid digit.
    let n = encoded.len().min(MAX_PROBES);
    for pos in 0..n {
        for &bad in &BAD_HEX_DIGITS {
            let mutated = if bad == 0xC3 {
                let mut s = encoded.clone();
                s.replace_range(pos..pos + 1, "\u{e9}");
                s
            } else {
                let mut b = encoded.clone().into_bytes();
                b[pos] = bad;
                String::from_utf8(b).expect("ASCII substitution stays valid UTF-8")
            };
            assert!(
                hex::decode(&mutated).is_err(),
                "hex::decode should reject {bad:#04x} at position {pos}"
            );
        }
    }

    if !encoded.is_empty() {
        assert!(
            hex::decode(&encoded[..encoded.len() - 1]).is_err(),
            "hex::decode should reject odd length"
        );
    }
}

/// `encode_rows`, `encode_rows_to_writer` and `decode_rows` against
/// [`hex_oracle`] over whole rows, plus their rejection of a malformed
/// row. `data.len()` must be a multiple of `width` (the proptest driving
/// this truncates `data` to a whole number of rows).
pub fn check_hex_rows(data: &[u8], width: usize, sep: &[u8]) {
    assert_eq!(
        data.len() % width,
        0,
        "data length {} is not a multiple of the row width {width}",
        data.len()
    );
    let rows: Vec<&[u8]> = data.chunks_exact(width).collect();

    // The oracle: each row's hex, lowercase, followed by `sep`.
    let mut want = Vec::new();
    for row in &rows {
        want.extend_from_slice(hex_oracle::encode(row).as_bytes());
        want.extend_from_slice(sep);
    }

    let prefix = b"prefix";
    let mut via_rows = prefix.to_vec();
    hex::encode_rows(data, width, sep, &mut via_rows);
    assert_eq!(&via_rows[prefix.len()..], &want[..], "encode_rows");

    let mut via_writer = prefix.to_vec();
    hex::encode_rows_to_writer(data, width, sep, &mut via_writer).expect("encode_rows_to_writer");
    assert_eq!(
        &via_writer[prefix.len()..],
        &want[..],
        "encode_rows_to_writer"
    );

    // `decode_rows` of the oracle's own strings returns the data and the
    // row count, appending (not overwriting) `out`.
    let strs: Vec<String> = rows.iter().map(|r| hex_oracle::encode(r)).collect();
    let sentinel = [0xAAu8; 3];
    let mut out = sentinel.to_vec();
    let n = hex::decode_rows(strs.iter().map(String::as_str), width, &mut out)
        .expect("decode_rows of the oracle's own strings");
    assert_eq!(n, rows.len(), "decode_rows row count");
    assert_eq!(&out[..sentinel.len()], &sentinel[..], "decode_rows prefix");
    assert_eq!(&out[sentinel.len()..], data, "decode_rows data");

    if rows.is_empty() {
        // No row to corrupt.
        return;
    }

    // A row of the wrong length is rejected, and `out` is left unchanged.
    let mut wrong_len = strs.clone();
    wrong_len[0].push('0');
    let mut out = sentinel.to_vec();
    assert!(
        hex::decode_rows(wrong_len.iter().map(String::as_str), width, &mut out).is_err(),
        "decode_rows should reject a row of the wrong length"
    );
    assert_eq!(out, sentinel, "out after a wrong-length row");

    // A row with a bad digit is rejected, and `out` is left unchanged.
    let mut bad_digit = strs.clone();
    bad_digit[0].replace_range(0..1, "g");
    let mut out = sentinel.to_vec();
    assert!(
        hex::decode_rows(bad_digit.iter().map(String::as_str), width, &mut out).is_err(),
        "decode_rows should reject a row with a bad digit"
    );
    assert_eq!(out, sentinel, "out after a bad-digit row");
}

/// The field sets [`check_text_input`] parses against: one digest, a
/// digest with a size, the float column alone, three columns mixed, and
/// TLSH with a digest.
const TEXT_FIELD_SETS: [&[HashType]; 5] = [
    &[HashType::Md5],
    &[HashType::Sha1, HashType::Size],
    &[HashType::Entropy],
    &[HashType::Md5, HashType::Sha1, HashType::Size],
    &[HashType::Tlsh, HashType::Md5],
];

/// Whether `Builder::add_text` should accept `text` for `fields`, decided
/// line by line from `text.lines()`: strip one trailing `'\r'`; an empty
/// line is accepted; otherwise the line needs exactly `fields.len()`
/// columns split on `' '`, and each non-empty column must parse — a
/// digest as exactly `2 * length` ASCII hex digits, `Size` as a `u64`,
/// `Entropy` as an `f64`, TLSH as `"TNULL"` or 70 ASCII hex digits after
/// an optional `"T1"`. An empty column is an absent value.
fn text_oracle_accepts(fields: &[HashType], text: &str) -> bool {
    text.lines().all(|line| {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            return true;
        }
        let cols: Vec<&str> = line.split(' ').collect();
        cols.len() == fields.len()
            && fields.iter().zip(&cols).all(|(t, col)| {
                col.is_empty()
                    || match t {
                        HashType::Size => col.parse::<u64>().is_ok(),
                        HashType::Entropy => col.parse::<f64>().is_ok(),
                        HashType::Tlsh => {
                            let digits = col.strip_prefix("T1").unwrap_or(col);
                            *col == "TNULL"
                                || (digits.len() == 70
                                    && digits.bytes().all(|b| b.is_ascii_hexdigit()))
                        }
                        t => {
                            let len = t.length().expect("storable type has a length");
                            col.len() == 2 * len && col.bytes().all(|b| b.is_ascii_hexdigit())
                        }
                    }
            })
    })
}

/// For every [`TEXT_FIELD_SETS`] entry: `Builder::add_text(text)` does not
/// panic and is `Ok` exactly when [`text_oracle_accepts`]; and
/// `parse_value` on every space-separated column of every line, for every
/// field, does not panic.
pub fn check_text_input(text: &str) {
    for types in TEXT_FIELD_SETS {
        let mut b = Builder::new(types).expect("storable, distinct types");
        let got = b.add_text(text);
        let want = text_oracle_accepts(types, text);
        assert_eq!(
            got.is_ok(),
            want,
            "add_text for {types:?} on {text:?}: got {got:?}, oracle says {want}"
        );
        for f in b.fields() {
            for line in text.lines() {
                for col in line.split(' ') {
                    let _ = parse_value(f, col);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::Field;
    use crate::tlsh::doc_value;
    use hset::TlshIndexPolicy;

    /// Fields tlsh and sizes, `n` records: TLSH values of every
    /// [`doc_value`] kind (every fifth absent), sizes `i % 5`.
    fn tlsh_doc(n: u64, seed: u64) -> Doc {
        Doc {
            fields: vec![
                Field::canonical(HashType::Tlsh),
                Field::canonical(HashType::Size),
            ],
            records: (0..n)
                .map(|i| {
                    let v = i * 7 + seed;
                    vec![
                        (i % 5 != 4).then(|| doc_value((v % 6) as u8, (v % 4) as u8, v).0.to_vec()),
                        Some((i % 5).to_le_bytes().to_vec()),
                    ]
                })
                .collect(),
            opts: Opts::default_for_tests(),
        }
    }

    #[test]
    fn tlsh_knn_check_holds_with_and_without_an_index() {
        for (tlsh_index, want) in [(true, Some(true)), (false, None)] {
            let mut doc = tlsh_doc(40, 0);
            doc.opts.tlsh_index = tlsh_index;
            doc.opts.tlsh_list_size = 3;
            let bytes = doc.build().unwrap();
            let hs = Hashset::load(&bytes).unwrap();
            assert_eq!(check_tlsh_knn(&hs, 0), want);
            assert!(exercise_loaded(&bytes));
        }
    }

    #[test]
    fn tlsh_knn_check_reports_an_invalid_index() {
        let bytes = tlsh_doc(40, 0).build().unwrap();
        let file = decode(&bytes).unwrap();
        let tivf = file.sections[0].tivf.unwrap();
        // the last row id, out of range
        let at = tivf.as_ptr() as usize - bytes.as_ptr() as usize + tivf.len() - 4;
        let mut bad = bytes.clone();
        bad[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let hs = Hashset::load(&bad).unwrap();
        assert_eq!(check_tlsh_knn(&hs, 0), Some(false));
        assert!(exercise_loaded(&bad));
    }

    #[test]
    fn tlsh_knn_check_accepts_any_answer_from_an_index_corrupt_within_bounds() {
        let bytes = tlsh_doc(40, 0).build().unwrap();
        let file = decode(&bytes).unwrap();
        let tivf = file.sections[0].tivf.unwrap();
        let lists = u32::from_le_bytes(tivf[8..12].try_into().unwrap()) as usize;
        // every radius2 0: the index prunes lists that hold matches
        let at = tivf.as_ptr() as usize - bytes.as_ptr() as usize + 32 + 4 * 65537 + 36 * lists;
        let mut bad = bytes.clone();
        bad[at..at + 4 * lists].fill(0);
        let hs = Hashset::load(&bad).unwrap();
        assert_eq!(check_tlsh_knn(&hs, 0), Some(false));
        assert!(exercise_loaded(&bad));
    }

    #[test]
    fn tlsh_documents_round_trip_and_merge_as_modelled() {
        let mut a = tlsh_doc(48, 0);
        a.opts.tlsh_list_size = 3;
        check_doc_roundtrip(&a);
        for (op, b_index, policy, coalesce) in [
            (SetOp::Union, true, TlshIndexPolicy::Inherit, 64),
            (SetOp::Union, false, TlshIndexPolicy::Inherit, 64),
            (SetOp::Intersect, false, TlshIndexPolicy::Write, 6),
            (SetOp::Subtract, true, TlshIndexPolicy::Omit, 0),
            (SetOp::Subtract, true, TlshIndexPolicy::Inherit, 6),
        ] {
            let mut b = tlsh_doc(30, 3);
            b.opts.tlsh_index = b_index;
            a.opts.tlsh_merge = policy;
            a.opts.tlsh_coalesce = coalesce;
            check_set_op(op, &a, &b);
            b.opts.tlsh_merge = policy;
            check_set_op(op, &b, &a);
        }
    }

    #[test]
    fn text_input_accepts_well_formed_lines() {
        let md5 = "0123456789abcdef0123456789ABCDEF";
        let sha1 = "00112233445566778899aabbccddeeff00112233";
        assert!(text_oracle_accepts(
            &[HashType::Md5],
            &format!("{md5}\r\n\n{md5}")
        ));
        assert!(text_oracle_accepts(
            &[HashType::Md5, HashType::Sha1, HashType::Size],
            &format!("{md5} {sha1} 42\n {sha1} \n  ")
        ));
        assert!(text_oracle_accepts(&[HashType::Entropy], "7.5\ninf\n"));
        check_text_input(&format!("{md5}\r\n{md5} {sha1} 42\n"));
        let tlsh = crate::tlsh::VEC_HEX;
        let lower = tlsh[2..].to_ascii_lowercase();
        let tm = [HashType::Tlsh, HashType::Md5];
        let text = format!("{tlsh} {md5}\n{lower} \nTNULL {md5}\n {md5}\n");
        assert!(text_oracle_accepts(&tm, &text));
        check_text_input(&text);
        check_text_input(&format!("T1{} {md5}\n", "0".repeat(70)));
    }

    #[test]
    fn text_input_rejects_malformed_lines() {
        assert!(!text_oracle_accepts(&[HashType::Md5], "0123"));
        assert!(!text_oracle_accepts(
            &[HashType::Sha1, HashType::Size],
            " -1"
        ));
        assert!(!text_oracle_accepts(&[HashType::Entropy], "x"));
        assert!(!text_oracle_accepts(&[HashType::Md5], "a b"));
        check_text_input("0123\n a b\t\n");
        let tlsh = crate::tlsh::VEC_HEX;
        let tm = [HashType::Tlsh, HashType::Md5];
        for bad in [
            format!("{tlsh}0 "),
            format!("T2{} ", &tlsh[2..]),
            format!("{} ", &tlsh[..71]),
            "TNULLX ".to_string(),
            "T1 ".to_string(),
            format!("{}{} ", &tlsh[2..], "00"),
        ] {
            assert!(!text_oracle_accepts(&tm, &bad), "{bad:?}");
            check_text_input(&bad);
        }
    }
}
