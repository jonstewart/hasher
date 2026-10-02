//! Shared checks used by `hset`'s tests and (in later tasks) its fuzz
//! targets.
//!
//! [`exercise_loaded`] is the robustness exerciser: once a `Hashset` loads,
//! hammer every query and record-access path the kit knows about. Panics
//! are the failure signal — nothing there distinguishes a correctness bug
//! from a crash beyond that.
//!
//! [`check_doc_roundtrip`] is the format property: a [`Doc`] builds,
//! decodes to its oracle, verifies, answers lookups per the oracle, builds
//! deterministically and rebuilds from its own decoded records.
//!
//! [`check_lookup`] is the lookup property: every strategy (hint kind,
//! search config, hash length) answers like the linear-scan [`NaiveSet`].

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use hset::format::decode;
use hset::lookup::{HintSpec, Lookup, build_hint, hint_from_parts, make_lookup_with};
use hset::{Builder, HashType, Hashset};

use crate::doc::Doc;
use crate::oracle::NaiveSet;
use crate::strategies::{LookupCase, UNSUPPORTED_LENGTH, queries};

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
    }
    exercise_records(&hs);
    true
}

/// Probe section `idx`: the original smoke-test queries, the boundary
/// hashes around its stored data, and a sample of its own stored hashes.
fn exercise_section(hs: &Hashset<'_>, idx: usize) {
    let s = hs.section(idx);
    let hl = s.hash_length();

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
