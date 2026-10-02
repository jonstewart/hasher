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

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use hset::format::decode;
use hset::{Builder, HashType, Hashset};

use crate::doc::Doc;
use crate::strategies::queries;

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
