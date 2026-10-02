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
//! [`check_set_op`] is the set-algebra property: `ops::apply` answers like
//! [`set_op_model`] over [`Doc::op_rows`] in the [`canonical_layout`], or
//! fails with the documented input error.
//!
//! [`check_hex`] and [`check_hex_rows`] are the hex-codec properties: every
//! [`simd_levels`] level agrees with [`hex_oracle`] and rejects a bad
//! digit, and the row APIs agree with it over whole rows.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use hset::format::{FieldDescriptor, decode};
use hset::lookup::{HintSpec, Lookup, build_hint, hint_from_parts, make_lookup_with};
use hset::ops::{SetOp, apply};
use hset::{Builder, Error, HashType, Hashset};

use hset::hex;

use crate::corrupt::Corruption;
use crate::doc::{Doc, Opts};
use crate::oracle::{NaiveSet, hex_oracle, set_op_model};
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

/// `doc`'s field descriptors sorted by `(htype, length)`: the layout
/// `ops::apply` gives its result (names are `doc`'s and play no part in
/// the rows).
pub fn canonical_layout(doc: &Doc) -> Vec<FieldDescriptor> {
    let mut layout = doc.descriptors();
    layout.sort_by_key(|d| (d.htype, d.length));
    layout
}

/// Build both docs, decode, `ops::apply`. Returns the result rows in the
/// canonical layout (fields ascending by `(htype, length)`) or `None` when
/// `apply` returned an error.
pub fn apply_rows(op: SetOp, a: &Doc, b: &Doc) -> Option<BTreeSet<Vec<u8>>> {
    apply_result(op, a, b).ok()
}

/// [`apply_rows`] keeping `apply`'s error. The result is built with
/// [`Opts::default_for_tests`] (records on, so it always has records),
/// decoded, checked to carry the canonical layout of `a`, and read back as
/// record rows. A hashes-only operand still compares like for like: `apply`
/// wraps its hashes as `[1] ++ hash` one-field records, the form
/// [`Doc::op_rows`] gives a hashes-only document.
fn apply_result(op: SetOp, a: &Doc, b: &Doc) -> hset::Result<BTreeSet<Vec<u8>>> {
    let (ab, bb) = (a.build().expect("build a"), b.build().expect("build b"));
    let fa = decode(&ab).expect("decode a");
    let fb = decode(&bb).expect("decode b");
    let builder = apply(op, &fa, &fb)?;
    let out = builder
        .build(&Opts::default_for_tests().build_options())
        .expect("build result");
    let file = decode(&out).expect("decode result");
    let shape = |fs: &[FieldDescriptor]| -> Vec<(HashType, u64)> {
        fs.iter().map(|f| (f.htype, f.length)).collect()
    };
    let layout = canonical_layout(a);
    let rhdr = file
        .rhdr
        .as_ref()
        .expect("a result built with records has records");
    assert_eq!(
        shape(&rhdr.fields),
        shape(&layout),
        "result fields are not the canonical layout"
    );
    Ok((0..file.record_count())
        .map(|i| file.record(i).expect("result record").to_vec())
        .collect())
}

/// Whether `ops::apply` can take `doc` as an operand: it has records, or
/// it is hashes-only with a single field.
fn expressible(doc: &Doc) -> bool {
    doc.opts.with_records || doc.fields.len() == 1
}

/// `apply_rows` == `set_op_model` over `op_rows` in the canonical layout, or
/// the documented error: error iff type sets differ, or an operand has
/// `!with_records && fields.len() != 1`. The error is `Error::Input`; its
/// Display contains "no records" / "set operations need records" for a
/// records-less operand (checked first), else "mismatch".
pub fn check_set_op(op: SetOp, a: &Doc, b: &Doc) {
    let types = |d: &Doc| -> BTreeSet<(HashType, u64)> {
        d.descriptors()
            .iter()
            .map(|f| (f.htype, f.length))
            .collect()
    };
    let records_less = !expressible(a) || !expressible(b);
    let mismatch = types(a) != types(b);
    match apply_result(op, a, b) {
        Ok(got) => {
            assert!(
                !records_less && !mismatch,
                "{op:?} succeeded but should fail (records-less {records_less}, \
                 mismatch {mismatch})\na: {a:?}\nb: {b:?}"
            );
            let layout = canonical_layout(a);
            let want = set_op_model(op, &a.op_rows(&layout), &b.op_rows(&layout));
            assert_eq!(
                got, want,
                "{op:?} differs from the model\na: {a:?}\nb: {b:?}"
            );
        }
        Err(e) => {
            assert!(
                records_less || mismatch,
                "{op:?} failed unexpectedly: {e}\na: {a:?}\nb: {b:?}"
            );
            assert!(matches!(e, Error::Input(_)), "{op:?} error kind: {e:?}");
            let msg = e.to_string();
            if records_less {
                assert!(
                    msg.contains("no records") || msg.contains("set operations need records"),
                    "records-less error: {msg}"
                );
            } else {
                assert!(msg.contains("mismatch"), "mismatch error: {msg}");
            }
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
