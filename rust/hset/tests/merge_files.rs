//! File-level merges ([`hset::merge::merge`], C++ `write_merged_hset` /
//! `sfhash_hashset_merge`, `test/test_hset_merge.cpp` and
//! `test/test_hset_merge_incremental.cpp`): the output is checked against
//! the set operation computed independently over the inputs' rows
//! (hashsets-only) or records, and every derived TLSH structure carried
//! through the merge is checked against the output rows. Every output
//! loads, verifies clean, and answers kNN by index as by brute force.
//!
//! With `HSET_FIXTURES_DIR` pointing at the C++ test directory, the merges
//! whose inputs and outputs the C++ suites leave on disk are re-run and
//! their payloads compared chunk by chunk.

use std::collections::BTreeSet;

use hset::format::{
    Document, FORMAT_VERSION, FieldDescriptor, HashsetIn, Hint, RecordHeader, RecordsIn, chunk,
    encode,
};
use hset::hashset::KnnStrategy;
use hset::merge::{MergeOptions, TlshIndexPolicy, merge};
use hset::tlsh::ivf::{
    DEFAULT_COALESCE, IvfBuildOptions, build_tlsh_ivf, check_invariant, tivf_len,
};
use hset::tlsh::{IvfIndex, TlshDigest, emb_body_dist2};
use hset::{BuildOptions, Builder, Error, HashType, Hashset, HintSpec, SetOp};
use hset_testkit::tlsh::{Perturbation, corpus, naive_cell_index, perturb_corpus};

#[test]
fn tlsh_options_select_the_index_policy_as_cpp_reads_them() {
    use TlshIndexPolicy::*;
    // INHERIT wins over INDEX (write_merged_hset tests INHERIT first);
    // bit 1, once VECTORS, is ignored
    for (bits, want) in [
        (0, Omit),
        (1, Omit),
        (2, Write),
        (3, Write),
        (4, Inherit),
        (5, Inherit),
        (6, Inherit),
        (7, Inherit),
    ] {
        assert_eq!(
            TlshIndexPolicy::from_tlsh_options(bits).unwrap(),
            want,
            "{bits}"
        );
    }
    // INDEX_KMEANS is not ported (ruling 4), whatever else is set; other
    // bits are unknown
    for bits in [8, 10, 12, 14, 16, 0x8000_0000] {
        assert!(
            matches!(
                TlshIndexPolicy::from_tlsh_options(bits),
                Err(Error::Input(_))
            ),
            "{bits}"
        );
    }
}

#[test]
fn merge_options_default_to_inheriting_the_index_and_writing_everything() {
    let o = MergeOptions::new("n", "d");
    assert_eq!(o.tlsh_index, TlshIndexPolicy::Inherit);
    assert_eq!(TlshIndexPolicy::default(), TlshIndexPolicy::Inherit);
    assert_eq!(o.coalesce_threshold, 64);
    assert_eq!(DEFAULT_COALESCE, 64);
    assert!(o.write_records && o.write_hashsets);
    assert_eq!((o.name.as_str(), o.desc.as_str()), ("n", "d"));
    assert_eq!(o.timestamp, None);
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const OPS: [SetOp; 3] = [SetOp::Union, SetOp::Intersect, SetOp::Subtract];

/// A distinct, deterministic `bytes`-byte "hash" per corpus index (C++
/// `fake_hex` of test_hset_merge.cpp, as bytes).
fn fake_hash(i: usize, bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 8);
    for b in (0..bytes).step_by(8) {
        let w = ((i as u64) + 1)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add((b as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9));
        out.extend_from_slice(&w.to_be_bytes());
    }
    out.truncate(bytes);
    out
}

/// One option set of an input file: records or not, hash sections or not,
/// the TIVF index or not.
#[derive(Clone, Copy, Debug)]
struct In {
    records: bool,
    hashsets: bool,
    index: bool,
}

const REC: In = In {
    records: true,
    hashsets: true,
    index: true,
};
const HO: In = In {
    records: false,
    hashsets: true,
    index: true,
};

impl In {
    fn index(self, index: bool) -> Self {
        In { index, ..self }
    }
}

/// An `.hset` of corpus rows `range` with the field `types` (TLSH from
/// `digests`, MD5 and SHA-1 from [`fake_hash`]), built by the Rust
/// builder (C++ `build_input`).
fn build_input(
    digests: &[TlshDigest],
    range: std::ops::Range<usize>,
    types: &[HashType],
    o: In,
) -> Vec<u8> {
    let mut b = Builder::new(types).unwrap();
    for i in range {
        let values: Vec<Vec<u8>> = types
            .iter()
            .map(|t| match t {
                HashType::Tlsh => digests[i].0.to_vec(),
                t => fake_hash(i, t.length().unwrap()),
            })
            .collect();
        let refs: Vec<Option<&[u8]>> = values.iter().map(|v| Some(v.as_slice())).collect();
        b.add_record(&refs).unwrap();
    }
    let opts = BuildOptions::new("input", "merge test input")
        .timestamp("2024-01-01T00:00:00Z")
        .records(o.records)
        .hashsets(o.hashsets)
        .tlsh_index(o.index);
    b.build(&opts).unwrap()
}

fn opts() -> MergeOptions {
    let mut o = MergeOptions::new("merged", "merge test output");
    o.timestamp = Some("2024-02-02T00:00:00Z".into());
    o
}

fn load(bytes: &[u8]) -> Hashset<'_> {
    Hashset::load(bytes).unwrap()
}

/// The merge of `l` and `r` under `o`, which must succeed.
fn merged(op: SetOp, l: &[u8], r: &[u8], o: &MergeOptions) -> Vec<u8> {
    merge(op, &load(l), &load(r), o).unwrap_or_else(|e| panic!("{} failed: {e}", op.name()))
}

// ---------------------------------------------------------------------------
// The expected output, computed independently over the inputs
// ---------------------------------------------------------------------------

type Rows = Vec<Vec<u8>>;

/// The rows of `t` in `hs`, in file order (empty without such a section).
fn rows_of(hs: &Hashset, t: HashType) -> Rows {
    hs.index_for_type(t).map_or_else(Vec::new, |i| {
        let s = hs.section(i);
        (0..s.len()).map(|k| s.hash(k).to_vec()).collect()
    })
}

fn unique(rows: &[Vec<u8>]) -> BTreeSet<Vec<u8>> {
    rows.iter().cloned().collect()
}

fn set_op(op: SetOp, a: &BTreeSet<Vec<u8>>, b: &BTreeSet<Vec<u8>>) -> Rows {
    match op {
        SetOp::Union => a.union(b).cloned().collect(),
        SetOp::Intersect => a.intersection(b).cloned().collect(),
        SetOp::Subtract => a.difference(b).cloned().collect(),
    }
}

/// The section types of a merge: left's, then right's extras.
fn section_types(l: &Hashset, r: &Hashset) -> Vec<HashType> {
    let mut types = Vec::new();
    for sections in [l.sections(), r.sections()] {
        for s in sections {
            if !types.contains(&s.header.htype) {
                types.push(s.header.htype);
            }
        }
    }
    types
}

/// The record fields of a merge: left's, then right's extras.
fn record_fields(l: &RecordHeader, r: &RecordHeader) -> Vec<FieldDescriptor> {
    let mut f = l.fields.clone();
    for rf in &r.fields {
        if !f.iter().any(|x| x.htype == rf.htype) {
            f.push(rf.clone());
        }
    }
    f
}

/// The records of `hs` rewritten to `fields` (an absent field is zeros).
fn widened(hs: &Hashset, fields: &[FieldDescriptor]) -> Rows {
    let rhdr = hs.record_header().unwrap();
    hs.records()
        .map(|rec| {
            let mut w = Vec::new();
            for f in fields {
                match rhdr.field_offset(f.htype) {
                    Some(off) => w.extend_from_slice(&rec[off..off + f.stride()]),
                    None => w.resize(w.len() + f.stride(), 0),
                }
            }
            w
        })
        .collect()
}

/// The present values of field `t` in `records`, sorted, duplicates kept.
fn rows_from_records(records: &[Vec<u8>], fields: &[FieldDescriptor], t: HashType) -> Rows {
    let mut off = 0;
    let mut f = None;
    for x in fields {
        if x.htype == t {
            f = Some(x);
            break;
        }
        off += x.stride();
    }
    let Some(f) = f else { return Vec::new() };
    let mut out: Rows = records
        .iter()
        .filter(|r| r[off] == 1)
        .map(|r| r[off + 1..off + f.stride()].to_vec())
        .collect();
    out.sort();
    out
}

#[derive(Debug, Default)]
struct Expected {
    /// The output fields and records, when both inputs have records.
    records: Option<(Vec<FieldDescriptor>, Rows)>,
    /// Per output section, its type and rows.
    rows: Vec<(HashType, Rows)>,
}

/// What merging `l` and `r` by `op` writes with both write flags set
/// (C++ `expected_output`).
fn expected_output(l: &Hashset, r: &Hashset, op: SetOp) -> Expected {
    let types = section_types(l, r);
    match (l.record_header(), r.record_header()) {
        (Some(lh), Some(rh)) => {
            let fields = record_fields(lh, rh);
            let recs = set_op(
                op,
                &unique(&widened(l, &fields)),
                &unique(&widened(r, &fields)),
            );
            let rows = if types.is_empty() {
                // records-only inputs give a records-only output
                Vec::new()
            } else {
                fields
                    .iter()
                    .map(|f| (f.htype, rows_from_records(&recs, &fields, f.htype)))
                    .collect()
            };
            Expected {
                records: Some((fields, recs)),
                rows,
            }
        }
        _ => Expected {
            records: None,
            rows: types
                .iter()
                .map(|&t| {
                    let a = unique(&rows_of(l, t));
                    let b = unique(&rows_of(r, t));
                    (t, set_op(op, &a, &b))
                })
                .collect(),
        },
    }
}

// ---------------------------------------------------------------------------
// Output checks
// ---------------------------------------------------------------------------

/// The chunk tags of `bytes` in FTOC order.
fn tags(bytes: &[u8]) -> Vec<u32> {
    hset::format::decode(bytes)
        .unwrap()
        .toc
        .iter()
        .map(|&(_, t)| t)
        .collect()
}

fn count_tag(bytes: &[u8], tag: u32) -> usize {
    tags(bytes).iter().filter(|&&t| t == tag).count()
}

/// The output loads and verifies clean, and has the name, description and
/// timestamp of [`opts`].
fn check_loads(o: &[u8]) -> Hashset<'_> {
    let hs = load(o);
    let report = hs.verify();
    assert!(report.is_ok(), "{:?}", report.problems);
    assert_eq!(hs.name(), "merged");
    assert_eq!(hs.description(), "merge test output");
    assert_eq!(hs.timestamp(), "2024-02-02T00:00:00Z");
    let toc = &hs.file().toc;
    assert!(
        toc.windows(2).all(|w| w[0].0 < w[1].0),
        "FTOC offsets ascend"
    );
    hs
}

/// `o` is the merge of `l` and `r` by `op` with both write flags set, its
/// TLSH section has a `TIVF` iff `want_idx`, and that index is coalesced
/// when both inputs had one (C++ `check_output`).
fn check_output(o: &[u8], l: &[u8], r: &[u8], op: SetOp, want_idx: bool) {
    let (hs, lh, rh) = (check_loads(o), load(l), load(r));
    let e = expected_output(&lh, &rh, op);

    assert_eq!(hs.section_count(), e.rows.len());
    for (i, (t, rows)) in e.rows.iter().enumerate() {
        let s = hs.section(i);
        assert_eq!(s.header.htype, *t);
        assert_eq!(&rows_of(&hs, *t), rows, "{t} rows of the {}", op.name());
        if e.records.is_none() {
            assert!(rows.windows(2).all(|w| w[0] < w[1]));
        }
        for (k, row) in rows.iter().enumerate() {
            assert!(hs.contains(i, row), "{t} row {k} is found");
        }
    }

    let n_sections = hs.section_count();
    match &e.records {
        Some((fields, recs)) => {
            let rhdr = hs.record_header().expect("an RHDR");
            assert_eq!(&rhdr.fields, fields);
            let got: Rows = hs.records().map(<[u8]>::to_vec).collect();
            assert_eq!(&got, recs);
            assert_eq!(count_tag(o, chunk::RIDX), n_sections);
            // every RIDX entry names a record whose field is the row
            for (i, s) in hs.sections().iter().enumerate() {
                let off = rhdr.field_offset(s.header.htype).unwrap();
                for k in 0..s.len() {
                    let rec = hs.record(s.record_index(k).unwrap() as usize).unwrap();
                    assert_eq!(rec[off], 1, "section {i} row {k}");
                    assert_eq!(&rec[off + 1..off + 1 + s.hash_length()], s.hash(k));
                }
            }
        }
        None => {
            assert!(hs.record_header().is_none());
            assert_eq!(count_tag(o, chunk::RDAT), 0);
            assert_eq!(count_tag(o, chunk::RIDX), 0);
        }
    }

    let merged_index = has_index(&lh) && has_index(&rh);
    match hs.index_for_type(HashType::Tlsh) {
        Some(t) => check_tlsh_section(&hs, t, want_idx, merged_index),
        None => assert_eq!(count_tag(o, chunk::TIVF), 0),
    }
}

/// Whether `hs` has no TLSH section or one with an index.
fn has_index(hs: &Hashset) -> bool {
    hs.index_for_type(HashType::Tlsh)
        .is_none_or(|t| hs.section(t).tivf.is_some())
}

/// The TLSH section `t` of `hs` has the cell hint of its rows, a `TIVF`
/// iff `want_idx` with exact radii (coalesced at the default threshold
/// when `merged_index`), and kNN by index equals brute force (C++
/// `check_tlsh_section`).
fn check_tlsh_section(hs: &Hashset, t: usize, want_idx: bool, merged_index: bool) {
    let s = hs.section(t);
    let rows = hs.tlsh_rows(t).unwrap();
    let Some(Hint::TlshCells { table }) = s.hint else {
        panic!("TLSH hint is {:?}", s.hint.map(|h| h.tag()));
    };
    let want: Vec<u8> = naive_cell_index(rows)
        .iter()
        .flat_map(|o| o.to_le_bytes())
        .collect();
    assert_eq!(table, &want[..], "the cell hint is the rows' cell index");
    assert_eq!(s.tivf.is_some(), want_idx, "TIVF presence");
    assert!(!tags(hs.raw()).contains(&chunk::TVEC));
    if !want_idx {
        assert!(!hs.tlsh_knn_strategies(t).unwrap().index);
        return;
    }
    let ivf = hs.tlsh_index(t).unwrap().unwrap();
    // radii are exact: a fresh build computes them, a merge recomputes
    // those of lists that lost members or were coalesced
    for l in 0..ivf.lists() {
        let m = ivf.medoid(l);
        let tight = ivf
            .list_ids(l)
            .map(|id| emb_body_dist2(&m, &TlshDigest(rows[id as usize])))
            .max()
            .unwrap();
        assert_eq!(ivf.radius2(l), tight, "list {l}");
    }
    if merged_index {
        assert!(check_invariant(&ivf, DEFAULT_COALESCE));
    }
    check_knn_exact(hs, t, 77);
}

/// kNN by index equals brute force for queries near the rows.
fn check_knn_exact(hs: &Hashset, t: usize, seed: u64) {
    let rows = hs.tlsh_rows(t).unwrap();
    let digests: Vec<TlshDigest> = rows.iter().map(|r| TlshDigest(*r)).collect();
    for q in perturb_corpus(seed, &digests, 6, &Perturbation::default()) {
        for (k, maxd) in [(1, 144), (10, 30), (10, 1000), (50, 144)] {
            for incl in [true, false] {
                let brute = hs
                    .tlsh_knn_with(t, &q, k, maxd, incl, KnnStrategy::Brute, None)
                    .unwrap();
                let index = hs
                    .tlsh_knn_with(t, &q, k, maxd, incl, KnnStrategy::Index, None)
                    .unwrap();
                assert_eq!(index, brute, "k {k} max {maxd} length {incl}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Merges
// ---------------------------------------------------------------------------

#[test]
fn a_union_of_hashsets_only_md5_files_is_the_set_union_of_their_rows() {
    let c = corpus(31, 300);
    let a = build_input(&c, 0..200, &[HashType::Md5], HO);
    let b = build_input(&c, 100..300, &[HashType::Md5], HO);
    let o = merged(SetOp::Union, &a, &b, &opts());
    check_output(&o, &a, &b, SetOp::Union, false);
    assert_eq!(load(&o).count(0), 300);
}

#[test]
fn record_merges_apply_the_operation_to_records_and_rows_follow_them() {
    let c = corpus(31, 300);
    let types = [HashType::Md5, HashType::Sha1];
    let a = build_input(&c, 0..200, &types, REC);
    let b = build_input(&c, 100..300, &types, REC);
    for (op, want) in OPS.into_iter().zip([300, 100, 100]) {
        let o = merged(op, &a, &b, &opts());
        check_output(&o, &a, &b, op, false);
        assert_eq!(load(&o).record_count(), want, "{}", op.name());
    }
}

/// The TLSH corpus of the merge tests (C++ `corpus()`, 9000 rows, scaled
/// down for debug builds). Every 50th digest repeats an earlier one, so
/// records files have duplicate TLSH rows (owned by different records).
fn tlsh_corpus() -> Vec<TlshDigest> {
    let mut c = corpus(31, 1200);
    for i in (50..c.len()).step_by(50) {
        c[i] = c[i - 7];
    }
    c
}

const MD5_TLSH: [HashType; 2] = [HashType::Md5, HashType::Tlsh];

/// The input and option matrix of C++ `run_matrix`: overlapping thirds of
/// the corpus, each with or without an index, merged under each policy
/// (given as C `tlsh_options` bits) by every operation.
fn run_matrix(input: In) {
    let c = tlsh_corpus();
    // (left index, right index, merge tlsh_options, output has an index)
    let cases = [
        (true, true, 4, true),    // both indexed: index carried through
        (false, false, 4, false), // both off
        (true, false, 4, false),  // b lacks the index: none
        (true, false, 2, true),   // ... index rebuilt from scratch
        (true, false, 3, true),   // ... the same with bit 1 set
        (false, false, 2, true),  // index computed for the output
        (true, true, 3, true),    // index merged, bit 1 ignored
        (true, true, 0, false),   // index dropped
        (true, true, 1, false),   // ... bit 1 alone writes nothing
    ];
    // [without, with] the index
    let a = [false, true].map(|i| build_input(&c, 0..600, &MD5_TLSH, input.index(i)));
    let b = [false, true].map(|i| build_input(&c, 300..900, &MD5_TLSH, input.index(i)));
    let tlsh = rows_of(&load(&a[0]), HashType::Tlsh);
    assert_eq!(
        tlsh.len() - unique(&tlsh).len(),
        if input.records { 11 } else { 0 },
        "duplicate TLSH rows of the left input"
    );
    for (aidx, bidx, bits, want_idx) in cases {
        let (a, b) = (&a[usize::from(aidx)], &b[usize::from(bidx)]);
        let mut o = opts();
        o.tlsh_index = TlshIndexPolicy::from_tlsh_options(bits).unwrap();
        for op in OPS {
            let out = merged(op, a, b, &o);
            check_output(&out, a, b, op, want_idx);
        }
    }
}

#[test]
fn hashsets_only_merges_over_the_option_matrix() {
    run_matrix(HO);
}

#[test]
fn record_merges_over_the_option_matrix() {
    run_matrix(REC);
}

/// C++ hset_merge_algebra: A ∪ B = B ∪ A as row sets, A − A is empty,
/// A ∩ A = A, (A ∪ B) − B = A − B, for records and hashsets-only files.
#[test]
fn merges_obey_the_set_algebra() {
    let c = tlsh_corpus();
    for input in [HO, REC] {
        let a = build_input(&c, 0..800, &MD5_TLSH, input);
        let b = build_input(&c, 400..1200, &MD5_TLSH, input);
        let o = opts();

        let ab = merged(SetOp::Union, &a, &b, &o);
        let ba = merged(SetOp::Union, &b, &a, &o);
        for t in MD5_TLSH {
            assert_eq!(rows_of(&load(&ab), t), rows_of(&load(&ba), t), "{t}");
        }
        assert_eq!(load(&ab).record_count(), load(&ba).record_count());
        check_output(&ba, &b, &a, SetOp::Union, true);

        let aa = merged(SetOp::Subtract, &a, &a, &o);
        assert_eq!(load(&aa).section_count(), 2);
        assert!((0..2).all(|i| load(&aa).count(i) == 0));
        assert_eq!(load(&aa).record_count(), 0);
        check_output(&aa, &a, &a, SetOp::Subtract, true);

        let ai = merged(SetOp::Intersect, &a, &a, &o);
        for t in MD5_TLSH {
            assert_eq!(rows_of(&load(&ai), t), rows_of(&load(&a), t), "{t}");
        }
        check_output(&ai, &a, &a, SetOp::Intersect, true);

        let ab_b = merged(SetOp::Subtract, &ab, &b, &o);
        let a_b = merged(SetOp::Subtract, &a, &b, &o);
        for t in MD5_TLSH {
            assert_eq!(rows_of(&load(&ab_b), t), rows_of(&load(&a_b), t), "{t}");
        }
        check_output(&ab_b, &ab, &b, SetOp::Subtract, true);
    }
}

/// C++ hset_merge_records_differing_fields: md5 + tlsh records merged with
/// sha1 + tlsh records widen to md5, tlsh, sha1 (and the reverse order to
/// sha1, tlsh, md5, re-sorting the right side).
#[test]
fn records_with_differing_fields_widen_to_the_union_of_the_fields() {
    let c = tlsh_corpus();
    let a = build_input(&c, 0..500, &MD5_TLSH, REC);
    let b = build_input(&c, 250..750, &[HashType::Sha1, HashType::Tlsh], REC);
    for op in OPS {
        let o = merged(op, &a, &b, &opts());
        let types: Vec<HashType> = load(&o)
            .record_header()
            .unwrap()
            .fields
            .iter()
            .map(|f| f.htype)
            .collect();
        assert_eq!(types, [HashType::Md5, HashType::Tlsh, HashType::Sha1]);
        check_output(&o, &a, &b, op, true);
        if op == SetOp::Union {
            // no record of one side can equal a record of the other
            assert_eq!(load(&o).record_count(), 1000);
        }
    }
    let o = merged(SetOp::Union, &b, &a, &opts());
    assert_eq!(
        load(&o).record_header().unwrap().fields[0].htype,
        HashType::Sha1
    );
    check_output(&o, &b, &a, SetOp::Union, true);
}

/// C++ hset_merge_mixed_records_and_hashsets_only: with records on one
/// side only the output is hashsets-only and rows deduplicate, the record
/// side's duplicate rows included.
#[test]
fn a_records_file_merged_with_a_hashsets_only_file_gives_hashsets_only() {
    let c = tlsh_corpus();
    let a = build_input(&c, 0..800, &MD5_TLSH, REC);
    let b = build_input(&c, 400..1200, &MD5_TLSH, HO);
    for op in OPS {
        let o = merged(op, &a, &b, &opts());
        assert!(load(&o).record_header().is_none());
        check_output(&o, &a, &b, op, true);
        let p = merged(op, &b, &a, &opts());
        check_output(&p, &b, &a, op, true);
    }
}

/// C++ hset_merge_type_only_on_one_side: a type on one side only is merged
/// against an empty run.
#[test]
fn a_type_on_one_side_only_is_merged_against_nothing() {
    let c = tlsh_corpus();
    let a = build_input(&c, 0..600, &MD5_TLSH, HO);
    let b = build_input(&c, 300..900, &[HashType::Tlsh], HO);
    for op in OPS {
        let o = merged(op, &a, &b, &opts());
        let hs = load(&o);
        assert_eq!(hs.section_count(), 2);
        let m = hs.index_for_type(HashType::Md5).unwrap();
        // union and difference copy the left md5 section, intersection
        // empties it
        let want = if op == SetOp::Intersect { 0 } else { 600 };
        assert_eq!(hs.count(m), want, "{}", op.name());
        check_output(&o, &a, &b, op, true);
    }
}

// ---------------------------------------------------------------------------
// Records-only inputs and errors
// ---------------------------------------------------------------------------

/// The input error of merging `l` and `r` under `o`.
fn merge_err(l: &[u8], r: &[u8], o: &MergeOptions) -> String {
    match merge(SetOp::Union, &load(l), &load(r), o) {
        Err(e @ Error::Input(_)) => e.to_string(),
        other => panic!("expected an input error, got {:?}", other.map(|b| b.len())),
    }
}

fn assert_contains(msg: &str, want: &str) {
    assert!(msg.contains(want), "{msg:?} does not contain {want:?}");
}

/// `bytes` re-encoded with only the sections `keep` accepts, without
/// their record indexes when `drop_ridx`.
fn reencode(bytes: &[u8], keep: impl Fn(HashType) -> bool, drop_ridx: bool) -> Vec<u8> {
    let f = hset::format::decode(bytes).unwrap();
    let rhdr = f.rhdr.as_ref();
    encode(&Document {
        version: FORMAT_VERSION,
        name: &f.fhdr.name,
        desc: &f.fhdr.desc,
        time: &f.fhdr.time,
        records: rhdr.map(|h| RecordsIn {
            fields: &h.fields,
            record_length: h.record_length as usize,
            data: f.rdat.unwrap(),
        }),
        hashsets: f
            .sections
            .iter()
            .filter(|s| keep(s.header.htype))
            .map(|s| HashsetIn {
                htype: s.header.htype,
                name: &s.header.name,
                hash_length: s.hash_length(),
                data: s.data,
                hint: None,
                ridx: if drop_ridx { None } else { s.ridx },
                tivf: s.tivf,
            })
            .collect(),
    })
    .unwrap()
}

/// A file with neither records nor hash sections.
fn empty_file() -> Vec<u8> {
    encode(&Document {
        version: FORMAT_VERSION,
        name: "empty",
        desc: "",
        time: "",
        records: None,
        hashsets: vec![],
    })
    .unwrap()
}

const RECORDS_ONLY: In = In {
    records: true,
    hashsets: false,
    index: true,
};

/// C++ hset_merge_errors: two records-only files merge to a records-only
/// file; a records-only file cannot be merged with one that has sections.
#[test]
fn records_only_inputs_merge_to_records_only_and_not_with_hash_sections() {
    let c = tlsh_corpus();
    let ro = build_input(&c, 0..100, &MD5_TLSH, RECORDS_ONLY);
    let ro2 = build_input(&c, 50..150, &MD5_TLSH, RECORDS_ONLY);
    assert_eq!(load(&ro).section_count(), 0);
    let o = merged(SetOp::Union, &ro, &ro2, &opts());
    assert_eq!(load(&o).section_count(), 0);
    assert_eq!(load(&o).record_count(), 150);
    check_output(&o, &ro, &ro2, SetOp::Union, false);

    let a = build_input(&c, 0..100, &MD5_TLSH, REC);
    for (l, r) in [(&a, &ro), (&ro, &a)] {
        assert_contains(
            &merge_err(l, r, &opts()),
            "cannot merge a records-only hashset with one that has hash sections",
        );
    }
}

#[test]
fn inputs_without_records_or_sections_in_common_are_an_error() {
    let c = tlsh_corpus();
    let ro = build_input(&c, 0..100, &MD5_TLSH, RECORDS_ONLY);
    let empty = empty_file();
    for (l, r) in [(&ro, &empty), (&empty, &ro), (&empty, &empty)] {
        assert_contains(
            &merge_err(l, r, &opts()),
            "the inputs have neither records nor hash sections in common",
        );
    }
}

#[test]
fn write_flags_that_leave_nothing_to_write_are_an_error() {
    let c = tlsh_corpus();
    let rec = build_input(&c, 0..100, &MD5_TLSH, REC);
    let ho = build_input(&c, 0..100, &MD5_TLSH, HO);
    let ro = build_input(&c, 0..100, &MD5_TLSH, RECORDS_ONLY);
    let mut neither = opts();
    neither.write_records = false;
    neither.write_hashsets = false;
    let mut no_sections = opts();
    no_sections.write_hashsets = false;
    let mut no_records = opts();
    no_records.write_records = false;
    for (l, r, o) in [
        (&rec, &rec, &neither),
        (&ho, &ho, &no_sections),
        (&rec, &ho, &no_sections),
        (&ro, &ro, &no_records),
    ] {
        assert_contains(
            &merge_err(l, r, o),
            "neither records nor hash sections are to be written",
        );
    }
}

#[test]
fn sections_and_fields_that_disagree_are_an_error() {
    let c = tlsh_corpus();
    let md5_8 = |records: bool| {
        let mut b = Builder::with_fields(vec![FieldDescriptor {
            htype: HashType::Md5,
            name: "md5".into(),
            length: 8,
        }]);
        b.add_record(&[Some(&[7u8; 8][..])]).unwrap();
        b.build(&BuildOptions::new("short", "").records(records))
            .unwrap()
    };
    let md5 = |records: bool| {
        build_input(
            &c,
            0..10,
            &[HashType::Md5],
            In {
                records,
                hashsets: true,
                index: true,
            },
        )
    };
    // a field of two lengths
    assert_contains(
        &merge_err(&md5(true), &md5_8(true), &opts()),
        "field md5 has length 16 on the left and 8 on the right",
    );
    // a section of another length than the output field
    assert_contains(
        &merge_err(&md5(false), &md5_8(false), &opts()),
        "right md5 hashset has hash length 8, expected 16",
    );
    assert_contains(
        &merge_err(&md5_8(false), &md5(false), &opts()),
        "right md5 hashset has hash length 16, expected 8",
    );

    // a record field without its section, a section without its RIDX
    let rec = build_input(&c, 0..100, &MD5_TLSH, REC);
    let no_tlsh = reencode(&rec, |t| t != HashType::Tlsh, false);
    let no_ridx = reencode(&rec, |_| true, true);
    assert_contains(
        &merge_err(&no_tlsh, &rec, &opts()),
        "left has a tlsh field but no tlsh hashset",
    );
    assert_contains(
        &merge_err(&rec, &no_tlsh, &opts()),
        "right has a tlsh field but no tlsh hashset",
    );
    assert_contains(
        &merge_err(&no_ridx, &rec, &opts()),
        "left md5 hashset has no record index",
    );
    assert_contains(
        &merge_err(&rec, &no_ridx, &opts()),
        "right md5 hashset has no record index",
    );
}

#[test]
fn an_overlong_name_is_an_error() {
    let c = tlsh_corpus();
    let ho = build_input(&c, 0..10, &[HashType::Md5], HO);
    let mut o = opts();
    o.name = "x".repeat(65536);
    assert_contains(&merge_err(&ho, &ho, &o), "too long");
}

// ---------------------------------------------------------------------------
// Write flags, hints, invalid indexes
// ---------------------------------------------------------------------------

/// C++ hset_builder_setops_write_flags: without the record table the
/// operation is still applied to the records, rows follow them and are
/// then written once each; without sections the records are those of the
/// full merge.
#[test]
fn write_flags_select_the_record_table_and_the_sections() {
    let c = tlsh_corpus();
    let a = build_input(&c, 0..800, &MD5_TLSH, REC);
    let b = build_input(&c, 400..1200, &MD5_TLSH, REC);
    let mut ho_opts = opts();
    ho_opts.write_records = false;
    let mut ro_opts = opts();
    ro_opts.write_hashsets = false;
    for op in OPS {
        let full = merged(op, &a, &b, &opts());
        let full = load(&full);

        let ho = merged(op, &a, &b, &ho_opts);
        let hs = check_loads(&ho);
        assert!(hs.record_header().is_none());
        assert_eq!(count_tag(&ho, chunk::RIDX), 0);
        assert_eq!(hs.section_count(), full.section_count());
        for t in MD5_TLSH {
            let want: Rows = unique(&rows_of(&full, t)).into_iter().collect();
            assert_eq!(rows_of(&hs, t), want, "{t} of the {}", op.name());
        }
        let t = hs.index_for_type(HashType::Tlsh).unwrap();
        check_tlsh_section(&hs, t, true, true);

        let ro = merged(op, &a, &b, &ro_opts);
        let hs = check_loads(&ro);
        assert_eq!(hs.section_count(), 0);
        assert_eq!(hs.record_header(), full.record_header());
        assert_eq!(hs.file().rdat, full.file().rdat);
    }
}

#[test]
fn digest_sections_get_the_hint_of_the_options_and_tlsh_the_cell_index() {
    let c = tlsh_corpus();
    let types = [HashType::Md5, HashType::Size, HashType::Tlsh];
    let a = build_input(&c, 0..300, &types, REC);
    let b = build_input(&c, 200..500, &types, REC);
    for (hint, md5_tag) in [
        (HintSpec::LEGACY, Some(0x6208)),
        (HintSpec::Hull { bits: 4 }, Some(0x6804)),
        (HintSpec::None, None),
    ] {
        let mut o = opts();
        o.hint = hint;
        let out = merged(SetOp::Union, &a, &b, &o);
        check_output(&out, &a, &b, SetOp::Union, true);
        let hs = load(&out);
        let tag = |t| {
            hs.section(hs.index_for_type(t).unwrap())
                .hint
                .map(|h| h.tag())
        };
        assert_eq!(tag(HashType::Md5), md5_tag, "{hint:?}");
        assert_eq!(tag(HashType::Size), None, "{hint:?}");
        assert_eq!(tag(HashType::Tlsh), Some(0x7400), "{hint:?}");
    }
}

/// `bytes` with the first two ids of its TIVF equal, so that the index
/// fails validation (a row twice, another missing) while its header
/// still parses.
fn with_a_repeated_tivf_id(bytes: &[u8]) -> Vec<u8> {
    let f = hset::format::decode(bytes).unwrap();
    let t = f.section_for(HashType::Tlsh).unwrap();
    let n = f.sections[t].len();
    let &(off, _) = f.toc.iter().find(|&&(_, tag)| tag == chunk::TIVF).unwrap();
    let chunk = chunk::read_chunk(bytes, off as usize).unwrap();
    let ids = off as usize + chunk::CHUNK_HEADER_LEN + chunk.data.len() - 4 * n;
    let mut out = bytes.to_vec();
    out.copy_within(ids + 4..ids + 8, ids);
    out
}

/// Rust validates an input index before merging it (controller ruling
/// 5); C++ trusts it. An invalid index fails a merge that carries it and
/// is ignored by one that does not.
#[test]
fn an_invalid_input_index_fails_only_the_merges_that_carry_it() {
    let c = tlsh_corpus();
    let a = with_a_repeated_tivf_id(&build_input(&c, 0..300, &MD5_TLSH, HO));
    assert!(load(&a).tlsh_index(1).is_err());
    let b = build_input(&c, 200..500, &MD5_TLSH, HO);
    let b_bare = build_input(&c, 200..500, &MD5_TLSH, HO.index(false));
    let mut o = opts();
    for (r, policy, ok) in [
        (&b, TlshIndexPolicy::Inherit, false),
        (&b, TlshIndexPolicy::Write, false),
        (&b, TlshIndexPolicy::Omit, true),
        (&b_bare, TlshIndexPolicy::Inherit, true),
        (&b_bare, TlshIndexPolicy::Write, true),
    ] {
        o.tlsh_index = policy;
        match merge(SetOp::Union, &load(&a), &load(r), &o) {
            Ok(out) => {
                assert!(ok, "{policy:?}");
                check_loads(&out);
            }
            Err(e) => {
                assert!(!ok, "{policy:?}: {e}");
                assert!(matches!(e, Error::Format(_)), "{e}");
                assert_contains(&e.to_string(), "TIVF");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Incremental unions
// ---------------------------------------------------------------------------

/// A TLSH-only, hashsets-only file of `digests` with the index (C++
/// `build_file` of test_hset_merge_incremental.cpp).
fn tlsh_file(digests: &[TlshDigest]) -> Vec<u8> {
    let mut b = Builder::new(&[HashType::Tlsh]).unwrap();
    for d in digests {
        b.add_record(&[Some(&d.0[..])]).unwrap();
    }
    b.build(&BuildOptions::new("inc", "incremental merge test").records(false))
        .unwrap()
}

/// C++ hset_merge_incremental_unions, scaled down: a master absorbs
/// batches, half new families and half near-duplicates of master rows,
/// by unions with the index written and coalescing threshold C. After
/// every step the rows are the union so far, the index is valid and
/// coalesced (at most one list per cell below C / 2), each cell of m rows
/// has at most m / (C / 2) + 1 lists, with the default C at most one list
/// (48 TIVF bytes) more per nonempty cell than a fresh build, and the
/// index search is exact.
#[test]
fn incremental_unions_keep_the_index_within_its_bounds() {
    const MASTER: usize = 3000;
    const STEPS: u64 = 5;
    const HALF_BATCH: usize = 150;
    let master_corpus = corpus(101, MASTER);
    let near = Perturbation {
        bucket_flip_prob: 0.03,
        ..Perturbation::default()
    };
    let batches: Vec<Vec<TlshDigest>> = (0..STEPS)
        .map(|i| {
            let mut b = corpus(1000 + i, HALF_BATCH);
            b.extend(perturb_corpus(2000 + i, &master_corpus, HALF_BATCH, &near));
            b
        })
        .collect();
    let sorted_unique =
        |d: &[TlshDigest]| -> BTreeSet<[u8; 36]> { d.iter().map(|d| d.0).collect() };

    let mut final_lists = Vec::new();
    for c in [64, 32, 0] {
        let mut o = MergeOptions::new("inc", "incremental merge test");
        o.tlsh_index = TlshIndexPolicy::Write;
        o.coalesce_threshold = c;
        let mut expected = sorted_unique(&master_corpus);
        let mut master = tlsh_file(&master_corpus);
        for (step, batch) in batches.iter().enumerate() {
            let out = merge(SetOp::Union, &load(&master), &load(&tlsh_file(batch)), &o).unwrap();
            let hs = load(&out);
            assert!(
                hs.verify().is_ok(),
                "C {c} step {step}: {:?}",
                hs.verify().problems
            );

            expected.extend(sorted_unique(batch));
            let rows = hs.tlsh_rows(0).unwrap();
            assert!(rows.iter().eq(expected.iter()), "C {c} step {step}: rows");

            let ivf = hs.tlsh_index(0).unwrap().unwrap();
            assert!(check_invariant(&ivf, c), "C {c} step {step}");
            let cells = naive_cell_index(rows);
            let sizes = cells.windows(2).map(|w| w[1] - w[0]).filter(|&m| m > 0);
            let nonempty = sizes.clone().count();
            if c > 0 {
                let bound: u64 = sizes.map(|m| m / u64::from(c / 2) + 1).sum();
                assert!(ivf.lists() as u64 <= bound, "C {c} step {step}");
            }
            if c == DEFAULT_COALESCE {
                let fresh = build_tlsh_ivf(rows, &IvfBuildOptions::default()).unwrap();
                assert!(ivf.lists() <= fresh.lists() + nonempty, "step {step}");
                let n = rows.len() as u64;
                assert!(
                    tivf_len(ivf.lists() as u32, n)
                        <= tivf_len(fresh.lists() as u32, n) + 48 * nonempty as u64
                );
            }
            check_knn_exact(&hs, 0, 77 + step as u64);
            drop(hs);
            master = out;
        }
        let hs = load(&master);
        final_lists.push(hs.tlsh_index(0).unwrap().unwrap().lists());
    }
    // coalescing keeps the lists down; without it they accumulate
    assert!(
        final_lists[0] <= final_lists[1] && final_lists[1] < final_lists[2],
        "lists at C = 64, 32, 0: {final_lists:?}"
    );
}

// ---------------------------------------------------------------------------
// The C++ merges on disk
// ---------------------------------------------------------------------------

/// A merge the C++ suites run whose inputs and output they leave in
/// `test/` (the last one written to each output file).
struct CppMerge {
    out: &'static str,
    left: &'static str,
    right: &'static str,
    op: SetOp,
    /// C `tlsh_options`.
    tlsh_options: u32,
    /// C `coalesce_threshold` (`SFHASH_HSET_COALESCE_DEFAULT` is 64).
    coalesce: u32,
    write_records: bool,
    write_hashsets: bool,
    /// Whether the TIVF payloads are compared.
    compare_tivf: bool,
}

const fn cpp(out: &'static str, left: &'static str, right: &'static str, op: SetOp) -> CppMerge {
    CppMerge {
        out,
        left,
        right,
        op,
        tlsh_options: 4, // INHERIT
        coalesce: DEFAULT_COALESCE,
        write_records: true,
        write_hashsets: true,
        compare_tivf: true,
    }
}

impl CppMerge {
    const fn tlsh_options(self, tlsh_options: u32) -> Self {
        CppMerge {
            tlsh_options,
            ..self
        }
    }

    const fn flags(self, write_records: bool, write_hashsets: bool) -> Self {
        CppMerge {
            write_records,
            write_hashsets,
            ..self
        }
    }
}

use SetOp::{Intersect as I, Subtract as D, Union as U};

/// The merges of test_hset_merge.cpp and test_hset_merge_incremental.cpp
/// whose files are on disk after `make check`: each output file holds the
/// last merge the suite wrote to it (run_matrix ends with its last case,
/// INDEX/INDEX inputs merged with options 1 by DIFFERENCE; the set-op
/// loops end with the difference).
const CPP_MERGES: &[CppMerge] = &[
    cpp(
        "merge_out_rec.hset",
        "merge_a_rec.hset",
        "merge_b_rec.hset",
        D,
    )
    .tlsh_options(1),
    cpp("merge_out_ho.hset", "merge_a_ho.hset", "merge_b_ho.hset", D).tlsh_options(1),
    cpp(
        "merge_alg_ab.hset",
        "merge_alg_a_rec.hset",
        "merge_alg_b_rec.hset",
        U,
    ),
    cpp(
        "merge_alg_ba.hset",
        "merge_alg_b_rec.hset",
        "merge_alg_a_rec.hset",
        U,
    ),
    cpp(
        "merge_alg_a-a.hset",
        "merge_alg_a_rec.hset",
        "merge_alg_a_rec.hset",
        D,
    ),
    cpp(
        "merge_alg_a&a.hset",
        "merge_alg_a_rec.hset",
        "merge_alg_a_rec.hset",
        I,
    ),
    cpp(
        "merge_alg_ab-b.hset",
        "merge_alg_ab.hset",
        "merge_alg_b_rec.hset",
        D,
    ),
    cpp(
        "merge_alg_a-b.hset",
        "merge_alg_a_rec.hset",
        "merge_alg_b_rec.hset",
        D,
    ),
    cpp("merge_df_out.hset", "merge_df_a.hset", "merge_df_b.hset", D),
    cpp(
        "merge_df_out2.hset",
        "merge_df_b.hset",
        "merge_df_a.hset",
        U,
    ),
    cpp("merge_mx_out.hset", "merge_mx_a.hset", "merge_mx_b.hset", D),
    cpp(
        "merge_mx_out2.hset",
        "merge_mx_b.hset",
        "merge_mx_a.hset",
        D,
    ),
    cpp("merge_t1_out.hset", "merge_t1_a.hset", "merge_t1_b.hset", D),
    cpp(
        "merge_err_out.hset",
        "merge_err_ro.hset",
        "merge_err_ro2.hset",
        U,
    ),
    cpp(
        "setop_out_rec.hset",
        "setop_a_rec.hset",
        "setop_b_rec.hset",
        D,
    ),
    cpp(
        "setop_merge_rec.hset",
        "setop_a_rec.hset",
        "setop_b_rec.hset",
        D,
    ),
    cpp("setop_out_ho.hset", "setop_a_ho.hset", "setop_b_ho.hset", D),
    cpp(
        "setop_merge_ho.hset",
        "setop_a_ho.hset",
        "setop_b_ho.hset",
        D,
    ),
    cpp(
        "setop_fl_full.hset",
        "setop_fl_a.hset",
        "setop_fl_b.hset",
        D,
    ),
    cpp("setop_fl_ho.hset", "setop_fl_a.hset", "setop_fl_b.hset", D).flags(false, true),
    cpp("setop_fl_ro.hset", "setop_fl_a.hset", "setop_fl_b.hset", D).flags(true, false),
    // inputs without an index: INDEX builds one from scratch (BISECT)
    cpp(
        "setop_fl_both.hset",
        "setop_fl_na.hset",
        "setop_fl_nb.hset",
        U,
    )
    .tlsh_options(2),
    cpp(
        "setop_fl_none.hset",
        "setop_fl_na.hset",
        "setop_fl_nb.hset",
        U,
    ),
    // the last step of the C = 0 simulation (step 23 writes inc_out_a
    // from step 22's inc_out_b)
    CppMerge {
        coalesce: 0,
        ..cpp("inc_out_a.hset", "inc_out_b.hset", "inc_batch.hset", U).tlsh_options(2)
    },
];

/// The payloads of `ours` equal those of the C++ output `theirs` chunk
/// by chunk: RHDR and RDAT, and per section its header, HINT (legacy
/// block hints and TLSH cell indexes), HDAT, RIDX and TIVF.
fn assert_same_payloads(name: &str, ours: &[u8], theirs: &[u8]) {
    let (a, b) = (
        hset::format::decode(ours).unwrap(),
        hset::format::decode(theirs).unwrap(),
    );
    assert_eq!(a.rhdr, b.rhdr, "{name}: RHDR");
    assert!(a.rdat == b.rdat, "{name}: RDAT");
    assert_eq!(a.sections.len(), b.sections.len(), "{name}: sections");
    for (s, t) in a.sections.iter().zip(&b.sections) {
        let what = format!("{name}: {} section", s.header.htype);
        assert_eq!(s.header, t.header, "{what} header");
        assert!(s.data == t.data, "{what} HDAT");
        assert!(s.ridx == t.ridx, "{what} RIDX");
        assert!(
            s.hint.map(|h| (h.tag(), h.byte_len())) == t.hint.map(|h| (h.tag(), h.byte_len()))
                && s.hint == t.hint,
            "{what} HINT {:?} vs {:?}",
            s.hint.map(|h| h.tag()),
            t.hint.map(|h| h.tag())
        );
        assert!(s.tivf == t.tivf, "{what} TIVF");
    }
}

/// Re-runs the C++ merges whose inputs and outputs are on disk
/// (`HSET_FIXTURES_DIR`) and compares the payloads; absent files are
/// skipped. Rust writes the legacy block hint here, as C++ does.
/// Re-runs `merges` from the files on disk (`HSET_FIXTURES_DIR`) and
/// compares the payloads; absent files are skipped. Rust writes the
/// legacy block hint here, as C++ does.
fn run_cpp_merges(merges: &[CppMerge]) {
    let dir = hset_testkit::fixtures::fixtures_dir();
    let read = |name: &str| std::fs::read(dir.join(name)).ok();
    let mut compared = 0;
    for m in merges {
        let (Some(theirs), Some(l), Some(r)) = (read(m.out), read(m.left), read(m.right)) else {
            eprintln!(
                "SKIP: {} or its inputs are absent (run the C++ make check)",
                m.out
            );
            continue;
        };
        let mut o = MergeOptions::new("merged", "merge test output");
        o.hint = HintSpec::LEGACY;
        o.tlsh_index = TlshIndexPolicy::from_tlsh_options(m.tlsh_options).unwrap();
        o.coalesce_threshold = m.coalesce;
        o.write_records = m.write_records;
        o.write_hashsets = m.write_hashsets;
        let ours =
            merge(m.op, &load(&l), &load(&r), &o).unwrap_or_else(|e| panic!("{}: {e}", m.out));
        let report = load(&ours).verify();
        assert!(report.is_ok(), "{}: {:?}", m.out, report.problems);
        let ours = if m.compare_tivf {
            ours
        } else {
            without_tivf(&ours)
        };
        let theirs = if m.compare_tivf {
            theirs
        } else {
            without_tivf(&theirs)
        };
        assert_same_payloads(m.out, &ours, &theirs);
        compared += 1;
    }
    eprintln!("compared {compared} of {} C++ merges", merges.len());
}

/// `bytes` re-encoded without its TIVF chunks.
fn without_tivf(bytes: &[u8]) -> Vec<u8> {
    let f = hset::format::decode(bytes).unwrap();
    let rhdr = f.rhdr.as_ref();
    encode(&Document {
        version: FORMAT_VERSION,
        name: &f.fhdr.name,
        desc: &f.fhdr.desc,
        time: &f.fhdr.time,
        records: rhdr.map(|h| RecordsIn {
            fields: &h.fields,
            record_length: h.record_length as usize,
            data: f.rdat.unwrap(),
        }),
        hashsets: f
            .sections
            .iter()
            .map(|s| HashsetIn {
                htype: s.header.htype,
                name: &s.header.name,
                hash_length: s.hash_length(),
                data: s.data,
                hint: s.hint.map(|h| match h {
                    Hint::Block { table, .. }
                    | Hint::Hull { table, .. }
                    | Hint::TlshCells { table } => (h.tag(), table),
                    Hint::Unknown { tag, data } => (tag, data),
                }),
                ridx: s.ridx,
                tivf: None,
            })
            .collect(),
    })
    .unwrap()
}

#[test]
fn rust_merges_reproduce_the_cpp_merge_payloads() {
    run_cpp_merges(CPP_MERGES);
}

/// The large C++ merges on disk: hset_merge_timing's 200k + 200k union
/// (merge_big_*), and hset_merge_rebuild_honours_index_kmeans's union
/// whose index C++ last rebuilt with INDEX_KMEANS (merge_method_*), which
/// Rust does not port: there Rust builds by BISECT and only the other
/// payloads are compared.
#[test]
#[ignore = "large: run with --run-ignored and HSET_FIXTURES_DIR"]
fn rust_merges_reproduce_the_large_cpp_merge_payloads() {
    run_cpp_merges(&[
        cpp(
            "merge_big_out.hset",
            "merge_big_a.hset",
            "merge_big_b.hset",
            U,
        ),
        CppMerge {
            compare_tivf: false,
            ..cpp(
                "merge_method_out.hset",
                "merge_method_a.hset",
                "merge_method_b.hset",
                U,
            )
            .tlsh_options(2)
        },
    ]);
}
