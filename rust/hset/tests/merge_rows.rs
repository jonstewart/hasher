//! Row and record merges (`hset::merge`), ported from test_hset_merge.cpp
//! (merge_rows_sets, merge_rows_records, the differing-fields record
//! merges) plus proptests against `BTreeSet` / `BTreeMap` models.

use std::collections::{BTreeMap, BTreeSet};

use hset::format::{FieldDescriptor, RecordHeader};
use hset::merge::{
    DROPPED, RECORD_DROPPED, RowMerge, RowMode, RowOwners, merge_records, merge_rows,
    merged_record_fields,
};
use hset::ops::SetOp;
use hset::{Error, HashType};
use hset_testkit::oracle::set_op_model;
use hset_testkit::strategies::set_op;
use proptest::prelude::*;

const D: u32 = DROPPED;

// 2-byte rows of test_hset_merge.cpp merge_rows_sets
const L5: [u8; 10] = [0, 1, 0, 3, 0, 3, 0, 5, 0, 9];
const R5: [u8; 10] = [0, 3, 0, 4, 0, 9, 0, 9, 1, 0];

fn sets(op: SetOp, l: &[u8], r: &[u8]) -> RowMerge {
    merge_rows(l, r, 2, RowMode::Set(op)).unwrap()
}

#[test]
fn set_union_emits_each_distinct_row_once_left_copy_first() {
    let m = sets(SetOp::Union, &L5, &R5);
    assert_eq!(m.n, 6);
    assert_eq!(m.lmap, [0, 1, D, 3, 4]);
    assert_eq!(m.rmap, [D, 2, D, D, 5]);
}

#[test]
fn set_intersect_emits_rows_on_both_sides_as_left_copies() {
    let m = sets(SetOp::Intersect, &L5, &R5);
    assert_eq!(m.n, 2);
    assert_eq!(m.lmap, [D, 0, D, D, 1]);
    assert_eq!(m.rmap, [D; 5]);
}

#[test]
fn set_difference_emits_left_rows_absent_on_the_right() {
    let m = sets(SetOp::Subtract, &L5, &R5);
    assert_eq!(m.n, 2);
    assert_eq!(m.lmap, [0, D, D, 1, D]);
    assert_eq!(m.rmap, [D; 5]);
}

#[test]
fn set_merges_with_an_empty_side() {
    assert_eq!(sets(SetOp::Union, &L5, &[]).n, 4);
    assert_eq!(sets(SetOp::Intersect, &L5, &[]).n, 0);
    assert_eq!(sets(SetOp::Subtract, &[], &R5).n, 0);
    let m = sets(SetOp::Union, &[], &R5);
    assert_eq!(m.n, 4);
    assert_eq!(m.rmap, [0, 1, 2, D, 3]);
    assert!(m.lmap.is_empty());
}

/// An `RIDX` payload: one little-endian u64 per row.
fn ridx(recs: &[u64]) -> Vec<u8> {
    recs.iter().flat_map(|r| r.to_le_bytes()).collect()
}

fn records(l: &[u8], lo: RowOwners<'_>, r: &[u8], ro: RowOwners<'_>, collapse: bool) -> RowMerge {
    let mode = RowMode::Records {
        left: lo,
        right: ro,
        collapse_equal: collapse,
    };
    merge_rows(l, r, 2, mode).unwrap()
}

// rows owned by records, test_hset_merge.cpp merge_rows_records
const L4: [u8; 8] = [0, 1, 0, 3, 0, 3, 0, 5];
const L4_RECMAP: [u64; 4] = [0, RD, 2, 3];
const R2: [u8; 4] = [0, 3, 0, 4];
const R2_RECMAP: [u64; 2] = [1, RD];
const RD: u64 = RECORD_DROPPED;

#[test]
fn record_rows_follow_their_records_and_left_precedes_right_on_ties() {
    let (lr, rr) = (ridx(&[0, 1, 2, 3]), ridx(&[0, 1]));
    let lo = RowOwners {
        ridx: &lr,
        recmap: &L4_RECMAP,
    };
    let ro = RowOwners {
        ridx: &rr,
        recmap: &R2_RECMAP,
    };
    let m = records(&L4, lo, &R2, ro, false);
    // 0,1 (l0) 0,3 (l2) 0,3 (r0) 0,5 (l3)
    assert_eq!(m.n, 4);
    assert_eq!(m.lmap, [0, D, 1, 3]);
    assert_eq!(m.rmap, [2, D]);
    // HDAT and RIDX of the output: l0 rec 0 -> 0, l2 rec 2 -> 2, r0 rec 0 -> 1,
    // l3 rec 3 -> 3
    assert_eq!(
        m.gather_rows(&L4, &R2, 2).unwrap(),
        [0, 1, 0, 3, 0, 3, 0, 5]
    );
    assert_eq!(m.gather_ridx(lo, ro).unwrap(), ridx(&[0, 2, 1, 3]));
}

#[test]
fn gather_rows_of_a_set_union_is_the_sorted_distinct_rows() {
    let m = sets(SetOp::Union, &L5, &R5);
    assert_eq!(
        m.gather_rows(&L5, &R5, 2).unwrap(),
        [0, 1, 0, 3, 0, 4, 0, 5, 0, 9, 1, 0]
    );
    // the inputs must be the merged ones
    assert!(matches!(
        m.gather_rows(&L5, &R5[2..], 2),
        Err(Error::Input(_))
    ));
    assert!(matches!(
        m.gather_rows(&L5[2..], &R5, 2),
        Err(Error::Input(_))
    ));
}

#[test]
fn record_rows_with_collapse_equal_emit_equal_rows_once() {
    let (lr, rr) = (ridx(&[0, 1, 2, 3]), ridx(&[0, 1]));
    let lo = RowOwners {
        ridx: &lr,
        recmap: &L4_RECMAP,
    };
    let ro = RowOwners {
        ridx: &rr,
        recmap: &R2_RECMAP,
    };
    let m = records(&L4, lo, &R2, ro, true);
    // 0,1 (l0) 0,3 (l2) 0,5 (l3); r0 equals l2 and is dropped
    assert_eq!(m.n, 3);
    assert_eq!(m.lmap, [0, D, 1, 2]);
    assert_eq!(m.rmap, [D, D]);

    // equal rows of kept records on one side: both stay unless collapsed
    let lr = ridx(&[1, 0]);
    let lo = RowOwners {
        ridx: &lr,
        recmap: &[0, 1],
    };
    let ro = RowOwners {
        ridx: &[],
        recmap: &[],
    };
    assert_eq!(records(&[0, 3, 0, 3], lo, &[], ro, false).lmap, [0, 1]);
    assert_eq!(records(&[0, 3, 0, 3], lo, &[], ro, true).lmap, [0, D]);
}

#[test]
fn merge_rows_rejects_bad_row_shapes() {
    let set = RowMode::Set(SetOp::Union);
    assert!(matches!(merge_rows(&[], &[], 0, set), Err(Error::Input(_))));
    assert!(matches!(
        merge_rows(&[0, 1, 2], &[], 2, set),
        Err(Error::Input(_))
    ));
    assert!(matches!(
        merge_rows(&[], &[0], 2, set),
        Err(Error::Input(_))
    ));
}

#[test]
fn merge_rows_rejects_owners_that_disagree_with_the_rows() {
    let none = RowOwners {
        ridx: &[],
        recmap: &[],
    };
    let mode = |left, right| RowMode::Records {
        left,
        right,
        collapse_equal: false,
    };
    // a record index shorter than the rows, or ragged
    let short = ridx(&[0]);
    let lo = RowOwners {
        ridx: &short,
        recmap: &[0, 1],
    };
    assert!(matches!(
        merge_rows(&L4[..4], &[], 2, mode(lo, none)),
        Err(Error::Input(_))
    ));
    let ragged = [0u8; 15];
    let ro = RowOwners {
        ridx: &ragged,
        recmap: &[0, 1],
    };
    assert!(matches!(
        merge_rows(&[], &R2, 2, mode(none, ro)),
        Err(Error::Input(_))
    ));
    // a row naming a record past the record map
    let far = ridx(&[0, 2]);
    let ro = RowOwners {
        ridx: &far,
        recmap: &[0, 1],
    };
    let e = merge_rows(&[], &R2, 2, mode(none, ro)).unwrap_err();
    assert!(matches!(e, Error::Format(_)), "{e}");
    assert!(e.to_string().contains("right row 1 names record 2"), "{e}");
}

fn field(htype: HashType, name: &str, length: u64) -> FieldDescriptor {
    FieldDescriptor {
        htype,
        name: name.to_string(),
        length,
    }
}

fn canonical(t: HashType) -> FieldDescriptor {
    FieldDescriptor::for_type(t).unwrap()
}

fn header(fields: Vec<FieldDescriptor>, count: u64) -> RecordHeader {
    RecordHeader {
        record_length: fields.iter().map(FieldDescriptor::stride).sum::<usize>() as u64,
        record_count: count,
        fields,
    }
}

#[test]
fn merged_fields_are_the_left_fields_then_the_right_extras() {
    // test_hset_merge.cpp hset_merge_records_differing_fields, with SIZE in
    // TLSH's place: md5 + size against sha1 + size gives md5, size, sha1
    let l = header(
        vec![
            canonical(HashType::Md5),
            field(HashType::Size, "left size", 8),
        ],
        0,
    );
    let r = header(
        vec![
            canonical(HashType::Sha1),
            field(HashType::Size, "right size", 8),
        ],
        0,
    );
    let f = merged_record_fields(&l, &r).unwrap();
    assert_eq!(
        f,
        [
            canonical(HashType::Md5),
            field(HashType::Size, "left size", 8),
            canonical(HashType::Sha1)
        ]
    );
    let f = merged_record_fields(&r, &l).unwrap();
    assert_eq!(
        f,
        [
            canonical(HashType::Sha1),
            field(HashType::Size, "right size", 8),
            canonical(HashType::Md5)
        ]
    );
}

#[test]
fn merged_fields_reject_a_type_with_two_lengths() {
    let l = header(vec![field(HashType::Md5, "md5", 16)], 0);
    let r = header(
        vec![canonical(HashType::Sha1), field(HashType::Md5, "md5", 15)],
        0,
    );
    let e = merged_record_fields(&l, &r).unwrap_err();
    assert!(matches!(e, Error::Input(_)), "{e}");
    assert!(
        e.to_string()
            .contains("field md5 has length 16 on the left and 15 on the right"),
        "{e}"
    );
}

// one-byte fields A (md5), B (size), C (sha1): left has A B, right C B, so
// widening reorders the right side's fields and it must be re-sorted
fn fa() -> FieldDescriptor {
    field(HashType::Md5, "a", 1)
}
fn fb() -> FieldDescriptor {
    field(HashType::Size, "b", 1)
}
fn fc() -> FieldDescriptor {
    field(HashType::Sha1, "c", 1)
}

// left records (A B), sorted
const LREC: [u8; 12] = [
    0, 0, 1, 7, // A absent, B 7
    1, 1, 1, 5, // A 1, B 5
    1, 2, 0, 0, // A 2, B absent
];
// right records (C B), sorted
const RREC: [u8; 12] = [
    0, 0, 1, 7, // C absent, B 7: equals left record 0 once widened
    1, 1, 0, 0, // C 1, B absent
    1, 3, 1, 2, // C 3, B 2
];

fn rec_merge(op: SetOp) -> hset::merge::RecordMerge {
    let l = header(vec![fa(), fb()], 3);
    let r = header(vec![fc(), fb()], 3);
    merge_records(op, &l, &LREC, &r, &RREC).unwrap()
}

#[test]
fn record_union_widens_resorts_and_keeps_the_left_copy_of_identical_records() {
    let m = rec_merge(SetOp::Union);
    assert_eq!(m.fields, [fa(), fb(), fc()]);
    assert_eq!(m.record_length, 6);
    // widened to A B C and sorted
    #[rustfmt::skip]
    let want = [
        0, 0, 0, 0, 1, 1, // r1
        0, 0, 1, 2, 1, 3, // r2
        0, 0, 1, 7, 0, 0, // l0 (= r0)
        1, 1, 1, 5, 0, 0, // l1
        1, 2, 0, 0, 0, 0, // l2
    ];
    assert_eq!(m.rdat, want);
    assert_eq!(m.record_count(), 5);
    assert_eq!(m.lmap, [2, 3, 4]);
    assert_eq!(m.rmap, [RD, 0, 1]);
    assert_eq!(m.header(), header(vec![fa(), fb(), fc()], 5));
}

#[test]
fn record_intersect_and_difference_emit_left_records_only() {
    let m = rec_merge(SetOp::Intersect);
    assert_eq!(m.rdat, [0, 0, 1, 7, 0, 0]);
    assert_eq!(m.lmap, [0, RD, RD]);
    assert_eq!(m.rmap, [RD; 3]);

    let m = rec_merge(SetOp::Subtract);
    assert_eq!(m.rdat, [1, 1, 1, 5, 0, 0, 1, 2, 0, 0, 0, 0]);
    assert_eq!(m.lmap, [RD, 0, 1]);
    assert_eq!(m.rmap, [RD; 3]);
}

#[test]
fn record_merge_rejects_headers_that_disagree_with_the_data() {
    let good = header(vec![fa(), fb()], 3);
    let mut bad_len = good.clone();
    bad_len.record_length = 5;
    let mut bad_count = good.clone();
    bad_count.record_count = 2;
    for bad in [bad_len, bad_count] {
        let e = merge_records(SetOp::Union, &bad, &LREC, &good, &LREC).unwrap_err();
        assert!(matches!(e, Error::Format(_)), "{e}");
        let e = merge_records(SetOp::Union, &good, &LREC, &bad, &LREC).unwrap_err();
        assert!(matches!(e, Error::Format(_)), "{e}");
    }
    let e = merge_records(SetOp::Union, &good, &LREC[..8], &good, &LREC).unwrap_err();
    assert!(matches!(e, Error::Format(_)), "{e}");
}

// ---------------------------------------------------------------------------
// proptests against BTreeSet / BTreeMap models

/// Sorted 2-byte rows over a small alphabet, so runs and cross-side equal
/// rows are common.
fn sorted_rows2() -> impl Strategy<Value = Vec<[u8; 2]>> {
    prop::collection::vec(prop::array::uniform2(0u8..3), 0..14).prop_map(|mut v| {
        v.sort();
        v
    })
}

fn flat(rows: &[[u8; 2]]) -> Vec<u8> {
    rows.concat()
}

/// Rows with owning records: each row names a record, each record is kept
/// (`Some(output record)`) or dropped.
fn owned_rows() -> impl Strategy<Value = (Vec<[u8; 2]>, Vec<u64>, Vec<Option<u64>>)> {
    (
        sorted_rows2(),
        prop::collection::vec(prop::option::of(0u64..100), 1..6),
    )
        .prop_flat_map(|(rows, fates)| {
            let n = rows.len();
            let nrec = fates.len() as u64;
            (
                Just(rows),
                prop::collection::vec(0..nrec, n..=n),
                Just(fates),
            )
        })
}

fn recmap(fates: &[Option<u64>]) -> Vec<u64> {
    fates.iter().map(|f| f.unwrap_or(RD)).collect()
}

proptest! {
    #[test]
    fn set_merge_matches_the_btreeset_model(
        l in sorted_rows2(), r in sorted_rows2(), op in set_op()
    ) {
        let m = merge_rows(&flat(&l), &flat(&r), 2, RowMode::Set(op)).unwrap();
        let ls: BTreeSet<Vec<u8>> = l.iter().map(|x| x.to_vec()).collect();
        let rs: BTreeSet<Vec<u8>> = r.iter().map(|x| x.to_vec()).collect();
        let want: Vec<Vec<u8>> = set_op_model(op, &ls, &rs).into_iter().collect();

        prop_assert_eq!(m.n, want.len() as u64);
        prop_assert_eq!(m.gather_rows(&flat(&l), &flat(&r), 2).unwrap(), want.concat());
        // the first row of a left run stands for it when its value is output;
        // a right run is emitted only for a value the left lacks
        for (i, row) in l.iter().enumerate() {
            let first = i == 0 || l[i - 1] != *row;
            let at = want.iter().position(|w| w == row);
            let expect = if first { at.map_or(D, |k| k as u32) } else { D };
            prop_assert_eq!(m.lmap[i], expect, "left row {}", i);
        }
        for (j, row) in r.iter().enumerate() {
            let first = j == 0 || r[j - 1] != *row;
            let at = want.iter().position(|w| w == row);
            let expect = match at {
                Some(k) if first && !ls.contains(&row.to_vec()) => k as u32,
                _ => D,
            };
            prop_assert_eq!(m.rmap[j], expect, "right row {}", j);
        }
    }

    #[test]
    fn record_mode_merge_matches_a_stable_sort_of_the_kept_rows(
        (l, lridx, lfates) in owned_rows(),
        (r, rridx, rfates) in owned_rows(),
        collapse in any::<bool>(),
    ) {
        let (lrm, rrm) = (recmap(&lfates), recmap(&rfates));
        let (lrb, rrb) = (ridx(&lridx), ridx(&rridx));
        let lo = RowOwners { ridx: &lrb, recmap: &lrm };
        let ro = RowOwners { ridx: &rrb, recmap: &rrm };
        let mode = RowMode::Records { left: lo, right: ro, collapse_equal: collapse };
        let m = merge_rows(&flat(&l), &flat(&r), 2, mode).unwrap();

        // model: kept rows as (row, side, index), sorted so ties put left
        // (side 0) first and keep input order; collapsing keeps the first of
        // each value
        let mut kept: Vec<([u8; 2], u8, usize)> = Vec::new();
        for (i, row) in l.iter().enumerate() {
            if lfates[lridx[i] as usize].is_some() {
                kept.push((*row, 0, i));
            }
        }
        for (j, row) in r.iter().enumerate() {
            if rfates[rridx[j] as usize].is_some() {
                kept.push((*row, 1, j));
            }
        }
        kept.sort();
        if collapse {
            kept.dedup_by_key(|k| k.0);
        }
        let (mut lmap, mut rmap) = (vec![D; l.len()], vec![D; r.len()]);
        let mut want_ridx = Vec::new();
        for (k, &(_, side, i)) in kept.iter().enumerate() {
            if side == 0 {
                lmap[i] = k as u32;
                want_ridx.push(lfates[lridx[i] as usize].unwrap());
            } else {
                rmap[i] = k as u32;
                want_ridx.push(rfates[rridx[i] as usize].unwrap());
            }
        }
        prop_assert_eq!(m.n, kept.len() as u64);
        prop_assert_eq!(&m.lmap, &lmap);
        prop_assert_eq!(&m.rmap, &rmap);
        let rows: Vec<[u8; 2]> = kept.iter().map(|k| k.0).collect();
        prop_assert_eq!(m.gather_rows(&flat(&l), &flat(&r), 2).unwrap(), rows.concat());
        prop_assert_eq!(m.gather_ridx(lo, ro).unwrap(), ridx(&want_ridx));
    }
}

/// The three one-byte field types the record proptests draw from.
const TYPES: [HashType; 3] = [HashType::Md5, HashType::Size, HashType::Sha1];

/// A record as the model sees it: each field type's value, `None` = absent.
type ModelRecord = BTreeMap<HashType, Option<u8>>;

/// A record table with a shuffled nonempty subset of `TYPES` as its fields.
fn record_table() -> impl Strategy<Value = (Vec<HashType>, Vec<ModelRecord>)> {
    Just(TYPES.to_vec())
        .prop_shuffle()
        .prop_flat_map(|types| (Just(types), 1usize..=3))
        .prop_flat_map(|(types, k)| {
            let types: Vec<HashType> = types[..k].to_vec();
            let rec = prop::collection::vec(prop::option::of(0u8..3), k..=k);
            (Just(types), prop::collection::vec(rec, 0..12))
        })
        .prop_map(|(types, recs)| {
            let recs = recs
                .into_iter()
                .map(|vals| types.iter().copied().zip(vals).collect())
                .collect();
            (types, recs)
        })
}

/// A record in the layout `types`: presence byte and value per field, an
/// absent field (or one the record lacks) all zero.
fn layout(types: &[HashType], rec: &ModelRecord) -> Vec<u8> {
    types
        .iter()
        .flat_map(|t| match rec.get(t).copied().flatten() {
            Some(v) => [1, v],
            None => [0, 0],
        })
        .collect()
}

/// The sorted, unique records of a table, as the builder writes them.
fn table_bytes(types: &[HashType], recs: &[ModelRecord]) -> (RecordHeader, Vec<Vec<u8>>) {
    let rows: BTreeSet<Vec<u8>> = recs.iter().map(|r| layout(types, r)).collect();
    let fields = types.iter().map(|&t| field(t, t.field_name(), 1)).collect();
    (
        header(fields, rows.len() as u64),
        rows.into_iter().collect(),
    )
}

/// Reads a record in the layout `types` back into the model.
fn unlayout(types: &[HashType], bytes: &[u8]) -> ModelRecord {
    types
        .iter()
        .zip(bytes.chunks_exact(2))
        .map(|(&t, pv)| (t, (pv[0] == 1).then_some(pv[1])))
        .collect()
}

proptest! {
    #[test]
    fn record_merge_matches_the_btreemap_model(
        (ltypes, lrecs) in record_table(),
        (rtypes, rrecs) in record_table(),
        op in set_op(),
    ) {
        let (lh, lrows) = table_bytes(&ltypes, &lrecs);
        let (rh, rrows) = table_bytes(&rtypes, &rrecs);
        let m = merge_records(op, &lh, &lrows.concat(), &rh, &rrows.concat()).unwrap();

        // the output layout: left types, then the right types the left lacks
        let mut otypes = ltypes.clone();
        otypes.extend(rtypes.iter().filter(|t| !ltypes.contains(t)));
        let ofields: Vec<HashType> = m.fields.iter().map(|f| f.htype).collect();
        prop_assert_eq!(&ofields, &otypes);
        prop_assert_eq!(m.record_length, 2 * otypes.len() as u64);

        // every record widened through the model
        let widen = |types: &[HashType], row: &Vec<u8>| layout(&otypes, &unlayout(types, row));
        let lw: Vec<Vec<u8>> = lrows.iter().map(|x| widen(&ltypes, x)).collect();
        let rw: Vec<Vec<u8>> = rrows.iter().map(|x| widen(&rtypes, x)).collect();
        let ls: BTreeSet<Vec<u8>> = lw.iter().cloned().collect();
        let rs: BTreeSet<Vec<u8>> = rw.iter().cloned().collect();
        let want: Vec<Vec<u8>> = set_op_model(op, &ls, &rs).into_iter().collect();
        prop_assert_eq!(&m.rdat, &want.concat());
        prop_assert_eq!(m.record_count(), want.len() as u64);

        let pos = |w: &Vec<u8>| want.iter().position(|x| x == w).map_or(RD, |k| k as u64);
        let lmap: Vec<u64> = lw.iter().map(pos).collect();
        let rmap: Vec<u64> = rw
            .iter()
            .map(|w| if op == SetOp::Union && !ls.contains(w) { pos(w) } else { RD })
            .collect();
        prop_assert_eq!(&m.lmap, &lmap);
        prop_assert_eq!(&m.rmap, &rmap);
    }
}
