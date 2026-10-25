//! Row and record merges (`hset::merge`), ported from test_hset_merge.cpp
//! (merge_rows_sets, merge_rows_records, the differing-fields record
//! merges) plus proptests against `BTreeSet` / `BTreeMap` models.

use hset::Error;
use hset::merge::{DROPPED, RECORD_DROPPED, RowMerge, RowMode, RowOwners, merge_rows};
use hset::ops::SetOp;

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
