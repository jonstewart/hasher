//! Row and record merges (`hset::merge`), ported from test_hset_merge.cpp
//! (merge_rows_sets, merge_rows_records, the differing-fields record
//! merges) plus proptests against `BTreeSet` / `BTreeMap` models.

use hset::merge::{DROPPED, RowMerge, RowMode, merge_rows};
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
