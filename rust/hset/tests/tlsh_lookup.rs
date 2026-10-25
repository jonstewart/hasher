//! Exact lookup in TLSH sections through the `0x7400` cell index
//! (`TlshCellLookup`, C++ `TlshLookupStrategy` in `tlsh_ls.h`): answers
//! agree with the linear-scan `NaiveSet`, duplicates included.
//!
//! Expected cell tables come from the testkit's counting
//! `naive_cell_index`, written out little endian here, not from
//! `hset::tlsh::cells`.

use hset::format::Hint;
use hset::lookup::{Lookup, make_lookup};
use hset_testkit::oracle::NaiveSet;
use hset_testkit::tlsh::{corpus, naive_cell_index, sorted_rows};

/// The `0x7400` table of sorted `rows`: 65,537 little-endian `u64`s.
fn table_of(rows: &[[u8; 36]]) -> Vec<u8> {
    naive_cell_index(rows)
        .iter()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

fn flat(rows: &[[u8; 36]]) -> Vec<u8> {
    rows.iter().flatten().copied().collect()
}

fn cell_lookup<'a>(data: &'a [u8], table: &'a [u8]) -> Box<dyn Lookup + 'a> {
    make_lookup(36, data, Some(&Hint::TlshCells { table })).expect("make_lookup")
}

#[test]
fn every_row_is_found_through_the_cell_index() {
    let rows = sorted_rows(&corpus(1, 500));
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    assert!(
        lk.describe().starts_with("tlsh cell index"),
        "{}",
        lk.describe()
    );
    assert_eq!(lk.len(), rows.len());
    assert_eq!(lk.hash_length(), 36);
    let naive = NaiveSet::from_bytes(&data, 36);
    for r in &rows {
        assert!(lk.contains(r));
        assert_eq!(lk.find(r), naive.find(r));
    }
}

/// `find`, `contains` and `equal_range` of `q` as the linear scan answers.
fn agrees_with_naive(lk: &dyn Lookup, naive: &NaiveSet, q: &[u8]) {
    assert_eq!(lk.find(q), naive.find(q), "find {q:02x?}");
    assert_eq!(lk.contains(q), naive.contains(q), "contains {q:02x?}");
    assert_eq!(
        lk.equal_range(q),
        naive.equal_range(q),
        "equal_range {q:02x?}"
    );
}

/// Records files keep one TLSH row per record, so equal rows repeat: `find`
/// is the first of them and `equal_range` all of them, as for every other
/// strategy. Runs of 1 to 5 copies sit at the start, middle and end of
/// cells and of the section.
#[test]
fn duplicate_rows_find_the_first_and_range_over_all() {
    let distinct = sorted_rows(&corpus(3, 300));
    let mut rows = Vec::new();
    for (i, r) in distinct.iter().enumerate() {
        for _ in 0..1 + i % 5 {
            rows.push(*r);
        }
    }
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    let naive = NaiveSet::from_bytes(&data, 36);
    for (i, r) in distinct.iter().enumerate() {
        agrees_with_naive(lk.as_ref(), &naive, r);
        assert_eq!(lk.equal_range(r).len(), 1 + i % 5);
    }
}

/// Near misses of a stored row, each in a way the cell index must not
/// hide: a low-plane bit (same cell), the checksum (same cell, last byte
/// compared), L (another cell) and the reserved byte.
fn perturbations(r: &[u8; 36]) -> [[u8; 36]; 4] {
    let mut lo_bit = *r;
    lo_bit[18 + 5] ^= 0x10;
    let mut checksum = *r;
    checksum[34] ^= 0x80;
    let mut l = *r;
    l[0] ^= 1;
    let mut reserved = *r;
    reserved[35] ^= 1;
    [lo_bit, checksum, l, reserved]
}

/// `contains_batch` answers every query as `contains` does, over stored
/// rows and near misses, for batch sizes 0 to 9 and the whole list.
#[test]
fn batch_answers_equal_single_answers() {
    let rows = sorted_rows(&corpus(4, 300));
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    let queries: Vec<[u8; 36]> = rows
        .iter()
        .step_by(3)
        .flat_map(|r| std::iter::once(*r).chain(perturbations(r)))
        .collect();
    let want: Vec<bool> = queries.iter().map(|q| lk.contains(q)).collect();
    assert!(want.contains(&true) && want.contains(&false));
    let bytes = flat(&queries);
    for m in (0..10).chain([queries.len()]) {
        // Start from the wrong answers, so an entry left alone fails.
        let mut out: Vec<bool> = want[..m].iter().map(|w| !w).collect();
        lk.contains_batch(&bytes[..36 * m], &mut out);
        assert_eq!(out, want[..m], "batch of {m}");
    }
}

/// The window is the query's cell: exactly the rows sharing its first two
/// bytes, so every stored row lies inside its own window.
#[test]
fn the_window_is_the_rows_of_the_querys_cell() {
    let rows = sorted_rows(&corpus(2, 400));
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    for (i, r) in rows.iter().enumerate() {
        let w = lk.window(r);
        assert!(w.contains(&i), "row {i} outside {w:?}");
        let first = rows.iter().position(|s| s[..2] == r[..2]).unwrap();
        let last = rows.iter().rposition(|s| s[..2] == r[..2]).unwrap();
        assert_eq!(w, first..last + 1, "row {i}");
    }
    // A query in an empty cell has an empty window.
    let mut q = rows[0];
    while rows.iter().any(|r| r[..2] == q[..2]) {
        q[1] = q[1].wrapping_add(1);
    }
    assert!(lk.window(&q).is_empty());
}
