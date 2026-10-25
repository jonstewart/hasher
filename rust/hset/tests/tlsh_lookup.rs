//! Exact lookup in TLSH sections through the `0x7400` cell index
//! (`TlshCellLookup`, C++ `TlshLookupStrategy` in `tlsh_ls.h`): answers
//! agree with the linear-scan `NaiveSet`, duplicates included.
//!
//! Expected cell tables come from the testkit's counting
//! `naive_cell_index`, written out little endian here, not from
//! `hset::tlsh::cells`.

use hset::Error;
use hset::format::Hint;
use hset::lookup::{Lookup, hint_from_parts, make_lookup};
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

/// Every near miss of a stored row that is not itself stored is absent,
/// with an empty `equal_range`, exactly as the linear scan says.
#[test]
fn near_misses_are_absent() {
    let rows = sorted_rows(&corpus(5, 400));
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    let naive = NaiveSet::from_bytes(&data, 36);
    let mut absent = 0;
    for r in &rows {
        for q in perturbations(r) {
            agrees_with_naive(lk.as_ref(), &naive, &q);
            if !naive.contains(&q) {
                absent += 1;
                assert!(!lk.contains(&q), "{q:02x?}");
                assert_eq!(lk.equal_range(&q), 0..0);
            }
        }
    }
    // Nearly all near misses are absent from a random corpus.
    assert!(absent > 3 * rows.len(), "{absent}");
}

/// The null digest is not a row of a section that does not store it, even
/// when its cell, 0x0000, holds rows; the first and last cells work.
#[test]
fn the_null_digest_is_absent_and_the_end_cells_work() {
    let mut rows = sorted_rows(&corpus(6, 50));
    let mut first = [0u8; 36];
    first[34] = 1; // cell 0x0000, checksum 1
    let mut second = [0u8; 36];
    second[2] = 0x80; // cell 0x0000, one high-plane bit
    let mut last = [0xffu8; 36];
    last[35] = 0; // cell 0xFFFF
    rows.extend([first, second, last, last]);
    rows.sort_unstable();
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    let null = [0u8; 36];
    assert!(!lk.contains(&null));
    assert_eq!(lk.find(&null), None);
    assert_eq!(lk.equal_range(&null), 0..0);
    assert_eq!(lk.window(&null), 0..2);
    assert_eq!(lk.find(&first), Some(0));
    assert_eq!(lk.find(&second), Some(1));
    let n = rows.len();
    assert_eq!(lk.find(&last), Some(n - 2));
    assert_eq!(lk.equal_range(&last), n - 2..n);
    let mut after = last;
    after[35] = 1;
    assert!(!lk.contains(&after));
}

/// An empty section has an all-zero cell index; every cell is empty.
#[test]
fn an_empty_section_contains_nothing() {
    let table = table_of(&[]);
    let lk = cell_lookup(&[], &table);
    assert!(lk.is_empty());
    for q in [[0u8; 36], [0xff; 36], {
        let mut q = [0x55u8; 36];
        q[35] = 0;
        q
    }] {
        assert!(!lk.contains(&q));
        assert_eq!(lk.find(&q), None);
        assert_eq!(lk.equal_range(&q), 0..0);
        assert!(lk.window(&q).is_empty());
    }
    let mut out = [true; 3];
    lk.contains_batch(&[0u8; 108], &mut out);
    assert_eq!(out, [false; 3]);
}

/// A query longer than a row is answered by its first 36 bytes, as the
/// other strategies answer it.
#[test]
fn a_longer_query_is_answered_by_its_prefix() {
    let rows = sorted_rows(&corpus(7, 100));
    let data = flat(&rows);
    let table = table_of(&rows);
    let lk = cell_lookup(&data, &table);
    for (i, r) in rows.iter().enumerate() {
        let long = [&r[..], &[0xAA; 5]].concat();
        assert!(lk.contains(&long));
        assert_eq!(lk.find(&long), lk.find(r));
        assert_eq!(lk.equal_range(&long), lk.equal_range(r));
        assert!(lk.window(&long).contains(&i));
    }
}

fn make_err(hash_length: usize, data: &[u8], table: &[u8]) -> String {
    match make_lookup(hash_length, data, Some(&Hint::TlshCells { table })) {
        Err(e @ Error::Format(_)) => e.to_string(),
        Err(e) => panic!("expected a format error, got {e}"),
        Ok(lk) => panic!("expected an error, got {}", lk.describe()),
    }
}

/// A cell index that does not describe the rows fails the lookup's
/// construction, as the C++ strategy's constructor throws: wrong length,
/// first offset not 0, last offset not the row count, decreasing offsets.
#[test]
fn a_bad_cell_index_fails_construction() {
    let rows = sorted_rows(&corpus(8, 40));
    let data = flat(&rows);
    let good = table_of(&rows);

    let e = make_err(36, &data, &good[..good.len() - 8]);
    assert!(e.contains("bad TLSH cell index"), "{e}");
    let mut long = good.clone();
    long.extend_from_slice(&40u64.to_le_bytes());
    assert!(make_err(36, &data, &long).contains("length"));

    let mut first = good.clone();
    first[0] = 1;
    assert!(make_err(36, &data, &first).contains("first offset is 1"));

    let e = make_err(36, &data[..36 * 39], &good);
    assert!(e.contains("last offset is 40, expected 39"), "{e}");

    // Move the start of the first row's cell past the next cell's start.
    let c = usize::from(rows[0][0]) << 8 | usize::from(rows[0][1]);
    let mut dec = good.clone();
    dec[8 * (c + 1)..8 * (c + 2)].copy_from_slice(&41u64.to_le_bytes());
    assert!(make_err(36, &data, &dec).contains("decrease"));
}

/// The cell index belongs to 36-byte TLSH rows only.
#[test]
fn a_cell_index_on_other_hash_lengths_is_rejected() {
    let table = table_of(&[]);
    for hlen in [16, 20, 32, 35, 37] {
        let e = make_err(hlen, &[], &table);
        assert!(e.contains("36-byte"), "{hlen}: {e}");
    }
}

/// `hint_from_parts` recognises the cell index by its tag and table
/// length; a table of another length stays unknown, so the section falls
/// back to a plain search instead of failing.
#[test]
fn hint_from_parts_maps_0x7400_to_the_cell_index() {
    let rows = sorted_rows(&corpus(9, 60));
    let data = flat(&rows);
    let table = table_of(&rows);
    let h = hint_from_parts(0x7400, &table);
    assert!(
        matches!(h, Hint::TlshCells { table: t } if t == &table[..]),
        "{}",
        h.describe()
    );
    let lk = make_lookup(36, &data, Some(&h)).unwrap();
    assert!(lk.describe().starts_with("tlsh cell index"));
    // The lookup holds its own copy of the 65,537 offsets.
    assert_eq!(lk.table_bytes(), 65537 * size_of::<usize>());

    let short = &table[..table.len() - 8];
    for (tag, t) in [(0x7400, short), (0x7401, &table[..])] {
        let h = hint_from_parts(tag, t);
        assert!(
            matches!(h, Hint::Unknown { tag: g, data } if g == tag && data == t),
            "{tag:#06x}: {}",
            h.describe()
        );
    }
}
