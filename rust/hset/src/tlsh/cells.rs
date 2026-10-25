//! Cells: the (L, Q) prefix of a TLSH row, and the 65,537-entry prefix-sum
//! cell index stored in the `0x7400` HINT (`tlsh_cells.cpp`, `tlsh_ls.h`).
//!
//! TLSH rows in a section are sorted bytewise, which for the canonical
//! layout is (L, Q, body, checksum) order, so the rows of one cell
//! `(L << 8) | Q` are a contiguous run. The cell index records where each run
//! starts: the rows of cell `c` are `cells[c]..cells[c + 1]`, with
//! `cells[0] == 0` and `cells[65536] == n`.

use std::ops::Range;

use super::CELL_COUNT;
use super::digest::DIGEST_LENGTH;
use crate::error::{Error, Result};

/// Entries in a cell index: one start offset per cell, plus the row count.
pub const CELL_INDEX_LEN: usize = CELL_COUNT + 1;

/// Bytes of the `0x7400` HINT table after its tag: [`CELL_INDEX_LEN`]
/// little-endian `u64` offsets.
pub const CELL_TABLE_LEN: usize = CELL_INDEX_LEN * 8;

/// The cell of a canonical row: its first two bytes, `(L << 8) | Q`.
fn cell_of(row: &[u8; DIGEST_LENGTH]) -> usize {
    usize::from(u16::from_be_bytes([row[0], row[1]]))
}

/// The cell index of sorted `rows` (`make_tlsh_cell_index`): [`CELL_INDEX_LEN`]
/// start offsets. Equal rows are allowed; rows out of bytewise order are an
/// [`Error::Input`].
pub fn cell_index(rows: &[[u8; DIGEST_LENGTH]]) -> Result<Vec<u64>> {
    if let Some(i) = rows.windows(2).position(|w| w[0] > w[1]) {
        return Err(Error::input(format!(
            "TLSH rows are not sorted: row {} sorts before row {i}",
            i + 1
        )));
    }
    // Count the rows of each cell one slot up, then a prefix sum turns the
    // counts into start offsets.
    let mut cells = vec![0u64; CELL_INDEX_LEN];
    for r in rows {
        cells[cell_of(r) + 1] += 1;
    }
    for c in 1..CELL_INDEX_LEN {
        cells[c] += cells[c - 1];
    }
    Ok(cells)
}

/// The `0x7400` HINT table for `cells`: each offset as a little-endian `u64`
/// (`write_tlsh_hint_data`, without the tag).
pub fn cell_table(cells: &[u64]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// A validated cell index borrowed from a HINT table. The table need not be
/// aligned; offsets are read with `from_le_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellIndex<'a> {
    table: &'a [u8],
}

impl<'a> CellIndex<'a> {
    /// Check `table` as the cell index of a section of `n` rows, as the C++
    /// `TlshLookupStrategy` does at load: [`CELL_TABLE_LEN`] bytes, first
    /// offset 0, last offset `n`, offsets non-decreasing. Any violation is an
    /// [`Error::Format`].
    pub fn parse(table: &'a [u8], n: usize) -> Result<Self> {
        if table.len() != CELL_TABLE_LEN {
            return Err(Error::format(format!(
                "bad TLSH cell index: table length is {} bytes, expected {CELL_TABLE_LEN}",
                table.len()
            )));
        }
        let ix = CellIndex { table };
        let first = ix.offset(0);
        if first != 0 {
            return Err(Error::format(format!(
                "bad TLSH cell index: first offset is {first}"
            )));
        }
        let last = ix.offset(CELL_COUNT);
        if last != n as u64 {
            return Err(Error::format(format!(
                "bad TLSH cell index: last offset is {last}, expected {n}"
            )));
        }
        if let Some(c) = (0..CELL_COUNT).find(|&c| ix.offset(c) > ix.offset(c + 1)) {
            return Err(Error::format(format!(
                "bad TLSH cell index: offsets decrease at cell {c}"
            )));
        }
        Ok(ix)
    }

    /// The `c`th offset, `c <= CELL_COUNT`.
    pub fn offset(&self, c: usize) -> u64 {
        let (entries, _) = self.table.as_chunks::<8>();
        u64::from_le_bytes(entries[c])
    }

    /// The rows of `cell`. The offsets are at most the row count, which
    /// fits in `usize`, so the conversions cannot truncate.
    pub fn range(&self, cell: u16) -> Range<usize> {
        let c = usize::from(cell);
        self.offset(c) as usize..self.offset(c + 1) as usize
    }

    /// The table bytes, [`CELL_TABLE_LEN`] of them.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(l: u8, q: u8, checksum: u8) -> [u8; DIGEST_LENGTH] {
        let mut r = [0u8; DIGEST_LENGTH];
        r[0] = l;
        r[1] = q;
        r[34] = checksum;
        r
    }

    /// test_hset_tlsh.cpp `make_tlsh_cell_index_small`: cells 0x0000,
    /// 0x0000, 0x0102, 0x0102, 0xFFFF.
    fn five_rows() -> Vec<[u8; DIGEST_LENGTH]> {
        vec![
            row(0, 0, 0),
            row(0, 0, 0),
            row(1, 2, 0),
            row(1, 2, 1),
            row(0xff, 0xff, 0),
        ]
    }

    #[test]
    fn empty_rows_have_all_zero_offsets() {
        let cells = cell_index(&[]).unwrap();
        assert_eq!(cells.len(), 65537);
        assert!(cells.iter().all(|&c| c == 0));
    }

    #[test]
    fn five_rows_index_as_in_the_reference_test() {
        let cells = cell_index(&five_rows()).unwrap();
        assert_eq!(cells.len(), 65537);
        assert_eq!(cells[0], 0);
        assert_eq!(cells[1], 2);
        assert_eq!(cells[0x0102], 2);
        assert_eq!(cells[0x0103], 4);
        assert_eq!(cells[0xFFFF], 4);
        assert_eq!(cells[0x10000], 5);
    }

    #[test]
    fn unsorted_rows_are_an_input_error() {
        let mut rows = five_rows();
        rows.swap(3, 4);
        let e = cell_index(&rows).unwrap_err();
        assert!(matches!(e, Error::Input(_)), "{e}");
        assert!(e.to_string().contains("not sorted"), "{e}");
        // The order is bytewise over the whole row, not only the cell.
        rows = five_rows();
        rows.swap(2, 3);
        assert!(cell_index(&rows).is_err());
    }

    /// test_hset_tlsh.cpp `write_tlsh_hint_data`: offsets `3i`, each a
    /// little-endian u64.
    #[test]
    fn cell_table_writes_each_offset_little_endian() {
        let cells: Vec<u64> = (0..65537u64).map(|i| i * 3).collect();
        let t = cell_table(&cells);
        assert_eq!(t.len(), 524296);
        assert_eq!(&t[..16], &[0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]);
        // 65536 * 3 = 0x3_0000
        assert_eq!(&t[524288..], &[0, 0, 3, 0, 0, 0, 0, 0]);
        for (i, e) in t.as_chunks::<8>().0.iter().enumerate() {
            assert_eq!(u64::from_le_bytes(*e), i as u64 * 3);
        }
    }

    fn five_row_table() -> Vec<u8> {
        cell_table(&cell_index(&five_rows()).unwrap())
    }

    #[test]
    fn a_parsed_index_gives_each_cell_its_rows() {
        let t = five_row_table();
        let ix = CellIndex::parse(&t, 5).unwrap();
        assert_eq!(ix.as_bytes(), &t[..]);
        assert_eq!(ix.offset(0), 0);
        assert_eq!(ix.offset(0x0103), 4);
        assert_eq!(ix.offset(CELL_COUNT), 5);
        assert_eq!(ix.range(0x0000), 0..2);
        assert_eq!(ix.range(0x0001), 2..2);
        assert_eq!(ix.range(0x0102), 2..4);
        assert_eq!(ix.range(0x8000), 4..4);
        assert_eq!(ix.range(0xFFFF), 4..5);
    }

    #[test]
    fn an_unaligned_table_parses() {
        let t = five_row_table();
        let mut buf = vec![0u8; 1];
        buf.extend_from_slice(&t);
        let ix = CellIndex::parse(&buf[1..], 5).unwrap();
        assert_eq!(ix.range(0x0102), 2..4);
    }

    fn parse_err(t: &[u8], n: usize) -> String {
        match CellIndex::parse(t, n) {
            Err(e @ Error::Format(_)) => e.to_string(),
            other => panic!("expected a format error, got {other:?}"),
        }
    }

    #[test]
    fn a_table_of_the_wrong_length_is_rejected() {
        let mut t = five_row_table();
        assert!(parse_err(&t[..t.len() - 1], 5).contains("length"));
        t.extend_from_slice(&5u64.to_le_bytes());
        assert!(parse_err(&t, 5).contains("length"));
        assert!(parse_err(&[], 0).contains("length"));
    }

    #[test]
    fn a_nonzero_first_offset_is_rejected() {
        let mut t = five_row_table();
        t[0] = 1;
        assert!(parse_err(&t, 5).contains("first offset is 1"));
    }

    #[test]
    fn a_last_offset_other_than_the_row_count_is_rejected() {
        let t = five_row_table();
        let e = parse_err(&t, 4);
        assert!(e.contains("last offset is 5, expected 4"), "{e}");
        assert!(parse_err(&t, 6).contains("expected 6"));
    }

    #[test]
    fn decreasing_offsets_are_rejected() {
        // cells[0x0103] = 5 is above cells[0x0104] = 4.
        let mut cells = cell_index(&five_rows()).unwrap();
        cells[0x0103] = 5;
        let e = parse_err(&cell_table(&cells), 5);
        assert!(e.contains("decrease at cell 259"), "{e}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// Sorted rows whose (L, Q) come from a few values, so cells repeat and
    /// neighbouring cells are both empty and full.
    fn rows() -> impl Strategy<Value = Vec<[u8; DIGEST_LENGTH]>> {
        vec(
            (
                prop::sample::select(vec![0u8, 1, 2, 0x7f, 0xff]),
                prop::sample::select(vec![0u8, 1, 0x10, 0xff]),
                any::<u8>(),
            ),
            0..=64,
        )
        .prop_map(|v| {
            let mut rows: Vec<_> = v
                .into_iter()
                .map(|(l, q, b)| {
                    let mut r = [0u8; DIGEST_LENGTH];
                    r[0] = l;
                    r[1] = q;
                    r[2] = b;
                    r
                })
                .collect();
            rows.sort_unstable();
            rows
        })
    }

    proptest! {
        // Each case builds and checks a 512 KiB table; 64 cases keep the
        // debug-build run near two seconds.
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        #[test]
        fn every_row_lies_in_its_cells_range(rows in rows()) {
            let table = cell_table(&cell_index(&rows).unwrap());
            let ix = CellIndex::parse(&table, rows.len()).unwrap();
            for (i, r) in rows.iter().enumerate() {
                let cell = u16::from_be_bytes([r[0], r[1]]);
                let range = ix.range(cell);
                prop_assert!(range.contains(&i), "row {} cell {:#06x} {:?}", i, cell, range);
                // The range holds exactly the rows of that cell.
                let count = rows.iter().filter(|s| s[..2] == r[..2]).count();
                prop_assert_eq!(range.len(), count);
            }
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::tlsh::TlshDigest;

    /// A row's cell is `(L << 8) | Q`, the same through the index builder's
    /// `cell_of` and [`TlshDigest::cell`], and it never decreases in the
    /// rows' bytewise order, so each cell's rows are one contiguous run.
    /// Rules out a byte-swapped (little-endian) cell, which scatters a
    /// cell's rows and makes the prefix-sum ranges wrong.
    #[kani::proof]
    #[kani::unwind(37)]
    fn cell_is_l_then_q_and_monotone_in_row_order() {
        let a: [u8; DIGEST_LENGTH] = kani::any();
        let b: [u8; DIGEST_LENGTH] = kani::any();
        let d = TlshDigest(a);
        let want = (usize::from(d.l()) << 8) | usize::from(d.q());
        assert!(cell_of(&a) == want);
        assert!(usize::from(d.cell()) == want);
        if a <= b {
            assert!(cell_of(&a) <= cell_of(&b));
        }
    }
}
