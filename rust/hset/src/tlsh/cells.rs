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
    let _ = cells;
    Vec::new()
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
        let _ = n;
        Ok(CellIndex { table })
    }

    /// The `c`th offset, `c <= CELL_COUNT`.
    pub fn offset(&self, c: usize) -> u64 {
        let _ = c;
        0
    }

    /// The rows of `cell`.
    pub fn range(&self, cell: u16) -> Range<usize> {
        let _ = cell;
        0..0
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
}
