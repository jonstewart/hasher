//! Exact lookup in a TLSH section through its `0x7400` cell index
//! (`include/hashset/tlsh_ls.h`).
//!
//! The rows of a TLSH section are sorted bytewise, so the rows of one cell
//! `(L << 8) | Q` (a row's first two bytes) are a contiguous run, and the
//! cell index says where each run starts. A lookup reads the query's cell
//! range from the index and binary-searches only that run.

use std::ops::Range;

use super::Lookup;
use crate::error::Result;
use crate::tlsh::DIGEST_LENGTH;
use crate::tlsh::cells::{CELL_INDEX_LEN, CellIndex};

/// [`Lookup`] over sorted 36-byte TLSH rows using a validated cell index.
///
/// The offsets are copied out of the hint table (as C++ copies an
/// unaligned table), so the lookup borrows only the rows.
#[derive(Debug, Clone)]
pub struct TlshCellLookup<'a> {
    rows: &'a [[u8; DIGEST_LENGTH]],
    /// [`CELL_INDEX_LEN`] row offsets: cell `c` is `cells[c]..cells[c + 1]`.
    cells: Box<[usize]>,
}

impl<'a> TlshCellLookup<'a> {
    /// A lookup over `data`, sorted 36-byte rows, with the `0x7400` hint
    /// `table`. A table that is not a valid cell index of `data`'s row
    /// count ([`CellIndex::parse`]) is an [`crate::Error::Format`]; `data`
    /// must be a whole number of rows.
    pub fn new(data: &'a [u8], table: &[u8]) -> Result<Self> {
        let (rows, rest) = data.as_chunks::<DIGEST_LENGTH>();
        assert!(rest.is_empty(), "TLSH data is not a whole number of rows");
        let ix = CellIndex::parse(table, rows.len())?;
        // Every offset is at most the row count, so it fits in usize.
        let cells = (0..CELL_INDEX_LEN).map(|c| ix.offset(c) as usize).collect();
        Ok(TlshCellLookup { rows, cells })
    }

    /// The first [`DIGEST_LENGTH`] bytes of `hash`, which must have at
    /// least that many.
    fn key(hash: &[u8]) -> &[u8; DIGEST_LENGTH] {
        hash[..DIGEST_LENGTH]
            .try_into()
            .expect("a slice of DIGEST_LENGTH bytes")
    }

    /// The rows of `key`'s cell, as indices.
    fn cell_range(&self, key: &[u8; DIGEST_LENGTH]) -> Range<usize> {
        let c = usize::from(u16::from_be_bytes([key[0], key[1]]));
        self.cells[c]..self.cells[c + 1]
    }

    /// The first index in `key`'s cell whose row is not below `key`.
    fn lower_bound(&self, key: &[u8; DIGEST_LENGTH]) -> usize {
        let cell = self.cell_range(key);
        cell.start + self.rows[cell].partition_point(|r| r < key)
    }
}

impl Lookup for TlshCellLookup<'_> {
    fn hash_length(&self) -> usize {
        DIGEST_LENGTH
    }

    fn len(&self) -> usize {
        self.rows.len()
    }

    fn contains(&self, hash: &[u8]) -> bool {
        self.find(hash).is_some()
    }

    fn find(&self, hash: &[u8]) -> Option<usize> {
        let key = Self::key(hash);
        let i = self.lower_bound(key);
        (self.rows.get(i) == Some(key)).then_some(i)
    }

    /// All rows equal to `hash`, or `0..0` when there is none (as the other
    /// strategies answer).
    fn equal_range(&self, hash: &[u8]) -> Range<usize> {
        let key = Self::key(hash);
        let cell = self.cell_range(key);
        let rows = &self.rows[cell.clone()];
        let lo = rows.partition_point(|r| r < key);
        let hi = lo + rows[lo..].partition_point(|r| r == key);
        if lo == hi {
            0..0
        } else {
            cell.start + lo..cell.start + hi
        }
    }

    fn contains_batch(&self, hashes: &[u8], out: &mut [bool]) {
        assert_eq!(hashes.len(), out.len() * DIGEST_LENGTH);
        let (queries, _) = hashes.as_chunks::<DIGEST_LENGTH>();
        for (o, q) in out.iter_mut().zip(queries) {
            *o = self.contains(q);
        }
    }

    /// The rows of `hash`'s cell.
    fn window(&self, hash: &[u8]) -> Range<usize> {
        self.cell_range(Self::key(hash))
    }

    fn describe(&self) -> String {
        format!("tlsh cell index ({DIGEST_LENGTH}-byte rows, binary search within the cell)")
    }

    fn table_bytes(&self) -> usize {
        0
    }
}
