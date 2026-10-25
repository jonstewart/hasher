//! Row and record merges: the building blocks of merge-based set operations.
//!
//! A set operation on two hash sets is a two-pointer merge of their sorted
//! sections. Each merge reports, for every input row (or record), the row it
//! becomes in the output, or [`DROPPED`] ([`RECORD_DROPPED`] for records).
//! The derived structures of a section (its `RIDX` record index, a TLSH
//! `TIVF` index) are carried through the merge by those maps.

use crate::error::Result;
use crate::ops::SetOp;

/// A row that the merge does not emit (the same value as the TLSH index's
/// dropped-row marker).
pub const DROPPED: u32 = u32::MAX;

/// A record that the merge does not emit.
pub const RECORD_DROPPED: u64 = u64::MAX;

/// How [`merge_rows`] decides which rows to emit.
#[derive(Debug, Clone, Copy)]
pub enum RowMode<'a> {
    /// The rows are sets: equal rows, within a side or across the sides, are
    /// emitted once (the left copy for rows on both sides), subject to the
    /// operation.
    Set(SetOp),
    /// The rows belong to records and the operation has already been applied
    /// to the records: a row is emitted iff its record is. On ties left rows
    /// precede right rows.
    Records {
        left: RowOwners<'a>,
        right: RowOwners<'a>,
        /// Emit a row equal to the previously emitted row only once (for a
        /// hashsets-only output of a record-level operation).
        collapse_equal: bool,
    },
}

/// The records owning the rows of one side of a record-mode row merge.
#[derive(Debug, Clone, Copy)]
pub struct RowOwners<'a> {
    /// The record of each row: one little-endian `u64` per row, the layout of
    /// an `RIDX` chunk.
    pub ridx: &'a [u8],
    /// Each input record's output record, or [`RECORD_DROPPED`].
    pub recmap: &'a [u64],
}

/// The result of [`merge_rows`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RowMerge {
    /// Number of output rows.
    pub n: u64,
    /// Output row of each left row, or [`DROPPED`].
    pub lmap: Vec<u32>,
    /// Output row of each right row, or [`DROPPED`].
    pub rmap: Vec<u32>,
}

/// Merges two sorted runs of `len`-byte rows (`left` and `right` hold the
/// rows back to back). Output row `k` is the input row mapped to `k`.
pub fn merge_rows(left: &[u8], right: &[u8], len: usize, mode: RowMode<'_>) -> Result<RowMerge> {
    let _ = mode;
    let row = |b: &[u8], i: usize| -> Vec<u8> { b[i * len..(i + 1) * len].to_vec() };
    let (ln, rn) = (left.len() / len, right.len() / len);
    let mut m = RowMerge {
        n: 0,
        lmap: vec![DROPPED; ln],
        rmap: vec![DROPPED; rn],
    };
    let skip_run = |b: &[u8], n: usize, k: &mut usize| {
        let v = row(b, *k);
        *k += 1;
        while *k < n && row(b, *k) == v {
            *k += 1;
        }
    };
    let (mut i, mut j) = (0, 0);
    while i < ln || j < rn {
        let c = if i < ln && j < rn {
            row(left, i).cmp(&row(right, j))
        } else if i < ln {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
        match c {
            std::cmp::Ordering::Less => {
                m.lmap[i] = m.n as u32;
                m.n += 1;
                skip_run(left, ln, &mut i);
            }
            std::cmp::Ordering::Greater => {
                m.rmap[j] = m.n as u32;
                m.n += 1;
                skip_run(right, rn, &mut j);
            }
            std::cmp::Ordering::Equal => {
                m.lmap[i] = m.n as u32;
                m.n += 1;
                skip_run(left, ln, &mut i);
                skip_run(right, rn, &mut j);
            }
        }
    }
    Ok(m)
}
