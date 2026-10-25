//! Row and record merges: the building blocks of merge-based set operations.
//!
//! A set operation on two hash sets is a two-pointer merge of their sorted
//! sections. Each merge reports, for every input row (or record), the row it
//! becomes in the output, or [`DROPPED`] ([`RECORD_DROPPED`] for records).
//! The derived structures of a section (its `RIDX` record index, a TLSH
//! `TIVF` index) are carried through the merge by those maps.

use std::cmp::Ordering;

use crate::error::{Error, Result};
use crate::format::{FieldDescriptor, RecordHeader};
use crate::ops::SetOp;

/// The output fields of merging two record tables: the left fields followed
/// by the right fields the left lacks (fields are matched by type). A field
/// with different lengths on the two sides is an error.
pub fn merged_record_fields(
    left: &RecordHeader,
    right: &RecordHeader,
) -> Result<Vec<FieldDescriptor>> {
    let mut fields = left.fields.clone();
    for f in &right.fields {
        match fields.iter().find(|o| o.htype == f.htype) {
            None => fields.push(f.clone()),
            Some(o) if o.length != f.length => {
                return Err(Error::input(format!(
                    "field {} has length {} on the left and {} on the right",
                    f.name, o.length, f.length
                )));
            }
            Some(_) => {}
        }
    }
    Ok(fields)
}

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

impl RowMerge {
    /// The output rows (an `HDAT` payload): every emitted input row of the
    /// merged `left` and `right` at its output position.
    pub fn gather_rows(&self, left: &[u8], right: &[u8], len: usize) -> Result<Vec<u8>> {
        let (l, r) = (
            Rows::new(left, len, "left")?,
            Rows::new(right, len, "right")?,
        );
        let mut out = vec![0u8; self.out_len(len)?];
        self.scatter(l.n, r.n, |from_left, i, k| {
            let src = if from_left { l.get(i) } else { r.get(i) };
            out[k * len..(k + 1) * len].copy_from_slice(src);
            Ok(())
        })?;
        Ok(out)
    }

    /// The output record index (an `RIDX` payload): for every output row, the
    /// output record of the record owning its input row.
    pub fn gather_ridx(&self, left: RowOwners<'_>, right: RowOwners<'_>) -> Result<Vec<u8>> {
        let lrecs = left.output_records(self.lmap.len(), "left")?;
        let rrecs = right.output_records(self.rmap.len(), "right")?;
        let mut out = vec![0u8; self.out_len(8)?];
        self.scatter(lrecs.len(), rrecs.len(), |from_left, i, k| {
            let rec = if from_left { lrecs[i] } else { rrecs[i] };
            if rec == RECORD_DROPPED {
                return Err(Error::input(format!(
                    "output row {k} comes from a dropped record"
                )));
            }
            out[k * 8..k * 8 + 8].copy_from_slice(&rec.to_le_bytes());
            Ok(())
        })?;
        Ok(out)
    }

    /// Bytes of `n` output rows of `len` bytes.
    fn out_len(&self, len: usize) -> Result<usize> {
        usize::try_from(self.n)
            .ok()
            .and_then(|n| n.checked_mul(len))
            .ok_or_else(|| Error::input("merged rows do not fit in memory"))
    }

    /// Calls `put(from_left, input row, output row)` for every emitted row, after
    /// checking that the sides have `ln` and `rn` rows.
    fn scatter(
        &self,
        ln: usize,
        rn: usize,
        mut put: impl FnMut(bool, usize, usize) -> Result<()>,
    ) -> Result<()> {
        if ln != self.lmap.len() || rn != self.rmap.len() {
            return Err(Error::input(format!(
                "the merge has {} left and {} right rows, not {ln} and {rn}",
                self.lmap.len(),
                self.rmap.len()
            )));
        }
        let sides = [(&self.lmap, true), (&self.rmap, false)];
        for (map, from_left) in sides {
            for (i, &k) in map.iter().enumerate() {
                if k == DROPPED {
                    continue;
                }
                if u64::from(k) >= self.n {
                    return Err(Error::input(format!(
                        "output row {k} is past the {} merged rows",
                        self.n
                    )));
                }
                put(from_left, i, k as usize)?;
            }
        }
        Ok(())
    }
}

/// Merges two sorted runs of `len`-byte rows (`left` and `right` hold the
/// rows back to back). Output row `k` is the input row mapped to `k`.
pub fn merge_rows(left: &[u8], right: &[u8], len: usize, mode: RowMode<'_>) -> Result<RowMerge> {
    let (l, r) = (
        Rows::new(left, len, "left")?,
        Rows::new(right, len, "right")?,
    );
    let mut m = RowMerge {
        n: 0,
        lmap: vec![DROPPED; l.n],
        rmap: vec![DROPPED; r.n],
    };
    match mode {
        RowMode::Set(op) => merge_sets(op, l, r, &mut m)?,
        RowMode::Records {
            left,
            right,
            collapse_equal,
        } => {
            let lkept = left.kept(l.n, "left")?;
            let rkept = right.kept(r.n, "right")?;
            merge_owned(l, &lkept, r, &rkept, collapse_equal, &mut m)?;
        }
    }
    Ok(m)
}

impl RowOwners<'_> {
    /// Whether each of the side's `n` rows belongs to an emitted record.
    fn kept(&self, n: usize, side: &str) -> Result<Vec<bool>> {
        let recs = self.output_records(n, side)?;
        Ok(recs.into_iter().map(|r| r != RECORD_DROPPED).collect())
    }

    /// The output record of each of the side's `n` rows, or [`RECORD_DROPPED`].
    fn output_records(&self, n: usize, side: &str) -> Result<Vec<u64>> {
        if self.ridx.len() / 8 != n || self.ridx.len() % 8 != 0 {
            return Err(Error::input(format!(
                "the {side} record index has {} bytes for {n} rows",
                self.ridx.len()
            )));
        }
        self.ridx
            .chunks_exact(8)
            .enumerate()
            .map(|(k, b)| {
                let rec = u64::from_le_bytes(b.try_into().expect("8-byte chunk"));
                usize::try_from(rec)
                    .ok()
                    .and_then(|rec| self.recmap.get(rec).copied())
                    .ok_or_else(|| {
                        Error::format(format!(
                            "{side} row {k} names record {rec}, but there are {} records",
                            self.recmap.len()
                        ))
                    })
            })
            .collect()
    }
}

/// Fixed-length rows stored back to back.
#[derive(Clone, Copy)]
struct Rows<'a> {
    data: &'a [u8],
    len: usize,
    n: usize,
}

impl<'a> Rows<'a> {
    fn new(data: &'a [u8], len: usize, side: &str) -> Result<Self> {
        if len == 0 {
            return Err(Error::input("zero-length rows"));
        }
        if data.len() % len != 0 {
            return Err(Error::input(format!(
                "the {side} rows have {} bytes, not a multiple of the row length {len}",
                data.len()
            )));
        }
        Ok(Rows {
            data,
            len,
            n: data.len() / len,
        })
    }

    fn get(&self, i: usize) -> &'a [u8] {
        &self.data[i * self.len..(i + 1) * self.len]
    }

    /// The index after the run of rows equal to row `k`.
    fn skip_run(&self, k: usize) -> usize {
        let v = self.get(k);
        let mut k = k + 1;
        while k < self.n && self.get(k) == v {
            k += 1;
        }
        k
    }
}

/// Order of the next left row against the next right row, an exhausted side
/// sorting last.
fn next_order(l: &Rows<'_>, i: usize, r: &Rows<'_>, j: usize) -> Ordering {
    if i < l.n && j < r.n {
        l.get(i).cmp(r.get(j))
    } else if i < l.n {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// An input row of one side.
#[derive(Clone, Copy)]
enum Side {
    Left(usize),
    Right(usize),
}

/// Maps `row` to the next output row.
fn emit(m: &mut RowMerge, row: Side) -> Result<()> {
    // C++ refuses once the count reaches MERGE_DROPPED: the last row index
    // is DROPPED - 2
    let k = u32::try_from(m.n)
        .ok()
        .filter(|&k| k < DROPPED - 1)
        .ok_or_else(|| Error::input("too many rows in merged hashset"))?;
    match row {
        Side::Left(i) => m.lmap[i] = k,
        Side::Right(j) => m.rmap[j] = k,
    }
    m.n += 1;
    Ok(())
}

fn merge_owned(
    l: Rows<'_>,
    lkept: &[bool],
    r: Rows<'_>,
    rkept: &[bool],
    collapse_equal: bool,
    m: &mut RowMerge,
) -> Result<()> {
    let (mut i, mut j) = (0, 0);
    let mut last: Option<&[u8]> = None; // the previous emitted row
    loop {
        while i < l.n && !lkept[i] {
            i += 1;
        }
        while j < r.n && !rkept[j] {
            j += 1;
        }
        if i == l.n && j == r.n {
            return Ok(());
        }
        // ties go left
        let (row, next) = if next_order(&l, i, &r, j) != Ordering::Greater {
            i += 1;
            (l.get(i - 1), Side::Left(i - 1))
        } else {
            j += 1;
            (r.get(j - 1), Side::Right(j - 1))
        };
        if collapse_equal && last == Some(row) {
            continue;
        }
        last = Some(row);
        emit(m, next)?;
    }
}

fn merge_sets(op: SetOp, l: Rows<'_>, r: Rows<'_>, m: &mut RowMerge) -> Result<()> {
    let emit_left_only = op != SetOp::Intersect;
    let emit_right_only = op == SetOp::Union;
    let emit_both = op != SetOp::Subtract;
    let (mut i, mut j) = (0, 0);
    while i < l.n || j < r.n {
        match next_order(&l, i, &r, j) {
            Ordering::Less => {
                if emit_left_only {
                    emit(m, Side::Left(i))?;
                }
                i = l.skip_run(i);
            }
            Ordering::Greater => {
                if emit_right_only {
                    emit(m, Side::Right(j))?;
                }
                j = r.skip_run(j);
            }
            Ordering::Equal => {
                if emit_both {
                    emit(m, Side::Left(i))?;
                }
                i = l.skip_run(i);
                j = r.skip_run(j);
            }
        }
    }
    Ok(())
}
