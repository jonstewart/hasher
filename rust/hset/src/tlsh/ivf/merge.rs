//! Carrying TIVF lists through a merge, and coalescing small lists
//! (`merge_tlsh_ivf`, `coalesce_cell`).

use super::{DROPPED, IvfIndex, TlshIvf};
use crate::error::{Error, Result};
use crate::tlsh::CELL_COUNT;
use crate::tlsh::digest::{DIGEST_LENGTH, TlshDigest};
use crate::tlsh::distance::BodyQuery;

/// Stub.
pub fn merge_tlsh_ivf<A: IvfIndex + ?Sized, B: IvfIndex + ?Sized>(
    a: Option<(&A, &[u32])>,
    b: Option<(&B, &[u32])>,
    rows: &[[u8; DIGEST_LENGTH]],
    coalesce_threshold: u32,
) -> Result<TlshIvf> {
    let n_out = u32::try_from(rows.len())
        .map_err(|_| Error::input("too many rows for a TIVF index"))?;
    let _ = coalesce_threshold;
    if let Some((index, map)) = a {
        check_side(index, map, "left")?;
    }
    if let Some((index, map)) = b {
        check_side(index, map, "right")?;
    }

    let mut out = TlshIvf::empty();
    out.n = u64::from(n_out);
    out.ids.reserve(rows.len());

    let mut cell = Vec::new();
    for c in 0..CELL_COUNT {
        out.cell_lists[c] = out.lists() as u32;
        cell.clear();
        if let Some((index, map)) = a {
            gather(index, map, c, rows, &mut cell)?;
        }
        if let Some((index, map)) = b {
            gather(index, map, c, rows, &mut cell)?;
        }
        for m in cell.drain(..) {
            out.medoids.push(m.medoid);
            out.radius2.push(m.radius2);
            out.ids.extend_from_slice(&m.ids);
            out.list_start.push(out.ids.len() as u64);
        }
    }
    out.cell_lists[CELL_COUNT] = out.lists() as u32;

    if out.ids.len() != rows.len() {
        return Err(Error::input(format!(
            "merged TIVF index has {} ids, expected {}",
            out.ids.len(),
            rows.len()
        )));
    }
    Ok(out)
}

/// The array lengths of one side's index, and its map's length.
fn check_side<I: IvfIndex + ?Sized>(index: &I, map: &[u32], side: &str) -> Result<()> {
    index.check_layout()?;
    if map.len() as u64 != index.n() {
        return Err(Error::input(format!(
            "the {side} row map has {} entries, the {side} index {} rows",
            map.len(),
            index.n()
        )));
    }
    Ok(())
}

/// A list of one cell while it is merged (C++ `MergeList`).
struct MergeList {
    medoid: TlshDigest,
    radius2: u32,
    /// Output rows, ascending.
    ids: Vec<u32>,
}

/// Appends the lists of cell `c` of one input to `cell`, ids mapped
/// through `map`; a list that lost members gets its radius recomputed.
fn gather<I: IvfIndex + ?Sized>(
    index: &I,
    map: &[u32],
    c: usize,
    rows: &[[u8; DIGEST_LENGTH]],
    cell: &mut Vec<MergeList>,
) -> Result<()> {
    for l in index.cell_range(c) {
        let mut m = MergeList {
            medoid: index.medoid(l),
            radius2: index.radius2(l),
            ids: Vec::new(),
        };
        let mut shrunk = false;
        for id in index.list_ids(l) {
            let Some(&out) = map.get(id as usize) else {
                return Err(Error::format(format!(
                    "TIVF list {l} has id {id} out of range for {} rows",
                    map.len()
                )));
            };
            if out == DROPPED {
                shrunk = true;
                continue;
            }
            if out as usize >= rows.len() {
                return Err(Error::input(format!(
                    "row map sends row {id} to {out}, past the {} merged rows",
                    rows.len()
                )));
            }
            if m.ids.last().is_some_and(|&last| out <= last) {
                return Err(Error::input("row map is not increasing within a TIVF list"));
            }
            m.ids.push(out);
        }
        if m.ids.is_empty() {
            continue;
        }
        if shrunk {
            m.radius2 = radius_about(&m.medoid, &m.ids, rows);
        }
        cell.push(m);
    }
    Ok(())
}

/// Exact squared body-embedding radius about `m` over the rows `ids`.
fn radius_about(m: &TlshDigest, ids: &[u32], rows: &[[u8; DIGEST_LENGTH]]) -> u32 {
    let q = BodyQuery::new(m);
    ids.iter()
        .map(|&id| q.emb_body(&rows[id as usize]))
        .max()
        .unwrap_or(0)
}
