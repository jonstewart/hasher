//! Carrying TIVF lists through a merge, and coalescing small lists
//! (`merge_tlsh_ivf`, `coalesce_cell`).

use std::cmp::Reverse;
use std::collections::BinaryHeap;

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
    let n_out =
        u32::try_from(rows.len()).map_err(|_| Error::input("too many rows for a TIVF index"))?;
    let half = coalesce_threshold / 2;
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
        if half > 0 && cell.len() > 1 {
            coalesce_cell(&mut cell, rows, half);
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

/// Coalesces the lists of one cell in place (C++ `coalesce_cell`): while
/// two lists have fewer than `half` members each, the pair whose union has
/// the smallest exact radius about one of the two medoids becomes one list,
/// at the position of the earlier of the two. Emptied lists are removed;
/// the order of the rest is kept.
fn coalesce_cell(lists: &mut Vec<MergeList>, rows: &[[u8; DIGEST_LENGTH]], half: u32) {
    let small: Vec<usize> = (0..lists.len())
        .filter(|&i| lists[i].ids.len() < half as usize)
        .collect();
    let s = small.len();
    if s < 2 {
        return;
    }

    // dist[i * s + j]: max squared distance from the medoid of small list
    // i over the members of small list j; exact, including the diagonal
    let mut dist = vec![0u32; s * s];
    for i in 0..s {
        let q = BodyQuery::new(&lists[small[i]].medoid);
        for j in 0..s {
            dist[i * s + j] = lists[small[j]]
                .ids
                .iter()
                .map(|&id| q.emb_body(&rows[id as usize]))
                .max()
                .unwrap_or(0);
        }
    }

    // radius of the union of i and j about the medoid of i
    let about = |dist: &[u32], i: usize, j: usize| dist[i * s + i].max(dist[i * s + j]);

    // candidate pairs (radius of the union, i, j, versions of i and j when
    // pushed), the smallest radius first, ties by (i, j). C++ orders by
    // (radius, i, j) only; the versions break no tie that matters, since
    // at most one entry per (i, j) carries the current versions.
    let mut heap = BinaryHeap::new();
    let mut version = vec![0u32; s];
    let push = |heap: &mut BinaryHeap<_>, dist: &[u32], version: &[u32], i: usize, j: usize| {
        let radius2 = about(dist, i, j).min(about(dist, j, i));
        heap.push(Reverse((
            radius2, i as u32, j as u32, version[i], version[j],
        )));
    };
    for i in 0..s {
        for j in i + 1..s {
            push(&mut heap, &dist, &version, i, j);
        }
    }

    let mut alive = vec![true; s]; // still a small list
    let mut alive_count = s;
    while alive_count >= 2 {
        let Some(Reverse((radius2, i, j, vi, vj))) = heap.pop() else {
            break;
        };
        let (i, j) = (i as usize, j as usize);
        if !alive[i] || !alive[j] || version[i] != vi || version[j] != vj {
            continue; // stale
        }

        // the medoid giving the smaller radius; a's on ties
        let keep_a = about(&dist, i, j) <= about(&dist, j, i);

        let b = &mut lists[small[j]];
        let (b_ids, b_medoid) = (std::mem::take(&mut b.ids), b.medoid);
        let a = &mut lists[small[i]];
        a.ids = merge_sorted(&a.ids, &b_ids);
        if !keep_a {
            a.medoid = b_medoid;
        }
        a.radius2 = radius2;
        let a_len = a.ids.len();

        // distances from the merged list's medoid, and to its members
        for k in 0..s {
            if !keep_a {
                dist[i * s + k] = dist[j * s + k];
            }
            dist[k * s + i] = dist[k * s + i].max(dist[k * s + j]);
        }
        dist[i * s + i] = radius2;

        alive[j] = false;
        alive_count -= 1;
        version[i] += 1;
        if a_len >= half as usize {
            alive[i] = false;
            alive_count -= 1;
        } else {
            for k in 0..s {
                if k != i && alive[k] {
                    push(&mut heap, &dist, &version, i.min(k), i.max(k));
                }
            }
        }
    }

    lists.retain(|l| !l.ids.is_empty());
}

/// The sorted merge of two ascending runs (`std::merge`; equal ids, which
/// a valid merge never has, are both kept, `a`'s first).
fn merge_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut u = Vec::with_capacity(a.len() + b.len());
    let (mut x, mut y) = (0, 0);
    while x < a.len() && y < b.len() {
        if b[y] < a[x] {
            u.push(b[y]);
            y += 1;
        } else {
            u.push(a[x]);
            x += 1;
        }
    }
    u.extend_from_slice(&a[x..]);
    u.extend_from_slice(&b[y..]);
    u
}

/// Exact squared body-embedding radius about `m` over the rows `ids`.
fn radius_about(m: &TlshDigest, ids: &[u32], rows: &[[u8; DIGEST_LENGTH]]) -> u32 {
    let q = BodyQuery::new(m);
    ids.iter()
        .map(|&id| q.emb_body(&rows[id as usize]))
        .max()
        .unwrap_or(0)
}
