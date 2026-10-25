//! Exact indexed kNN search over a TIVF index (C++ `tlsh_knn_ivf`,
//! `tlsh_ivf.cpp`): [`knn_ivf`] returns exactly what
//! [`knn_brute`](crate::tlsh::knn::knn_brute) returns, visiting fewer rows
//! by bounding each list's body distance with [`list_bound`].
//!
//! The port is faithful down to the visit order, the `f32` bound
//! arithmetic and the `(bound, list)` sort, so the [`KnnStats`] counters
//! equal C++'s for the same index and query.
//!
//! # Differences from the C++ library
//!
//! * [`knn_ivf`] takes a [`ValidIvf`], the index together with the rows it
//!   was validated against, where C++ takes a view and a row pointer and
//!   trusts both. The single-list fast path (scan the cell's rows as one
//!   contiguous range starting at the list's first id) relies on what
//!   validation guarantees; C++ relies on how its builders and merge
//!   write indexes.
//! * C++ documents `MIN_BOUNDED_LIST` as applying to all lists; it only
//!   applies to a cell's only list (the lists of a multi-list cell are
//!   always bounded). Rust does the same and documents it so.

use super::{IvfIndex, ValidIvf};
use crate::tlsh::digest::{DIGEST_LENGTH, TlshDigest};
use crate::tlsh::distance::{BodyQuery, popcount};
use crate::tlsh::knn::{KnnStats, TlshMatch, TopK};
use crate::tlsh::order::HeaderOrder;

/// Offset of the checksum byte in a canonical row (see
/// [`crate::tlsh::digest`]).
const CHECKSUM: usize = 34;

/// A cell whose only list has fewer members than this is scanned without
/// evaluating the list's bound (C++ `MIN_BOUNDED_LIST`); such a list is
/// not counted in [`KnnStats::lists`].
pub const MIN_BOUNDED_LIST: u64 = 4;

/// Lower bound on the squared body-embedding distance from a query to any
/// member of a list, given the query's squared distance `d2` to the
/// list's medoid and the list's `radius2` `r2` (C++ `list_bound`).
///
/// By the triangle inequality in embedding space every member is at least
/// `sqrt(d2) - sqrt(r2)` from the query; the bound is that gap squared,
/// less `1e-2` so that `f32` rounding can never prune a row that is in
/// range, and 0 when the gap is not positive or the relaxed square is
/// negative. Computed in `f32` exactly as the C++ does (single-precision
/// square roots, multiply and subtract, no fused multiply-add), so the
/// search prunes, and counts, the same lists.
///
/// The squared body-embedding distance never exceeds the TLSH body
/// distance, so the bound is also a lower bound on the body part of the
/// TLSH distance of every member.
pub fn list_bound(d2: u32, r2: u32) -> f32 {
    let b = (d2 as f32).sqrt() - (r2 as f32).sqrt();
    if b > 0.0 {
        (b * b - 1e-2).max(0.0)
    } else {
        0.0
    }
}

/// Exact k nearest neighbours of `q` among the rows of a validated TIVF
/// index (C++ `tlsh_knn_ivf`): up to `k` matches with distance at most
/// `max_distance`, nearest first, ties by ascending row index; exactly
/// what [`knn_brute`](crate::tlsh::knn::knn_brute) returns over
/// `ivf.rows()`. Empty when `k == 0`, `q` is null, or the index has no
/// rows.
///
/// Cells are visited in [`HeaderOrder`] with the cell search's early
/// exits (the L loop stops at the first L cost above the current bound,
/// the Q loop at the first header cost `ch` above it; empty cells are
/// skipped). In a nonempty cell:
///
/// * a single list holds the whole cell, which by [`ValidIvf`] is a
///   contiguous row range: it is scanned if it has fewer than
///   [`MIN_BOUNDED_LIST`] rows or `ch + list_bound(d2, radius2) <= bound`
///   (in `f32`), where `d2` is the query's squared body-embedding distance
///   to the medoid;
/// * otherwise every list's bound `b2` is evaluated, lists with
///   `ch + b2 <= bound` are kept and sorted by `(b2, list)`, and they are
///   scanned in that order until the first whose `ch + b2` exceeds the
///   bound, which shrinks as matches are found.
///
/// A row's distance is `ch + (checksum differs) + body`. The pruning is
/// exact because `list_bound` is a lower bound on the body distance of
/// every member (see [`list_bound`]), whatever the medoid and however
/// loose the radius.
///
/// `stats`, when given, is added to as by C++: `cells` counts the
/// nonempty cells visited, `lists` every list of a cell with several plus
/// each single-list cell of at least [`MIN_BOUNDED_LIST`] rows (scanned
/// or pruned), and `rows` the rows whose distance was computed. The visit
/// order is C++'s, so the counts equal C++'s for the same index.
pub fn knn_ivf<I: IvfIndex>(
    ivf: &ValidIvf<'_, I>,
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
    stats: Option<&mut KnnStats>,
) -> Vec<TlshMatch> {
    if k == 0 || ivf.rows().is_empty() || q.is_null() {
        return Vec::new();
    }
    popcount().scan(
        #[inline(always)]
        || ivf_scan(ivf, q, k, max_distance, include_length, stats),
    )
}

/// The search of [`knn_ivf`], inlined into its `Popcount::scan` context.
#[inline(always)]
fn ivf_scan<I: IvfIndex>(
    ivf: &ValidIvf<'_, I>,
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
    mut stats: Option<&mut KnnStats>,
) -> Vec<TlshMatch> {
    let rows = ivf.rows();
    let order = HeaderOrder::new(q, include_length);
    let body = BodyQuery::new(q);
    let checksum = q.checksum();
    let mut top = TopK::new(k, max_distance);
    let row_cost =
        |ch: u32, r: &[u8; DIGEST_LENGTH]| ch + u32::from(r[CHECKSUM] != checksum) + body.body(r);

    // (body bound, list) of the lists of a multi-list cell worth scanning
    let mut lists: Vec<(f32, usize)> = Vec::new();

    for (&l, &cl) in order.l().iter().zip(order.l_cost()) {
        if cl > top.bound() {
            break;
        }
        for (&qb, &cq) in order.q().iter().zip(order.q_cost()) {
            let ch = cl + cq;
            if ch > top.bound() {
                break;
            }
            let c = usize::from(l) << 8 | usize::from(qb);
            let cell = ivf.cell_range(c);
            if cell.is_empty() {
                continue;
            }
            if let Some(s) = stats.as_deref_mut() {
                s.cells += 1;
            }

            if cell.len() == 1 {
                // a single list holds the whole cell: its ids are the
                // cell's contiguous row range in ascending order
                let fl = cell.start;
                let count = ivf.list_len(fl);
                let bounded = count >= MIN_BOUNDED_LIST;
                if let Some(s) = stats.as_deref_mut() {
                    s.lists += u64::from(bounded);
                }
                if bounded
                    && ch as f32 + list_bound(body.emb_body(&ivf.medoid(fl).0), ivf.radius2(fl))
                        > top.bound() as f32
                {
                    continue;
                }
                if let Some(s) = stats.as_deref_mut() {
                    s.rows += count;
                }
                let first = ivf.id(ivf.list_range(fl).start) as usize;
                for (i, r) in rows[first..first + count as usize].iter().enumerate() {
                    top.offer(TlshMatch {
                        index: (first + i) as u64,
                        distance: row_cost(ch, r),
                    });
                }
                continue;
            }

            // body lower bound per list, through medoid and radius
            if let Some(s) = stats.as_deref_mut() {
                s.lists += cell.len() as u64;
            }
            lists.clear();
            for fl in cell {
                let b2 = list_bound(body.emb_body(&ivf.medoid(fl).0), ivf.radius2(fl));
                if ch as f32 + b2 <= top.bound() as f32 {
                    lists.push((b2, fl));
                }
            }
            lists.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
            for &(b2, fl) in &lists {
                if ch as f32 + b2 > top.bound() as f32 {
                    break;
                }
                let range = ivf.list_range(fl);
                if let Some(s) = stats.as_deref_mut() {
                    s.rows += range.len() as u64;
                }
                for i in range {
                    let id = ivf.id(i);
                    top.offer(TlshMatch {
                        index: id.into(),
                        distance: row_cost(ch, &rows[id as usize]),
                    });
                }
            }
        }
    }
    top.into_sorted()
}
