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
//! * C++ trusts the index and reads out of bounds on a corrupt one. Rust
//!   does not validate it either (no pass over the index, at load or on
//!   first use), but checks each access the search makes: a cell's range
//!   of lists, a list's range of ids, each id against the rows, and the
//!   single-list fast path's row run. The first that is out of bounds is
//!   an [`Error::Format`]; nothing panics. A corrupt index whose accesses
//!   are in bounds (an id in the wrong cell or list, a radius too small,
//!   a row twice or never) is searched as C++ searches it, and the result
//!   may then differ from brute force.
//!   [`check_index`](super::check_index) finds those on request.
//! * An empty single-list cell is scanned as no rows; C++ reads `ids[lb]`
//!   first, which may be past the ids.
//! * C++ documents `MIN_BOUNDED_LIST` as applying to all lists; it only
//!   applies to a cell's only list (the lists of a multi-list cell are
//!   always bounded). Rust does the same and documents it so.

use super::IvfIndex;
use crate::error::{Error, Result};
use crate::key::prefetch;
use crate::tlsh::digest::{DIGEST_LENGTH, TlshDigest};
use crate::tlsh::distance::{BodyQuery, popcount};
use crate::tlsh::knn::{KnnStats, TlshMatch, TopK};
use crate::tlsh::order::HeaderOrder;

/// Offset of the checksum byte in a canonical row (see
/// [`crate::tlsh::digest`]).
const CHECKSUM: usize = 34;

/// Rows of a multi-list cell's list prefetched ahead of the scan (C++
/// `PF` in `tlsh_knn_ivf`).
const PREFETCH_AHEAD: usize = 8;

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

/// The k nearest neighbours of `q` among `rows`, the rows `ivf` indexes
/// (C++ `tlsh_knn_ivf`): up to `k` matches with distance at most
/// `max_distance`, nearest first, ties by ascending row index. For an
/// index that [`check_index`](super::check_index) accepts over `rows`
/// (every index the builder and the merge write), exactly what
/// [`knn_brute`](crate::tlsh::knn::knn_brute) returns over `rows`. Empty
/// when `k == 0`, `q` is null, or there are no rows.
///
/// Cells are visited in [`HeaderOrder`] with the cell search's early
/// exits (the L loop stops at the first L cost above the current bound,
/// the Q loop at the first header cost `ch` above it; empty cells are
/// skipped). In a nonempty cell:
///
/// * a single list holds the whole cell, which in a sound index is a
///   contiguous row range starting at the list's first id: that range is
///   scanned if it has fewer than
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
///
/// # Errors
///
/// [`Error::Format`] when the index does not fit `rows` in O(1) terms
/// (arrays of inconsistent lengths, [`IvfIndex::check_layout`], or `n`
/// other than `rows.len()`), or at the first access the search makes out
/// of bounds: an inverted range or one past the arrays
/// ([`IvfIndex::cell_range`], [`IvfIndex::list_range`]), an id not below
/// `rows.len()`, or a single-list cell whose rows run past the end. Which
/// out-of-bounds entry is found, if any, depends on the query: only what
/// the search visits is checked. Never panics.
pub fn knn_ivf<I: IvfIndex + ?Sized>(
    ivf: &I,
    rows: &[[u8; DIGEST_LENGTH]],
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
    stats: Option<&mut KnnStats>,
) -> Result<Vec<TlshMatch>> {
    // O(1): after these every accessor the scan calls with an index from a
    // checked range is in bounds
    ivf.check_layout()?;
    if ivf.n() != rows.len() as u64 {
        return Err(Error::format(format!(
            "TIVF indexes {} rows, the section has {}",
            ivf.n(),
            rows.len()
        )));
    }
    if k == 0 || rows.is_empty() || q.is_null() {
        return Ok(Vec::new());
    }
    popcount().scan(
        #[inline(always)]
        || ivf_scan(ivf, rows, q, k, max_distance, include_length, stats),
    )
}

/// The search of [`knn_ivf`], inlined into its `Popcount::scan` context.
#[inline(always)]
fn ivf_scan<I: IvfIndex + ?Sized>(
    ivf: &I,
    rows: &[[u8; DIGEST_LENGTH]],
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
    mut stats: Option<&mut KnnStats>,
) -> Result<Vec<TlshMatch>> {
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
            // most cells are empty: test that first, as C++ does
            if ivf.cell_lists(c) == ivf.cell_lists(c + 1) {
                continue;
            }
            let cell = ivf.cell_range(c)?;
            if let Some(s) = stats.as_deref_mut() {
                s.cells += 1;
            }

            if cell.len() == 1 {
                // a single list holds the whole cell: its ids are the
                // cell's contiguous row range in ascending order
                let fl = cell.start;
                let members = ivf.list_range(fl)?;
                let count = members.len() as u64;
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
                if members.is_empty() {
                    continue; // C++ reads ids[lb] here, which may be past the ids
                }
                let first = ivf.id(members.start) as usize;
                let Some(run) = rows.get(first..).and_then(|r| r.get(..members.len())) else {
                    return Err(run_error(fl, first, count, rows.len()));
                };
                for (i, r) in run.iter().enumerate() {
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
                let range = ivf.list_range(fl)?;
                if let Some(s) = stats.as_deref_mut() {
                    s.rows += range.len() as u64;
                }
                let end = range.end;
                for i in range {
                    // the members are scattered over the rows: fetch ahead.
                    // The address is only a hint (wrapping, never read), so
                    // an id past the rows needs no check here.
                    if i + PREFETCH_AHEAD < end {
                        let ahead = ivf.id(i + PREFETCH_AHEAD) as usize;
                        prefetch(rows.as_ptr().wrapping_add(ahead).cast());
                    }
                    let id = ivf.id(i);
                    let Some(r) = rows.get(id as usize) else {
                        return Err(id_error(fl, id, rows.len()));
                    };
                    top.offer(TlshMatch {
                        index: id.into(),
                        distance: row_cost(ch, r),
                    });
                }
            }
        }
    }
    Ok(top.into_sorted())
}

/// The error of an id past the rows, out of the scan's way.
#[cold]
#[inline(never)]
fn id_error(list: usize, id: u32, rows: usize) -> Error {
    Error::format(format!(
        "TIVF list {list} has id {id} out of range for {rows} rows"
    ))
}

/// The error of a single-list cell whose rows run past the end.
#[cold]
#[inline(never)]
fn run_error(list: usize, first: usize, count: u64, rows: usize) -> Error {
    Error::format(format!(
        "TIVF list {list} has rows {first}..{} out of range for {rows} rows",
        first as u64 + count
    ))
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `list_bound` is never negative or NaN, and is 0 when the query is no
    /// farther from the medoid than the radius (`d2 <= r2`: the query may
    /// lie inside the list). Rules out dropping the `max(0.0)` (a gap
    /// below 0.1 would give a negative bound that lowers the header cost
    /// it is added to) and a sign slip that prunes a list containing the
    /// query's neighbours.
    ///
    /// Inputs are below `2^10`: a squared body-embedding distance is at
    /// most `5 * 128 = 640`, so `d2` always is, and so is the exact
    /// `radius2` the build and the merge write. A loaded file's `radius2`
    /// is only checked to be an upper bound and may be larger; that range
    /// is not covered. (Over all `u32` pairs the `f32` square roots did not
    /// finish in 20 minutes.)
    #[kani::proof]
    #[kani::unwind(1)]
    fn list_bound_is_nonnegative_and_zero_inside() {
        let d2 = kani::any::<u32>() & 0x3ff;
        let r2 = kani::any::<u32>() & 0x3ff;
        let b = list_bound(d2, r2);
        assert!(b >= 0.0);
        if d2 <= r2 {
            assert!(b == 0.0);
        }
    }
}
