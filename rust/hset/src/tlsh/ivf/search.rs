//! Exact indexed kNN search over a TIVF index (`tlsh_knn_ivf`).

use super::{IvfIndex, ValidIvf};
use crate::tlsh::digest::TlshDigest;
use crate::tlsh::knn::{KnnStats, TlshMatch};

/// Lists with fewer members than this are scanned without evaluating
/// their bound (C++ `MIN_BOUNDED_LIST`).
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

/// Exact kNN through the index (stub).
pub fn knn_ivf<I: IvfIndex>(
    _ivf: &ValidIvf<'_, I>,
    _q: &TlshDigest,
    _k: usize,
    _max_distance: u32,
    _include_length: bool,
    _stats: Option<&mut KnnStats>,
) -> Vec<TlshMatch> {
    Vec::new()
}
