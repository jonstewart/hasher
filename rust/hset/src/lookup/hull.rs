//! Convex-hull fitted per-block position models.
//!
//! The sorted hash array is split into `2^bits` blocks by the leading `bits`
//! of each hash. Within a block, a hash's position is predicted from the next
//! 32 bits of its key by a straight line
//!
//! ```text
//! predicted(frac) = (frac * slope) >> 32          (all integer arithmetic)
//! ```
//!
//! and the window searched is `[predicted + rmin, predicted + rmax]`, where
//! `rmin`/`rmax` are the exact minimum and maximum residual `actual -
//! predicted` over every hash in the block, computed with the very same
//! integer formula used at query time. Correctness therefore never depends on
//! the distribution of the data: every stored hash is inside its own window.
//!
//! The slope is chosen to make that window as narrow as possible. The set of
//! `(frac, index)` points is monotone, and the narrowest slab of a fixed slope
//! enclosing a point set touches its convex hull, with the optimal slope equal
//! to the slope of some hull edge. So we build the upper and lower hulls
//! (monotone chain, linear time on the already-sorted points), evaluate the
//! slab width for every edge slope using only hull vertices, and keep the
//! best. Build cost is linear in the number of hashes.
//!
//! Compared to a flat per-block `[min, max]` deviation bound this removes the
//! within-block drift from the window, and compared to the previous
//! floating-point formulation it needs no verify-and-widen loop and no float
//! arithmetic on the query path. Each entry is 12 bytes.

use super::model::block_index;
use crate::key::key64;

/// One block's line and residual bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HullEntry {
    /// Positions per full `2^32` span of `frac`, i.e. `slope / 2^32` is the
    /// number of hashes per unit of key.
    pub slope: u32,
    /// Minimum residual (`actual - predicted`) in the block.
    pub rmin: i32,
    /// Maximum residual in the block.
    pub rmax: i32,
}

impl HullEntry {
    /// Marker for a block with no hashes: `rmin > rmax`.
    pub const EMPTY: HullEntry = HullEntry {
        slope: 0,
        rmin: 1,
        rmax: 0,
    };

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.rmin > self.rmax
    }

    /// Predicted position of a hash whose within-block key fraction is `frac`.
    #[inline(always)]
    pub fn predict(&self, frac: u32) -> i64 {
        ((u64::from(frac) * u64::from(self.slope)) >> 32) as i64
    }

    /// Half-open search window for `frac`, clamped to `[0, n)`.
    #[inline(always)]
    pub fn window(&self, frac: u32, n: u32) -> (u32, u32) {
        let p = self.predict(frac);
        let lo = (p + i64::from(self.rmin)).clamp(0, i64::from(n));
        let hi = (p + i64::from(self.rmax) + 1).clamp(lo, i64::from(n));
        (lo as u32, hi as u32)
    }

    /// Window width, i.e. the worst-case number of candidates.
    pub fn width(&self) -> u64 {
        if self.is_empty() {
            0
        } else {
            (i64::from(self.rmax) - i64::from(self.rmin) + 1) as u64
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&self.slope.to_le_bytes());
        b[4..8].copy_from_slice(&self.rmin.to_le_bytes());
        b[8..].copy_from_slice(&self.rmax.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> HullEntry {
        HullEntry {
            slope: u32::from_le_bytes(b[..4].try_into().unwrap()),
            rmin: i32::from_le_bytes(b[4..8].try_into().unwrap()),
            rmax: i32::from_le_bytes(b[8..12].try_into().unwrap()),
        }
    }
}

/// The 32 key bits below the block prefix.
#[inline(always)]
pub fn frac_of(key: u64, bits: u8) -> u32 {
    ((key << bits) >> 32) as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pt {
    x: u32,
    y: u32,
}

#[inline]
fn cross(o: Pt, a: Pt, b: Pt) -> i128 {
    let ax = i128::from(a.x) - i128::from(o.x);
    let ay = i128::from(a.y) - i128::from(o.y);
    let bx = i128::from(b.x) - i128::from(o.x);
    let by = i128::from(b.y) - i128::from(o.y);
    ax * by - ay * bx
}

/// Lower hull of points sorted by `(x, y)`; `upper` flips the turn test.
fn half_hull(pts: &[Pt], upper: bool) -> Vec<Pt> {
    let mut h: Vec<Pt> = Vec::with_capacity(16);
    for &p in pts {
        while h.len() >= 2 {
            let c = cross(h[h.len() - 2], h[h.len() - 1], p);
            let pop = if upper { c >= 0 } else { c <= 0 };
            if pop {
                h.pop();
            } else {
                break;
            }
        }
        h.push(p);
    }
    h
}

/// Slab width (max minus min of `y - s*x`) over hull vertices, in f64.
fn slab_width(s: f64, lower: &[Pt], upper: &[Pt]) -> f64 {
    let f = |p: &Pt| f64::from(p.y) - s * f64::from(p.x);
    let max = upper.iter().map(f).fold(f64::NEG_INFINITY, f64::max);
    let min = lower.iter().map(f).fold(f64::INFINITY, f64::min);
    max - min
}

/// Choose the slope (as fixed-point `u32`, scaled by `2^32`) minimizing the
/// enclosing slab width of `pts` (sorted by `(x, y)`).
fn choose_slope(pts: &[Pt]) -> u32 {
    if pts.len() < 2 {
        return 0;
    }
    let lower = half_hull(pts, false);
    let upper = half_hull(pts, true);

    let mut candidates: Vec<f64> = Vec::with_capacity(lower.len() + upper.len());
    for h in [&lower, &upper] {
        for w in h.windows(2) {
            let dx = f64::from(w[1].x) - f64::from(w[0].x);
            if dx > 0.0 {
                candidates.push((f64::from(w[1].y) - f64::from(w[0].y)) / dx);
            }
        }
    }
    // The end-to-end chord is a robust fallback (and often near-optimal).
    let (first, last) = (pts[0], pts[pts.len() - 1]);
    if last.x > first.x {
        candidates.push(
            (f64::from(last.y) - f64::from(first.y)) / (f64::from(last.x) - f64::from(first.x)),
        );
    }
    candidates.push(0.0);

    let mut best = 0.0f64;
    let mut best_w = f64::INFINITY;
    for s in candidates {
        if !(0.0..=1.0).contains(&s) {
            // Slopes above one hash per key unit cannot be represented and are
            // never optimal for digests; skip them.
            continue;
        }
        let w = slab_width(s, &lower, &upper);
        if w < best_w {
            best_w = w;
            best = s;
        }
    }
    (best * 4_294_967_296.0)
        .round()
        .clamp(0.0, f64::from(u32::MAX)) as u32
}

/// Fit the line and exact residual bounds for the hashes `data[start..end)`
/// whose within-block fractions are given by `frac`.
fn fit_block(indices: std::ops::Range<usize>, frac: impl Fn(usize) -> u32) -> HullEntry {
    let pts: Vec<Pt> = indices
        .clone()
        .map(|i| Pt {
            x: frac(i),
            y: i as u32,
        })
        .collect();
    if pts.is_empty() {
        return HullEntry::EMPTY;
    }
    // A steep slope over a narrow block can predict positions near 2^32,
    // leaving residuals no `i32` holds. Slope 0 always fits: its residuals
    // are the indices themselves, below 2^31.
    let fitted = residual_bounds(choose_slope(&pts), &pts);
    fitted.unwrap_or_else(|| residual_bounds(0, &pts).expect("indices fit in i32"))
}

/// The entry for `slope` with the exact residual bounds over `pts`, or
/// `None` if a bound does not fit in `i32`.
fn residual_bounds(slope: u32, pts: &[Pt]) -> Option<HullEntry> {
    let probe = HullEntry {
        slope,
        rmin: 0,
        rmax: 0,
    };
    let mut rmin = i64::MAX;
    let mut rmax = i64::MIN;
    for p in pts {
        let r = i64::from(p.y) - probe.predict(p.x);
        rmin = rmin.min(r);
        rmax = rmax.max(r);
    }
    Some(HullEntry {
        slope,
        rmin: i32::try_from(rmin).ok()?,
        rmax: i32::try_from(rmax).ok()?,
    })
}

/// Build the hull table for `data` (sorted, `L` bytes per hash) at `2^bits`
/// blocks. Panics if there are `2^32` or more hashes.
pub fn build_table<const L: usize>(data: &[u8], bits: u8) -> Vec<HullEntry> {
    let n = data.len() / L;
    assert!(
        n <= i32::MAX as usize,
        "too many hashes for 32-bit residual bounds"
    );
    assert!(bits <= 32, "block bits must be <= 32");
    let key = |i: usize| key64::<L>(&data[i * L..(i + 1) * L]);
    let mut table = vec![HullEntry::EMPTY; 1usize << bits];
    let mut i = 0;
    while i < n {
        let b = block_index(key(i), bits);
        let start = i;
        while i < n && block_index(key(i), bits) == b {
            i += 1;
        }
        table[b] = fit_block(start..i, |j| frac_of(key(j), bits));
    }
    table
}

/// Serialize a table as it is stored in a `HINT` chunk.
pub fn table_to_bytes(table: &[HullEntry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(table.len() * 12);
    for e in table {
        v.extend_from_slice(&e.to_bytes());
    }
    v
}

/// Parse a `HINT` table.
pub fn table_from_bytes(bytes: &[u8]) -> Vec<HullEntry> {
    bytes
        .as_chunks::<12>()
        .0
        .iter()
        .map(|c| HullEntry::from_bytes(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;

    fn check_table<const L: usize>(data: &[u8], bits: u8) -> (u64, u64) {
        let table = build_table::<L>(data, bits);
        let n = (data.len() / L) as u32;
        let mut total = 0u64;
        let mut max = 0u64;
        for i in 0..n as usize {
            let h = &data[i * L..(i + 1) * L];
            let k = key64::<L>(h);
            let e = table[block_index(k, bits)];
            let (lo, hi) = e.window(frac_of(k, bits), n);
            assert!(
                lo as usize <= i && i < hi as usize,
                "hash {i} outside its window [{lo},{hi})"
            );
            total += e.width();
            max = max.max(e.width());
        }
        (total / u64::from(n.max(1)), max)
    }

    #[test]
    fn every_hash_lies_in_its_window_uniform() {
        let data = synth::sorted_unique_hashes(20_000, 20, 1);
        for bits in [0u8, 4, 8, 12] {
            check_table::<20>(&data, bits);
        }
        let data = synth::sorted_unique_hashes(5_000, 4, 2);
        check_table::<4>(&data, 6);
        let data = synth::sorted_unique_hashes(5_000, 8, 3);
        check_table::<8>(&data, 6);
    }

    #[test]
    fn every_hash_lies_in_its_window_adversarial() {
        let data = synth::adversarial_hashes(20_000, 20, 7);
        for bits in [0u8, 3, 8, 11] {
            check_table::<20>(&data, bits);
        }
    }

    #[test]
    fn degenerate_sets() {
        assert!(build_table::<20>(&[], 8).iter().all(HullEntry::is_empty));
        let one = [0x80u8; 20];
        let t = build_table::<20>(&one, 8);
        assert!(!t[0x80].is_empty());
        assert_eq!(t[0x80].window(frac_of(key64::<20>(&one), 8), 1), (0, 1));
        // All hashes identical in key, differing only in tail.
        let mut same = vec![0x11u8; 20 * 5];
        for i in 0..5 {
            same[i * 20 + 19] = i as u8;
        }
        check_table::<20>(&same, 8);
        // Two blocks, one hash each, at the extremes.
        let mut two = vec![0u8; 40];
        two[20..].fill(0xff);
        check_table::<20>(&two, 1);
    }

    #[test]
    fn windows_are_narrower_than_flat_blocks() {
        // On uniform data the fitted line should beat a flat [min, max]
        // deviation bound at equal block count by a clear margin.
        let data = synth::sorted_unique_hashes(200_000, 20, 11);
        let bits = 8;
        let (hull_avg, _) = check_table::<20>(&data, bits);
        let flat = super::super::block::build_table::<20>(&data, bits);
        let flat_avg: u64 = {
            let widths: Vec<u64> = flat
                .iter()
                .filter(|(lo, hi)| lo <= hi)
                .map(|(lo, hi)| (hi - lo + 1) as u64)
                .collect();
            widths.iter().sum::<u64>() / widths.len() as u64
        };
        assert!(
            hull_avg * 10 < flat_avg * 8,
            "hull avg width {hull_avg} not < 0.8 * flat avg width {flat_avg}"
        );
    }

    #[test]
    fn steep_slope_with_out_of_range_residuals_falls_back() {
        // Fractions 0xfffffffe and 0xffffffff at indices 0 and 1: slope 1
        // predicts ~2^32, so its residuals do not fit in i32.
        let mut data = vec![0u8; 2 * 8];
        data[..8].copy_from_slice(&0x80ff_ffff_ff80_0000u64.to_be_bytes());
        data[8..].copy_from_slice(&0x80ff_ffff_ffff_0000u64.to_be_bytes());
        check_table::<8>(&data, 10);
    }

    #[test]
    fn bytes_roundtrip() {
        let data = synth::sorted_unique_hashes(1000, 16, 5);
        let t = build_table::<16>(&data, 6);
        let b = table_to_bytes(&t);
        assert_eq!(b.len(), 64 * 12);
        assert_eq!(table_from_bytes(&b), t);
    }

    #[test]
    fn hull_of_collinear_points_is_two_vertices() {
        let pts: Vec<Pt> = (0..10)
            .map(|i| Pt {
                x: i * 10,
                y: i * 3,
            })
            .collect();
        assert_eq!(half_hull(&pts, false).len(), 2);
        assert_eq!(half_hull(&pts, true).len(), 2);
        let s = choose_slope(&pts);
        assert_eq!(s, ((0.3f64) * 4_294_967_296.0).round() as u32);
    }
}
