//! The generic searcher: a window model plus an exact search within the window.
//!
//! With a good model the window is a handful of hashes, i.e. a few cache
//! lines, and the cost of a lookup is dominated by memory latency: one access
//! to the model's table and one to the hash data. The search is therefore
//! organised around overlapping those accesses:
//!
//! * **Single lookups** prefetch every line of a small window at once and then
//!   scan it, so the window costs one memory round trip instead of one per
//!   probe. Large windows (weak hints, adversarial data) use an 8-ary search
//!   whose seven loads per step are independent and overlap.
//! * **Batched lookups** run a three-stage software pipeline over the query
//!   stream: prefetch the table entry of query `i`, prefetch the window lines
//!   of query `i - D`, and search query `i - 2D`, whose data is by then in
//!   cache. When the model cannot keep windows small (or there is no model)
//!   batches fall back to many interleaved binary searches that each prefetch
//!   their next probe.

use std::ops::Range;

use super::model::Model;
use super::{BatchMode, Lookup, SearchConfig, SingleMode};
use crate::key::{cmp_hash, key64, prefetch};

/// A lookup strategy for `L`-byte hashes with model `M`.
pub struct Strategy<'a, const L: usize, M: Model> {
    data: &'a [u8],
    n: u32,
    model: M,
    cfg: SearchConfig,
    staged_batch: bool,
    passes_batch: bool,
    /// Half-width (in hashes) of the region around the model's prediction
    /// that covers `REGION_QUANTILE` of the stored hashes; the first level
    /// of the recursive search.
    region_radius: usize,
}

/// Windows at or below this many elements are scanned linearly.
const LINEAR_LIMIT: usize = 8;
const CACHE_LINE: usize = 64;
/// Models whose mean window is at most this use the staged batch pipeline.
const STAGED_MEAN_WINDOW_LIMIT: f64 = 48.0;
/// Pipeline distance of the staged batch.
const STAGE_DISTANCE: usize = 8;
/// Fraction of stored hashes whose residual the level-1 region must cover.
const REGION_QUANTILE: f64 = 0.90;
/// Hashes sampled at construction to estimate the region radius.
const REGION_SAMPLES: usize = 2048;
/// Maximum recursion depth before falling back to 8-ary search.
const MAX_LEVELS: usize = 8;

impl<const L: usize, M: Model> std::fmt::Debug for Strategy<'_, L, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Strategy")
            .field("hash_length", &L)
            .field("count", &self.n)
            .field("model", &self.model.describe())
            .field("cfg", &self.cfg)
            .field("staged_batch", &self.staged_batch)
            .field("region_radius", &self.region_radius)
            .finish()
    }
}

impl<'a, const L: usize, M: Model> Strategy<'a, L, M> {
    pub fn new(data: &'a [u8], model: M, cfg: SearchConfig) -> Self {
        assert!(
            data.len().is_multiple_of(L),
            "data is not a whole number of hashes"
        );
        let n = data.len() / L;
        assert!(n < (1usize << 32), "too many hashes for a 32-bit index");
        let mut cfg = cfg;
        if cfg.single == SingleMode::Auto {
            // Without a hint the window is the whole array and interpolation
            // beats bisection by a wide margin on digests; with a hint the
            // window already fits in a round trip or two.
            cfg.single = if model.mean_window().is_none() && L >= 16 {
                SingleMode::Recursive
            } else {
                SingleMode::KAry
            };
        }
        let small_windows = model
            .mean_window()
            .is_some_and(|w| w <= STAGED_MEAN_WINDOW_LIMIT);
        let staged_batch = match cfg.batch {
            BatchMode::Lanes | BatchMode::Passes => false,
            BatchMode::Staged => true,
            BatchMode::Auto => small_windows,
        };
        let passes_batch = cfg.batch == BatchMode::Passes && small_windows;
        let mut s = Strategy {
            data,
            n: n as u32,
            model,
            cfg,
            staged_batch,
            passes_batch,
            region_radius: 0,
        };
        s.region_radius = s.sample_region_radius();
        s
    }

    /// Estimate the level-1 region radius from a sample of stored hashes:
    /// the `REGION_QUANTILE` quantile of |index - predicted|.
    fn sample_region_radius(&self) -> usize {
        let n = self.n as usize;
        if n == 0 {
            return 0;
        }
        let step = (n / REGION_SAMPLES).max(1);
        let mut res: Vec<u64> = (0..n)
            .step_by(step)
            .map(|i| {
                let h = &self.data[i * L..(i + 1) * L];
                // `center` comes from a hint read from the file and can be
                // anywhere in `i64`; `abs_diff` cannot overflow.
                let c = self.model.center(key64::<L>(h), h, self.n);
                (i as i64).abs_diff(c)
            })
            .collect();
        res.sort_unstable();
        let q = ((res.len() as f64 - 1.0) * REGION_QUANTILE) as usize;
        self.clamp_radius(res[q] as usize)
    }

    /// Keep a region between one line and `cfg.region_bytes` per side.
    #[inline(always)]
    fn clamp_radius(&self, r: usize) -> usize {
        let min = CACHE_LINE / L + 1;
        r.clamp(min, (self.cfg.region_bytes / 2 / L).max(min))
    }

    /// Region radius used by the recursive search (diagnostics).
    pub fn region_radius(&self) -> usize {
        self.region_radius
    }

    /// Level-1 region `[a, b)` around the prediction for `key`, inside `[lo, hi)`.
    #[inline(always)]
    fn region(&self, center: i64, r: usize, lo: usize, hi: usize) -> (usize, usize) {
        let c = center.clamp(lo as i64, hi as i64 - 1) as usize;
        let a = c.saturating_sub(r).max(lo);
        let b = (c + r + 1).min(hi);
        (a, b)
    }

    /// Recursive dictionary search within `[lo, hi)`.
    ///
    /// Each level fetches the lines of a region around the current estimate
    /// in one round trip. If the key lies inside the region's key range the
    /// search finishes there; otherwise the region's edge key and the model's
    /// density give the next estimate, with a radius shrinking roughly as the
    /// square root, and the bracket narrows to the unexplored side. The
    /// bracket shrinks strictly, so this terminates and is exact on any data;
    /// after `MAX_LEVELS` it hands the remaining bracket to the 8-ary search.
    #[inline(always)]
    fn find_recursive(&self, hash: &[u8], hk: u64, mut lo: usize, mut hi: usize) -> Option<usize> {
        let mut center = self.model.center(hk, hash, self.n);
        let mut r = self.region_radius;
        for _ in 0..MAX_LEVELS {
            if (hi - lo) * L <= self.cfg.window_prefetch_bytes {
                self.prefetch_window(lo, hi);
                let pos = self.lower_bound_binary(hk, lo, hi);
                return self.confirm(hash, hk, pos, hi);
            }
            let (a, b) = self.region(center, r, lo, hi);
            self.prefetch_window(a, b);
            let ka = self.key_at(a);
            let kb = self.key_at(b - 1);
            if hk < ka {
                if a == lo {
                    return None; // smaller than everything in the window
                }
                // Everything in [a, hi) is too large; re-aim below a. The
                // error of the new estimate grows like the square root of
                // the distance jumped, so the next region shrinks that way.
                hi = a;
                let d = self.model.delta(hk, ka - hk, self.n);
                center = a as i64 - d as i64 - 1;
                r = self.clamp_radius(2 * (d as f64).sqrt() as usize);
            } else if hk == ka {
                // A run of equal primary keys may extend below a; its start is
                // the lower bound. Rare for digests, so a plain search is fine.
                let pos = self.lower_bound_binary(hk, lo, a + 1);
                return self.confirm(hash, hk, pos, hi);
            } else if hk > kb {
                if b == hi {
                    return None; // larger than everything in the window
                }
                lo = b;
                let d = self.model.delta(hk, hk - kb, self.n);
                center = b as i64 - 1 + d as i64;
                r = self.clamp_radius(2 * (d as f64).sqrt() as usize);
            } else {
                // ka < hk <= kb: the lower bound is inside (a, b).
                let pos = self.lower_bound_binary(hk, a + 1, b);
                return self.confirm(hash, hk, pos, hi);
            }
        }
        let pos = self.lower_bound_kary(hk, lo, hi);
        self.confirm(hash, hk, pos, hi)
    }

    pub fn model(&self) -> &M {
        &self.model
    }

    /// Whether batches use the staged pipeline (diagnostics).
    pub fn uses_staged_batch(&self) -> bool {
        self.staged_batch
    }

    #[inline(always)]
    fn key_at(&self, i: usize) -> u64 {
        key64::<L>(&self.data[i * L..])
    }

    #[inline(always)]
    fn ptr_at(&self, i: usize) -> *const u8 {
        // Only used as a prefetch hint; `i` is always within the data.
        self.data[i * L..].as_ptr()
    }

    /// Prefetch every cache line holding elements `[lo, hi)`.
    #[inline(always)]
    fn prefetch_window(&self, lo: usize, hi: usize) {
        let start = self.ptr_at(lo) as usize & !(CACHE_LINE - 1);
        let end = self.ptr_at(lo) as usize + (hi - lo) * L;
        let mut p = start;
        while p < end {
            prefetch(p as *const u8);
            p += CACHE_LINE;
        }
    }

    /// Issue prefetches that help a later search of `[lo, hi)`: the whole
    /// window when it is small, otherwise the first 8-ary probe positions.
    #[inline(always)]
    fn prefetch_for(&self, key: u64, hash: &[u8], lo: usize, hi: usize) {
        let len = hi - lo;
        if len * L <= self.cfg.window_prefetch_bytes {
            self.prefetch_window(lo, hi);
        } else if self.cfg.single == SingleMode::Recursive {
            let center = self.model.center(key, hash, self.n);
            let (a, b) = self.region(center, self.region_radius, lo, hi);
            self.prefetch_window(a, b);
        } else {
            for j in 1..8 {
                prefetch(self.ptr_at(lo + ((len * j) >> 3)));
            }
        }
    }

    /// Lower bound of `hk` in `[lo, hi)` by branchless binary search over
    /// primary keys, finishing with a linear scan.
    #[inline(always)]
    fn lower_bound_binary(&self, hk: u64, lo: usize, hi: usize) -> usize {
        let mut pos = lo;
        let mut len = hi - lo;
        while len > LINEAR_LIMIT {
            let half = len >> 1;
            let probe = pos + half;
            let lt = self.key_at(probe) < hk;
            pos = if lt { probe + 1 } else { pos };
            len = if lt { len - half - 1 } else { half };
        }
        self.lower_bound_linear(hk, pos, pos + len)
    }

    #[inline(always)]
    fn lower_bound_linear(&self, hk: u64, lo: usize, hi: usize) -> usize {
        let mut i = lo;
        while i < hi && self.key_at(i) < hk {
            i += 1;
        }
        i
    }

    /// One 8-ary step: returns the sub-window that must contain the lower
    /// bound of `hk`. Requires `hi - lo > 8`.
    #[inline(always)]
    fn kary_step(&self, hk: u64, lo: usize, hi: usize) -> (usize, usize) {
        let len = hi - lo;
        // Probe positions p1..p7; p0 = lo - 1 and p8 = hi are virtual.
        let mut p = [0usize; 9];
        for (j, slot) in p.iter_mut().enumerate().skip(1).take(7) {
            *slot = lo + ((len * j) >> 3);
        }
        p[8] = hi;
        // Issue all seven loads before comparing so they overlap.
        let keys = [
            self.key_at(p[1]),
            self.key_at(p[2]),
            self.key_at(p[3]),
            self.key_at(p[4]),
            self.key_at(p[5]),
            self.key_at(p[6]),
            self.key_at(p[7]),
        ];
        let mut c = 0usize;
        for k in keys {
            c += usize::from(k < hk);
        }
        // Keys at p1..pc are < hk; the lower bound is in (pc, p(c+1)].
        let new_lo = if c == 0 { lo } else { p[c] + 1 };
        let new_hi = if c == 7 { hi } else { p[c + 1] + 1 };
        (new_lo, new_hi)
    }

    #[inline(always)]
    fn lower_bound_kary(&self, hk: u64, mut lo: usize, mut hi: usize) -> usize {
        // `kary_step` only shrinks windows of more than 8 hashes; a prefetch
        // budget below that must not keep stepping smaller windows.
        while hi - lo > 8 && (hi - lo) * L > self.cfg.window_prefetch_bytes {
            (lo, hi) = self.kary_step(hk, lo, hi);
        }
        // The remainder spans few lines: fetch them all at once and scan.
        self.prefetch_window(lo, hi);
        self.lower_bound_binary(hk, lo, hi)
    }

    /// Index of the first hash equal to `hash` within `[pos, hi)`, given the
    /// lower bound `pos` of its primary key.
    #[inline(always)]
    fn confirm(&self, hash: &[u8], hk: u64, pos: usize, hi: usize) -> Option<usize> {
        let mut j = pos;
        while j < hi {
            let cand = &self.data[j * L..(j + 1) * L];
            if key64::<L>(cand) != hk {
                return None;
            }
            if L <= 8 {
                return Some(j);
            }
            match cand[8..L].cmp(&hash[8..L]) {
                std::cmp::Ordering::Equal => return Some(j),
                std::cmp::Ordering::Greater => return None,
                std::cmp::Ordering::Less => j += 1,
            }
        }
        None
    }

    /// Search `[lo, hi)` assuming nothing about cache state.
    #[inline(always)]
    fn find_in(&self, hash: &[u8], hk: u64, lo: usize, hi: usize) -> Option<usize> {
        if lo >= hi {
            return None;
        }
        let pos = match self.cfg.single {
            SingleMode::KAry | SingleMode::Auto => self.lower_bound_kary(hk, lo, hi),
            SingleMode::Binary => self.lower_bound_binary(hk, lo, hi),
            SingleMode::Recursive => return self.find_recursive(hash, hk, lo, hi),
        };
        self.confirm(hash, hk, pos, hi)
    }

    /// Search `[lo, hi)` whose lines were prefetched earlier.
    #[inline(always)]
    fn find_in_prefetched(&self, hash: &[u8], hk: u64, lo: usize, hi: usize) -> Option<usize> {
        if lo >= hi {
            return None;
        }
        let pos = if (hi - lo) * L <= self.cfg.window_prefetch_bytes {
            self.lower_bound_binary(hk, lo, hi)
        } else if self.cfg.single == SingleMode::Recursive {
            return self.find_recursive(hash, hk, lo, hi);
        } else {
            self.lower_bound_kary(hk, lo, hi)
        };
        self.confirm(hash, hk, pos, hi)
    }

    /// Three-stage software pipeline over the query stream.
    fn batch_staged(&self, hashes: &[u8], out: &mut [bool]) {
        const D: usize = STAGE_DISTANCE;
        let count = out.len();
        let hash_at = |q: usize| &hashes[q * L..(q + 1) * L];
        // Ring of 2D: query i - D is written while query i - 2D is read.
        let mut win = [(0u32, 0u32); 2 * D];
        // Keys are written for query i and read for i - D and i - 2D in the
        // same iteration, so they need a ring of 3D to keep the slots apart.
        let mut keys = [0u64; 3 * D];
        for i in 0..count + 2 * D {
            // Stage 1: table entry of query i.
            if i < count {
                let k = key64::<L>(hash_at(i));
                keys[i % (3 * D)] = k;
                self.model.prefetch_entry(k);
            }
            // Stage 2: window of query i - D (its table entry is now cached).
            if i >= D && i - D < count {
                let q = i - D;
                let h = hash_at(q);
                let k = keys[q % (3 * D)];
                let (lo, hi) = self.model.window(k, h, self.n);
                win[q % (2 * D)] = (lo, hi);
                if lo < hi {
                    self.prefetch_for(k, h, lo as usize, hi as usize);
                }
            }
            // Stage 3: search query i - 2D (its window is now cached).
            if i >= 2 * D && i - 2 * D < count {
                let q = i - 2 * D;
                let h = hash_at(q);
                let (lo, hi) = win[q % (2 * D)];
                let k = keys[q % (3 * D)];
                out[q] = self
                    .find_in_prefetched(h, k, lo as usize, hi as usize)
                    .is_some();
            }
        }
    }

    /// Struct-of-arrays passes over sub-batches, software-pipelined three
    /// sub-batches deep: while sub-batch `k` is searched, the windows of
    /// `k + 1` are being evaluated and prefetched and the table entries of
    /// `k + 2` are being touched. Within a pass every load is independent of
    /// every other, and the window arithmetic is a plain loop over arrays
    /// that the compiler can vectorise.
    fn batch_passes(&self, hashes: &[u8], out: &mut [bool]) {
        const MAX: usize = 256;
        let sb = self.cfg.passes_sub_batch.clamp(1, MAX);
        let n = self.n;
        let count = out.len();
        let nsub = count.div_ceil(sb);
        // Three rotating sub-batch buffers.
        let mut keys = [[0u64; MAX]; 3];
        let mut lo = [[0u32; MAX]; 3];
        let mut hi = [[0u32; MAX]; 3];
        let range = |k: usize| (k * sb, ((k + 1) * sb).min(count));
        for step in 0..nsub + 2 {
            // Pass 1 on sub-batch `step`: keys, and touch the table entries.
            if step < nsub {
                let (s0, s1) = range(step);
                let hs = &hashes[s0 * L..s1 * L];
                let ks = &mut keys[step % 3];
                for (j, k) in ks[..s1 - s0].iter_mut().enumerate() {
                    *k = key64::<L>(&hs[j * L..]);
                    self.model.prefetch_entry(*k);
                }
            }
            // Pass 2 on sub-batch `step - 1`: windows, prefetch their lines.
            if step >= 1 && step - 1 < nsub {
                let k = step - 1;
                let (s0, s1) = range(k);
                let len = s1 - s0;
                let hs = &hashes[s0 * L..s1 * L];
                let ks = &keys[k % 3];
                let (lo_k, hi_k) = (&mut lo[k % 3], &mut hi[k % 3]);
                self.model
                    .window_batch(&ks[..len], hs, L, n, &mut lo_k[..len], &mut hi_k[..len]);
                for j in 0..len {
                    let (a, b) = (lo_k[j], hi_k[j]);
                    if a < b {
                        self.prefetch_for(ks[j], &hs[j * L..(j + 1) * L], a as usize, b as usize);
                    }
                }
            }
            // Pass 3 on sub-batch `step - 2`: search from cache.
            if step >= 2 {
                let k = step - 2;
                let (s0, s1) = range(k);
                let hs = &hashes[s0 * L..s1 * L];
                let ks = &keys[k % 3];
                let (lo_k, hi_k) = (&lo[k % 3], &hi[k % 3]);
                for j in 0..s1 - s0 {
                    let h = &hs[j * L..(j + 1) * L];
                    out[s0 + j] = self
                        .find_in_prefetched(h, ks[j], lo_k[j] as usize, hi_k[j] as usize)
                        .is_some();
                }
            }
        }
    }

    /// Many interleaved searches, each prefetching its next probe. In
    /// recursive mode a lane's first probes interpolate from the model's
    /// prediction and density (one line per level, shrinking like the square
    /// root of the jump) before bisecting the small remaining bracket.
    fn batch_lanes(&self, hashes: &[u8], out: &mut [bool]) {
        const D: usize = 32;
        /// Interpolation rounds a lane may spend before bisecting.
        const INTERP_ROUNDS: u8 = 6;
        #[derive(Clone, Copy)]
        struct Lane {
            q: usize,
            lo: usize,
            hi: usize,
            mid: usize,
            interp: u8,
            active: bool,
        }
        let interpolate = self.cfg.single == SingleMode::Recursive;
        let count = out.len();
        let mut lanes = [Lane {
            q: 0,
            lo: 0,
            hi: 0,
            mid: 0,
            interp: 0,
            active: false,
        }; D];
        let mut next = 0usize;
        let mut nactive = 0usize;

        let dispatch = |ln: &mut Lane, next: &mut usize, out: &mut [bool]| -> bool {
            while *next < count {
                let q = *next;
                *next += 1;
                let h = &hashes[q * L..(q + 1) * L];
                let k = key64::<L>(h);
                let (lo, hi) = self.model.window(k, h, self.n);
                let (lo, hi) = (lo as usize, hi as usize);
                if lo < hi {
                    let mid = if interpolate && (hi - lo) * L > self.cfg.window_prefetch_bytes {
                        self.model
                            .center(k, h, self.n)
                            .clamp(lo as i64, hi as i64 - 1) as usize
                    } else {
                        lo + ((hi - lo) >> 1)
                    };
                    *ln = Lane {
                        q,
                        lo,
                        hi,
                        mid,
                        interp: if interpolate { INTERP_ROUNDS } else { 0 },
                        active: true,
                    };
                    prefetch(self.ptr_at(ln.mid));
                    return true;
                }
                out[q] = false;
            }
            ln.active = false;
            false
        };

        for ln in lanes.iter_mut() {
            if dispatch(ln, &mut next, out) {
                nactive += 1;
            }
        }

        while nactive > 0 {
            for ln in lanes.iter_mut() {
                if !ln.active {
                    continue;
                }
                let h = &hashes[ln.q * L..(ln.q + 1) * L];
                let probe = &self.data[ln.mid * L..(ln.mid + 1) * L];
                let c = cmp_hash::<L>(probe, h);
                let mut done = false;
                // Next estimate from the model's density, if still interpolating.
                let mut est: Option<usize> = None;
                match c {
                    std::cmp::Ordering::Less => {
                        if ln.interp > 0 {
                            let hk = key64::<L>(h);
                            let d = self.model.delta(hk, hk - key64::<L>(probe), self.n) as usize;
                            est = Some(ln.mid + 1 + d);
                        }
                        ln.lo = ln.mid + 1;
                    }
                    std::cmp::Ordering::Greater => {
                        if ln.interp > 0 {
                            let hk = key64::<L>(h);
                            let d = self.model.delta(hk, key64::<L>(probe) - hk, self.n) as usize;
                            est = Some(ln.mid.saturating_sub(d + 1));
                        }
                        ln.hi = ln.mid;
                    }
                    std::cmp::Ordering::Equal => {
                        out[ln.q] = true;
                        done = true;
                    }
                }
                if !done {
                    if ln.lo < ln.hi {
                        ln.mid = match est {
                            Some(e) if (ln.hi - ln.lo) * L > self.cfg.window_prefetch_bytes => {
                                ln.interp -= 1;
                                e.clamp(ln.lo, ln.hi - 1)
                            }
                            _ => {
                                ln.interp = 0;
                                ln.lo + ((ln.hi - ln.lo) >> 1)
                            }
                        };
                        prefetch(self.ptr_at(ln.mid));
                        continue;
                    }
                    out[ln.q] = false;
                }
                nactive -= 1;
                ln.active = false;
                if dispatch(ln, &mut next, out) {
                    nactive += 1;
                }
            }
        }
    }
}

impl<const L: usize, M: Model> Lookup for Strategy<'_, L, M> {
    fn hash_length(&self) -> usize {
        L
    }

    fn len(&self) -> usize {
        self.n as usize
    }

    #[inline]
    fn contains(&self, hash: &[u8]) -> bool {
        self.find(hash).is_some()
    }

    #[inline]
    fn find(&self, hash: &[u8]) -> Option<usize> {
        debug_assert!(hash.len() >= L);
        let hk = key64::<L>(hash);
        let (lo, hi) = self.model.window(hk, hash, self.n);
        self.find_in(hash, hk, lo as usize, hi as usize)
    }

    fn equal_range(&self, hash: &[u8]) -> Range<usize> {
        let Some(first) = self.find(hash) else {
            return 0..0;
        };
        let mut end = first + 1;
        while end < self.n as usize
            && cmp_hash::<L>(&self.data[end * L..(end + 1) * L], hash).is_eq()
        {
            end += 1;
        }
        first..end
    }

    fn contains_batch(&self, hashes: &[u8], out: &mut [bool]) {
        assert_eq!(hashes.len(), out.len() * L, "hashes/out length mismatch");
        if out.len() < 4 {
            for (i, o) in out.iter_mut().enumerate() {
                *o = self.contains(&hashes[i * L..(i + 1) * L]);
            }
        } else if self.passes_batch {
            self.batch_passes(hashes, out);
        } else if self.staged_batch {
            self.batch_staged(hashes, out);
        } else {
            self.batch_lanes(hashes, out);
        }
    }

    fn window(&self, hash: &[u8]) -> Range<usize> {
        let (lo, hi) = self.model.window(key64::<L>(hash), hash, self.n);
        lo as usize..hi as usize
    }

    fn describe(&self) -> String {
        format!(
            "{} ({}-byte hashes, {:?} single, {} batch, region radius {})",
            self.model.describe(),
            L,
            self.cfg.single,
            if self.passes_batch {
                "passes"
            } else if self.staged_batch {
                "staged"
            } else {
                "lane"
            },
            self.region_radius
        )
    }

    fn table_bytes(&self) -> usize {
        self.model.table_bytes()
    }
}

/// Binary search for hashes of a length without a dedicated specialisation.
#[derive(Debug)]
pub struct DynBasic<'a> {
    data: &'a [u8],
    hlen: usize,
}

impl<'a> DynBasic<'a> {
    pub fn new(data: &'a [u8], hlen: usize) -> Self {
        assert!(hlen > 0 && data.len().is_multiple_of(hlen));
        DynBasic { data, hlen }
    }

    fn lower_bound(&self, hash: &[u8]) -> usize {
        let n = self.len();
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.at(mid) < &hash[..self.hlen] {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    fn at(&self, i: usize) -> &[u8] {
        &self.data[i * self.hlen..(i + 1) * self.hlen]
    }
}

impl Lookup for DynBasic<'_> {
    fn hash_length(&self) -> usize {
        self.hlen
    }

    fn len(&self) -> usize {
        self.data.len() / self.hlen
    }

    fn contains(&self, hash: &[u8]) -> bool {
        self.find(hash).is_some()
    }

    fn find(&self, hash: &[u8]) -> Option<usize> {
        let i = self.lower_bound(hash);
        (i < self.len() && self.at(i) == &hash[..self.hlen]).then_some(i)
    }

    fn equal_range(&self, hash: &[u8]) -> Range<usize> {
        let Some(first) = self.find(hash) else {
            return 0..0;
        };
        let mut end = first + 1;
        while end < self.len() && self.at(end) == &hash[..self.hlen] {
            end += 1;
        }
        first..end
    }

    fn contains_batch(&self, hashes: &[u8], out: &mut [bool]) {
        assert_eq!(hashes.len(), out.len() * self.hlen);
        for (i, o) in out.iter_mut().enumerate() {
            *o = self.contains(&hashes[i * self.hlen..(i + 1) * self.hlen]);
        }
    }

    fn window(&self, _hash: &[u8]) -> Range<usize> {
        0..self.len()
    }

    fn describe(&self) -> String {
        format!("generic binary search ({}-byte hashes)", self.hlen)
    }

    fn table_bytes(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::model::{FlatBlocks, Full};

    /// `n` 16-byte hashes whose primary keys are given by `key(i)` and
    /// whose tails hold `i`, so they are sorted and distinct.
    fn hashes16(n: usize, key: impl Fn(usize) -> u64) -> Vec<u8> {
        (0..n)
            .flat_map(|i| {
                let mut h = [0u8; 16];
                h[..8].copy_from_slice(&key(i).to_be_bytes());
                h[8..].copy_from_slice(&(i as u64).to_be_bytes());
                h
            })
            .collect()
    }

    fn recursive(cfg: SearchConfig) -> SearchConfig {
        SearchConfig {
            single: SingleMode::Recursive,
            ..cfg
        }
    }

    #[test]
    fn debug_shows_the_strategy() {
        let s = Strategy::<8, _>::new(&[0u8; 8], Full, SearchConfig::default());
        let d = format!("{s:?}");
        assert!(d.starts_with("Strategy { hash_length: 8, count: 1,"), "{d}");
    }

    #[test]
    fn staged_batch_needs_small_windows() {
        let one = [0u8; 8];
        let full = Strategy::<8, _>::new(&one, Full, SearchConfig::default());
        assert!(!full.uses_staged_batch());
        let flat = FlatBlocks {
            bits: 0,
            table: vec![(0, 0)],
        };
        let flat = Strategy::<8, _>::new(&one, flat, SearchConfig::default());
        assert!(flat.uses_staged_batch());
    }

    #[test]
    fn region_radius_is_the_clamped_residual_quantile() {
        let zeros = |n: usize| vec![0u8; 8 * n];
        // 49 zero keys predicted at 0 (residuals 0..=48) and one all-ones
        // key predicted at 49 (residual 0). The 90 % quantile of 50
        // sorted residuals is element 44, i.e. 43; the clamp for 8-byte
        // hashes and 2048-byte regions is [64 / 8 + 1, 2048 / 2 / 8] = [9, 128].
        let mut data = zeros(50);
        data[49 * 8..].fill(0xff);
        let wide = SearchConfig {
            region_bytes: 2048,
            ..SearchConfig::default()
        };
        assert_eq!(Strategy::<8, _>::new(&data, Full, wide).region_radius(), 43);
        // 50 zero keys: quantile 44, clamped to 512 / 2 / 8 = 32.
        let cfg = SearchConfig::default();
        let data = zeros(50);
        assert_eq!(Strategy::<8, _>::new(&data, Full, cfg).region_radius(), 32);
        // One key: quantile 0, clamped up to one cache line plus one, 9.
        let data = zeros(1);
        assert_eq!(Strategy::<8, _>::new(&data, Full, cfg).region_radius(), 9);
    }

    #[test]
    fn recursive_search_steps_past_a_run_of_zero_keys() {
        // 100 hashes with primary key 0. A query with key 1 lands left of
        // everything it is compared with, so each level re-aims from a
        // region whose last key is 0.
        let data = hashes16(100, |_| 0);
        let s = Strategy::<16, _>::new(&data, Full, recursive(SearchConfig::default()));
        let mut q = [0u8; 16];
        q[7] = 1;
        assert_eq!(s.find(&q), None);
        assert_eq!(s.find(&data[50 * 16..51 * 16]), Some(50));
    }

    /// A corrupt flat hint whose window starts at index 2 for every key.
    /// The data's keys are all above the all-zero query, so the search
    /// keeps re-aiming left and must stop at the window, not below it.
    #[test]
    fn recursive_search_stays_inside_a_corrupt_window() {
        let data = hashes16(100, |i| (i as u64 + 1) << 40);
        let flat = FlatBlocks {
            bits: 0,
            table: vec![(2, 1000)],
        };
        let s = Strategy::<16, _>::new(&data, flat, recursive(SearchConfig::default()));
        assert_eq!(s.find(&[0u8; 16]), None);
        assert_eq!(s.find(&data[50 * 16..51 * 16]), Some(50));
    }

    /// A corrupt flat hint centred near 2^60 with an unbounded region
    /// budget: the level-1 radius is about 2^59, and the region around
    /// the last index must not overflow.
    #[test]
    fn recursive_search_survives_a_huge_region_radius() {
        let data = hashes16(64, |i| (i as u64 + 1) << 40);
        let flat = FlatBlocks {
            bits: 0,
            table: vec![(-(1 << 62), (1 << 62) + (1 << 61))],
        };
        let cfg = SearchConfig {
            region_bytes: usize::MAX,
            window_prefetch_bytes: 0,
            ..recursive(SearchConfig::default())
        };
        let s = Strategy::<16, _>::new(&data, flat, cfg);
        for i in [0, 31, 63] {
            assert_eq!(s.find(&data[i * 16..(i + 1) * 16]), Some(i));
        }
    }
}
