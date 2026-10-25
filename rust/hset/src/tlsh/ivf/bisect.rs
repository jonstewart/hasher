//! The BISECT builder of TIVF indexes (`build_tlsh_ivf`).

use super::{DEFAULT_SEED, FLAT_MAX, TARGET_LIST_SIZE, TlshIvf};
use crate::error::{Error, Result};
use crate::tlsh::CELL_COUNT;
use crate::tlsh::digest::{DIGEST_LENGTH, TlshDigest};
use crate::tlsh::distance::BodyQuery;
use crate::tlsh::embed::{EMBED_BODY_DIMS, embed_body_i8};
use crate::tlsh::mt64::Mt19937_64;

/// A raw 36-byte row of a TLSH section.
type Row = [u8; DIGEST_LENGTH];

/// Options of [`build_tlsh_ivf`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IvfBuildOptions {
    /// The clustering target `T`: lists hold about this many rows.
    pub target_list_size: usize,
    /// Seed of the random draws.
    pub seed: u64,
    /// Threads to cluster cells on; 0 = available parallelism.
    pub threads: usize,
}

impl Default for IvfBuildOptions {
    fn default() -> Self {
        Self {
            target_list_size: TARGET_LIST_SIZE,
            seed: DEFAULT_SEED,
            threads: 0,
        }
    }
}

/// Whether the squared distance `big_a / n_a^2` is strictly smaller than
/// `big_b / n_b^2`, compared exactly as `big_a * n_b^2 < big_b * n_a^2`
/// (C++ `tlsh_ivf_nearer`).
///
/// In the flat k-means the squared distance from a row `x` to a centroid
/// of `n` members with coordinate sum `S` is `||x - S / n||^2 = N / n^2`,
/// `N = ||n x - S||^2`. With `x` and every member in `{-1, 0, 1}^256`,
/// `|n x_j - S_j| <= 2n`, so `N <= 2^10 n^2`; for `n <= FLAT_MAX = 2^12`
/// both products are at most `2^58`. Beyond that range the products wrap,
/// as the C++ `uint64_t` products do.
pub const fn nearer(big_a: u64, n_a: u64, big_b: u64, n_b: u64) -> bool {
    big_a.wrapping_mul(n_b).wrapping_mul(n_b) < big_b.wrapping_mul(n_a).wrapping_mul(n_a)
}

// The products of `nearer` stay in 64 bits for nodes of up to 2^13 rows
// (2^10 * 2^26 * 2^26 = 2^62), as C++'s static_assert requires.
const _: () = assert!(super::FLAT_MAX <= 8192);

/// The lists of one cell: per list its medoid, radius2 and size, and the
/// members concatenated (row indexes of the whole section, ascending
/// within a list).
#[derive(Default)]
struct CellLists {
    medoids: Vec<TlshDigest>,
    radius2: Vec<u32>,
    sizes: Vec<u32>,
    ids: Vec<u32>,
}

/// Build the BISECT index over sorted rows.
pub fn build_tlsh_ivf(rows: &[Row], opts: &IvfBuildOptions) -> Result<TlshIvf> {
    if opts.target_list_size == 0 {
        return Err(Error::input("target_list_size must be positive"));
    }
    let n = rows.len() as u64;
    if n > u64::from(u32::MAX) {
        return Err(Error::input("too many rows for a TIVF index"));
    }
    let cells = cell_bounds(rows)?;
    let nonempty: Vec<usize> = (0..CELL_COUNT)
        .filter(|&c| cells[c] != cells[c + 1])
        .collect();

    let results: Vec<CellLists> = nonempty
        .iter()
        .map(|&c| {
            let mut rng = Mt19937_64::new(opts.seed ^ (c as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            bisect_cell(
                &rows[cells[c]..cells[c + 1]],
                cells[c] as u32,
                opts.target_list_size,
                &mut rng,
            )
        })
        .collect();

    // concatenate in cell order
    let mut ivf = TlshIvf {
        n,
        cell_lists: vec![0; CELL_COUNT + 1],
        medoids: Vec::new(),
        radius2: Vec::new(),
        list_start: vec![0],
        ids: Vec::with_capacity(rows.len()),
    };
    let mut ri = 0;
    for c in 0..CELL_COUNT {
        ivf.cell_lists[c] = ivf.lists() as u32;
        if nonempty.get(ri) == Some(&c) {
            let r = &results[ri];
            ri += 1;
            ivf.medoids.extend_from_slice(&r.medoids);
            ivf.radius2.extend_from_slice(&r.radius2);
            for &sz in &r.sizes {
                let last = *ivf.list_start.last().expect("list_start starts at 0");
                ivf.list_start.push(last + u64::from(sz));
            }
            ivf.ids.extend_from_slice(&r.ids);
        }
    }
    ivf.cell_lists[CELL_COUNT] = ivf.lists() as u32;
    Ok(ivf)
}

/// The start of each cell's rows in sorted `rows`, `CELL_COUNT + 1`
/// entries (C++ `make_tlsh_cell_index`, whose sortedness check it keeps).
fn cell_bounds(rows: &[Row]) -> Result<Vec<usize>> {
    let mut cells = vec![0usize; CELL_COUNT + 1];
    for (i, r) in rows.iter().enumerate() {
        if i > 0 && r < &rows[i - 1] {
            return Err(Error::input("TLSH rows are not sorted"));
        }
        cells[usize::from(TlshDigest(*r).cell()) + 1] += 1;
    }
    for c in 1..=CELL_COUNT {
        cells[c] += cells[c - 1];
    }
    Ok(cells)
}

/// A pivot split leaving fewer than `1 / MIN_SIDE_DIVISOR` of a node's
/// rows on one side is replaced by a median split; this bounds the depth
/// by `log_{8/7} m` and guarantees termination (C++
/// `BISECT_MIN_SIDE_DIVISOR`). A quality knob only.
const MIN_SIDE_DIVISOR: usize = 8;

/// The flat k-means of a node stops after this many update and
/// reassignment rounds if assignments still change (C++
/// `BISECT_KMEANS_MAX_ITERATIONS`). A quality and build-cost knob only.
const KMEANS_MAX_ITERATIONS: usize = 10;

/// The partition of one cell's rows into lists (C++ `CellBisector`). `perm`
/// holds the cell's local row indexes; a node is a range `lo..hi` of
/// `perm`, rearranged in place, so the lists are contiguous ranges of
/// `perm` in depth-first order. Integer arithmetic only.
struct CellBisector<'a> {
    rows: &'a [Row],
    perm: Vec<u32>,
    target: usize,
    rng: &'a mut Mt19937_64,
    /// Scratch of `cluster`: the node's members (local row indexes).
    node: Vec<u32>,
    /// Seeds, as positions in `node`.
    seeds: Vec<u32>,
    /// Each member's squared distance to the nearest seed so far.
    best: Vec<u32>,
    /// Each member's centroid. Kept across nodes, as in C++; only the
    /// ignored "changed" result of the first assignment can see stale
    /// entries.
    of: Vec<u32>,
    /// Positions in `node` grouped by list, list `l` at
    /// `members[start[l]..start[l + 1]]`.
    members: Vec<u32>,
    start: Vec<usize>,
    /// The members' body embeddings and their squared norms.
    emb: Vec<[i8; EMBED_BODY_DIMS]>,
    norm2: Vec<u32>,
    /// Per centroid: coordinate sum `S`, member count `n`, `||S||^2`.
    sum: Vec<[i32; EMBED_BODY_DIMS]>,
    cnt: Vec<u32>,
    sum2: Vec<i64>,
}

impl<'a> CellBisector<'a> {
    fn new(rows: &'a [Row], target: usize, rng: &'a mut Mt19937_64) -> Self {
        Self {
            rows,
            perm: (0..rows.len() as u32).collect(),
            target,
            rng,
            node: Vec::new(),
            seeds: Vec::new(),
            best: Vec::new(),
            of: Vec::new(),
            members: Vec::new(),
            start: Vec::new(),
            emb: Vec::new(),
            norm2: Vec::new(),
            sum: Vec::new(),
            cnt: Vec::new(),
            sum2: Vec::new(),
        }
    }

    /// The lists as `lo..hi` ranges of `perm`, in depth-first order.
    fn leaves(&mut self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        self.split(0, self.perm.len(), &mut out);
        out
    }

    /// Node `lo..hi`: clustered flat if it has at most [`FLAT_MAX`] rows,
    /// else split in two and each half recursed into, the lower first
    /// (depth-first, which fixes the order of the RNG draws).
    fn split(&mut self, lo: usize, hi: usize, out: &mut Vec<(usize, usize)>) {
        if hi - lo <= FLAT_MAX {
            self.cluster(lo, hi, out);
            return;
        }
        let mid = self.partition(lo, hi);
        self.split(lo, mid, out);
        self.split(mid, hi, out);
    }

    /// Split node `lo..hi` in two in place and return the boundary: pivots
    /// `a`, the member farthest from a random member, and `b`, the member
    /// farthest from `a`; the members nearer `a` (ties to `a`) go first,
    /// stably. A split leaving fewer than `1 / MIN_SIDE_DIVISOR` of the
    /// node on one side is replaced by [`median_split`](Self::median_split).
    fn partition(&mut self, lo: usize, hi: usize) -> usize {
        let at = lo + self.draw(hi - lo);
        let p0 = self.perm[at];
        let a = self.farthest(lo, hi, p0);
        let b = self.farthest(lo, hi, a);
        let mid = self.assign(lo, hi, a, b);
        if (mid - lo).min(hi - mid) * MIN_SIDE_DIVISOR < hi - lo {
            return self.median_split(lo, hi, a);
        }
        mid
    }

    /// The member of `lo..hi` farthest from row `p`, ties by the smaller
    /// local index; `p` itself (at distance 0) when every member is at
    /// distance 0 and none has a smaller index.
    fn farthest(&self, lo: usize, hi: usize, p: u32) -> u32 {
        let q = BodyQuery::new(&TlshDigest(self.rows[p as usize]));
        let (mut best, mut best_d) = (p, 0);
        for &id in &self.perm[lo..hi] {
            let d = q.emb_body(&self.rows[id as usize]);
            if d > best_d || (d == best_d && id < best) {
                best = id;
                best_d = d;
            }
        }
        best
    }

    /// Move the members of `lo..hi` nearer `a` than `b` (ties to `a`) to
    /// the front, stably (`std::stable_partition`); returns the end of
    /// `a`'s side.
    fn assign(&mut self, lo: usize, hi: usize, a: u32, b: u32) -> usize {
        let qa = BodyQuery::new(&TlshDigest(self.rows[a as usize]));
        let qb = BodyQuery::new(&TlshDigest(self.rows[b as usize]));
        let rows = self.rows;
        let (near_a, near_b): (Vec<u32>, Vec<u32>) =
            self.perm[lo..hi].iter().partition(|&&id| {
                let r = &rows[id as usize];
                qa.emb_body(r) <= qb.emb_body(r)
            });
        let mid = lo + near_a.len();
        self.perm[lo..mid].copy_from_slice(&near_a);
        self.perm[mid..hi].copy_from_slice(&near_b);
        mid
    }

    /// Sort `lo..hi` by (distance to `a`, local index) and cut it in half:
    /// the fallback when the pivots split off too few rows (or none, when
    /// every body in the node is the same), so every split makes progress.
    fn median_split(&mut self, lo: usize, hi: usize, a: u32) -> usize {
        let q = BodyQuery::new(&TlshDigest(self.rows[a as usize]));
        let mut keyed: Vec<(u32, u32)> = self.perm[lo..hi]
            .iter()
            .map(|&id| (q.emb_body(&self.rows[id as usize]), id))
            .collect();
        keyed.sort_unstable();
        for (p, (_, id)) in self.perm[lo..hi].iter_mut().zip(keyed) {
            *p = id;
        }
        lo + (hi - lo) / 2
    }

    /// A draw in `0..n` straight from the engine (`rng() % n`): the C++
    /// standard distributions are implementation-defined, the engine is
    /// not.
    fn draw(&mut self, n: usize) -> usize {
        (self.rng.next_u64() % n as u64) as usize
    }

    /// The flat clustering of node `lo..hi` into at most `ceil(s / T)`
    /// lists by k-means over exact integer centroids: k-means++ seeding,
    /// every member assigned to its nearest centroid (ties to the smaller
    /// centroid index), then rounds of recomputing the centroids and
    /// reassigning until no assignment changes. The node's range of `perm`
    /// is rearranged so each nonempty list is contiguous, in centroid
    /// order; empty lists are dropped.
    fn cluster(&mut self, lo: usize, hi: usize, out: &mut Vec<(usize, usize)>) {
        let s = hi - lo;
        let k = s.div_ceil(self.target);
        if k <= 1 {
            out.push((lo, hi));
            return;
        }
        self.node.clear();
        self.node.extend_from_slice(&self.perm[lo..hi]);
        self.embed_node();
        self.seed_rows(k);
        self.seed_centroids();
        self.assign_nearest();
        for _ in 0..KMEANS_MAX_ITERATIONS {
            self.update_centroids();
            if !self.assign_nearest() {
                break;
            }
        }

        self.group_by_list();
        for l in 0..self.cnt.len() {
            if self.start[l] != self.start[l + 1] {
                out.push((lo + self.start[l], lo + self.start[l + 1]));
            }
        }
        for i in 0..s {
            self.perm[lo + i] = self.node[self.members[i] as usize];
        }
    }

    /// `members` = the positions in `node` grouped by list, ascending
    /// within a list; list `l` is `members[start[l]..start[l + 1]]`.
    fn group_by_list(&mut self) {
        self.start.clear();
        self.start.resize(self.cnt.len() + 1, 0);
        for &l in &self.of {
            self.start[l as usize + 1] += 1;
        }
        for l in 1..self.start.len() {
            self.start[l] += self.start[l - 1];
        }
        self.members.resize(self.node.len(), 0);
        let mut at: Vec<usize> = self.start[..self.start.len() - 1].to_vec();
        for (i, &l) in self.of.iter().enumerate() {
            self.members[at[l as usize]] = i as u32;
            at[l as usize] += 1;
        }
    }

    /// k-means++ seeding over `node`: the first seed a random member,
    /// each next one a member drawn with probability proportional to its
    /// squared distance to the nearest seed so far (`best`). When every
    /// member coincides with a seed's body there are fewer than `k`
    /// distinct bodies and seeding stops early.
    fn seed_rows(&mut self, k: usize) {
        let s = self.node.len();
        let first = self.draw(s) as u32;
        self.seeds.clear();
        self.seeds.push(first);
        self.best.resize(s, 0);
        let q = BodyQuery::new(&TlshDigest(self.rows[self.node[first as usize] as usize]));
        for (b, &id) in self.best.iter_mut().zip(&self.node) {
            *b = q.emb_body(&self.rows[id as usize]);
        }
        while self.seeds.len() < k {
            let sum: u64 = self.best.iter().map(|&b| u64::from(b)).sum();
            if sum == 0 {
                break;
            }
            // the first member at which the prefix sum of best exceeds r;
            // a member with best 0 (a seed, among others) is never chosen
            let mut r = self.rng.next_u64() % sum;
            let mut next = 0;
            while r >= u64::from(self.best[next]) {
                r -= u64::from(self.best[next]);
                next += 1;
            }
            self.seeds.push(next as u32);
            let q = BodyQuery::new(&TlshDigest(self.rows[self.node[next] as usize]));
            for (b, &id) in self.best.iter_mut().zip(&self.node) {
                *b = (*b).min(q.emb_body(&self.rows[id as usize]));
            }
        }
    }

    /// `emb` and `norm2` of the node's members.
    fn embed_node(&mut self) {
        let s = self.node.len();
        self.emb.resize(s, [0; EMBED_BODY_DIMS]);
        self.norm2.resize(s, 0);
        for i in 0..s {
            self.norm2[i] = embed_body_i8(&self.rows[self.node[i] as usize], &mut self.emb[i]);
        }
    }

    /// Centroid `c` is the seed row `seeds[c]` alone: `(x, 1, ||x||^2)`.
    fn seed_centroids(&mut self) {
        self.sum.clear();
        self.cnt.clear();
        self.sum2.clear();
        for &p in &self.seeds {
            self.sum.push(self.emb[p as usize].map(i32::from));
            self.cnt.push(1);
            self.sum2.push(i64::from(self.norm2[p as usize]));
        }
    }

    /// Recompute every centroid's `(S, n, ||S||^2)` from its members, in
    /// integers, so independent of order. A centroid with no members keeps
    /// its previous values: it may win members back in the next
    /// assignment, and is dropped at the end if still empty.
    fn update_centroids(&mut self) {
        let k = self.cnt.len();
        let mut sum = vec![[0i32; EMBED_BODY_DIMS]; k];
        let mut cnt = vec![0u32; k];
        for (x, &c) in self.emb.iter().zip(&self.of) {
            let s = &mut sum[c as usize];
            for (sj, &xj) in s.iter_mut().zip(x) {
                *sj += i32::from(xj);
            }
            cnt[c as usize] += 1;
        }
        for c in 0..k {
            if cnt[c] == 0 {
                continue;
            }
            self.sum[c] = sum[c];
            self.cnt[c] = cnt[c];
            self.sum2[c] = sum[c].iter().map(|&v| i64::from(v) * i64::from(v)).sum();
        }
    }

    /// `of[i]` = the centroid nearest member `i`, ties to the smaller
    /// index; returns whether any assignment changed. For centroid
    /// `(S, n)`, `N = ||n x - S||^2 = n^2 ||x||^2 - 2n (x . S) + ||S||^2`,
    /// compared exactly by [`nearer`].
    fn assign_nearest(&mut self) -> bool {
        let s = self.node.len();
        self.of.resize(s, u32::MAX);
        let mut changed = false;
        for i in 0..s {
            let x = &self.emb[i];
            let (mut best, mut best_big, mut best_n) = (0u32, 0u64, 0u64);
            for (c, (sc, &nc)) in self.sum.iter().zip(&self.cnt).enumerate() {
                let dot = dot(x, sc);
                let n = i64::from(nc);
                let big = (n * n * i64::from(self.norm2[i]) - 2 * n * i64::from(dot)
                    + self.sum2[c]) as u64;
                if c == 0 || nearer(big, n as u64, best_big, best_n) {
                    best = c as u32;
                    best_big = big;
                    best_n = n as u64;
                }
            }
            changed |= self.of[i] != best;
            self.of[i] = best;
        }
        changed
    }
}

/// `x . s` in `i32` (no overflow: `|s_j| <= FLAT_MAX`).
///
/// The hot loop of the build. A plain indexed loop over fixed-size arrays
/// keeps unoptimized (test) builds several times faster than an iterator
/// chain, and optimizes to the same vector code.
#[inline]
fn dot(x: &[i8; EMBED_BODY_DIMS], s: &[i32; EMBED_BODY_DIMS]) -> i32 {
    let (xs, sx) = (x.as_chunks::<8>().0, s.as_chunks::<8>().0);
    let mut d = 0;
    for j in 0..EMBED_BODY_DIMS / 8 {
        let (x, s) = (&xs[j], &sx[j]);
        d += i32::from(x[0]) * s[0]
            + i32::from(x[1]) * s[1]
            + i32::from(x[2]) * s[2]
            + i32::from(x[3]) * s[3]
            + i32::from(x[4]) * s[4]
            + i32::from(x[5]) * s[5]
            + i32::from(x[6]) * s[6]
            + i32::from(x[7]) * s[7];
    }
    d
}

/// The lists of one cell's rows by coarse bisection and flat integer
/// k-means (C++ `bisect_cell`), each with its exact 1-center; ids written
/// are local indexes plus `base`.
fn bisect_cell(rows: &[Row], base: u32, target: usize, rng: &mut Mt19937_64) -> CellLists {
    let mut bis = CellBisector::new(rows, target, rng);
    let leaves = bis.leaves();
    let mut out = CellLists {
        ids: Vec::with_capacity(rows.len()),
        ..CellLists::default()
    };
    for (lo, hi) in leaves {
        let mut ids = bis.perm[lo..hi].to_vec();
        ids.sort_unstable();
        let (med, r2) = one_center(rows, &ids);
        out.medoids.push(TlshDigest(rows[med as usize]));
        out.radius2.push(r2);
        out.sizes.push(ids.len() as u32);
        out.ids.extend(ids.iter().map(|&id| base + id));
    }
    out
}

/// The exact 1-center of the rows `ids` (local indexes into `rows`,
/// ascending): the member whose largest squared body-embedding distance
/// to the others is smallest, ties by the smaller index. Returns
/// `(medoid, radius2)` (C++ `one_center`).
fn one_center(rows: &[Row], ids: &[u32]) -> (u32, u32) {
    let (mut best, mut best_r) = (ids[0], u32::MAX);
    for &i in ids {
        let q = BodyQuery::new(&TlshDigest(rows[i as usize]));
        let mut r = 0;
        for &j in ids {
            if r > best_r {
                break;
            }
            r = r.max(q.emb_body(&rows[j as usize]));
        }
        if r < best_r || (r == best_r && i < best) {
            best = i;
            best_r = r;
        }
    }
    (best, best_r)
}
