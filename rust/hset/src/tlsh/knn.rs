//! Exact brute-force TLSH k-nearest-neighbour search over sorted rows
//! (`tlsh_search.cpp`), the reference every indexed search must equal.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use super::digest::{DIGEST_LENGTH, TlshDigest};
use super::CELL_COUNT;
use super::distance::{BodyQuery, l_cost, mod_diff, q_cost};
use super::order::HeaderOrder;

/// Offset of the checksum byte in a canonical row (see [`super::digest`]).
const CHECKSUM: usize = 34;

/// One kNN hit: a row of the searched section and its TLSH distance from
/// the query (C `SFHASH_TlshMatch`).
///
/// Matches order by `(distance, index)`, nearest first with ties broken
/// by ascending row index. That is a total order, so every search strategy
/// returns the same list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TlshMatch {
    /// Row index in the section's sorted rows.
    pub index: u64,
    /// TLSH distance from the query.
    pub distance: u32,
}

impl Ord for TlshMatch {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.distance, self.index).cmp(&(other.distance, other.index))
    }
}

impl PartialOrd for TlshMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Work counters an indexed search adds to (C++ `TlshKnnStats`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KnnStats {
    /// Nonempty header cells visited.
    pub cells: u64,
    /// IVF lists whose bound was evaluated (0 for the cell search).
    pub lists: u64,
    /// Rows whose distance was computed.
    pub rows: u64,
}

/// The k nearest matches offered so far and the distance bound they imply:
/// the top-k collector every TLSH kNN search shares (the heap and `tau`
/// of `tlsh_knn_brute`, `tlsh_knn_cells` and `tlsh_knn_ivf`).
///
/// A match is kept when its distance is at most [`bound`](Self::bound)
/// and either fewer than k are held or it is nearer, in
/// [`TlshMatch`] order, than the worst one held, which it then replaces.
/// The bound starts at `max_distance`; once k are held it is the worst
/// held distance, so it only shrinks. A search may skip any candidate
/// whose distance (or lower bound on it) exceeds `bound()`.
///
/// The kept set depends only on the multiset of offers, not their order,
/// because the replacement test is the total `(distance, index)` order:
/// rows may be offered in any order, as the indexed searches do.
#[derive(Clone, Debug)]
pub struct TopK {
    k: usize,
    /// Inclusive bound on useful distances.
    tau: u32,
    /// Max-heap: the worst kept match on top.
    heap: BinaryHeap<TlshMatch>,
}

impl TopK {
    /// An empty collector for at most `k` matches within `max_distance`
    /// (inclusive). With `k == 0` nothing is ever kept.
    pub fn new(k: usize, max_distance: u32) -> Self {
        Self {
            k,
            tau: max_distance,
            heap: BinaryHeap::with_capacity(k.min(1024) + 1),
        }
    }

    /// The inclusive bound on distances still worth offering.
    #[inline]
    pub fn bound(&self) -> u32 {
        self.tau
    }

    /// Offer a match; true if it was kept.
    #[inline]
    pub fn offer(&mut self, m: TlshMatch) -> bool {
        if m.distance > self.tau || self.k == 0 {
            return false;
        }
        if self.heap.len() < self.k {
            self.heap.push(m);
        } else {
            let mut top = self.heap.peek_mut().expect("k > 0 matches held");
            if m >= *top {
                return false;
            }
            *top = m;
        }
        if self.heap.len() == self.k {
            self.tau = self.heap.peek().expect("k > 0 matches held").distance;
        }
        true
    }

    /// The kept matches, nearest first.
    pub fn into_sorted(self) -> Vec<TlshMatch> {
        self.heap.into_sorted_vec()
    }
}

/// Brute-force k nearest neighbours of `q` among `rows` by TLSH distance
/// (C++ `tlsh_knn_brute`): up to `k` matches with distance at most
/// `max_distance`, nearest first, ties by ascending row index.
///
/// Empty when `k == 0`, `q` is null, or there are no rows. Rows are not
/// checked: a null row gets its header-plus-body distance like any other,
/// as in C++ (a loaded TLSH section never holds one).
pub fn knn_brute(
    rows: &[[u8; DIGEST_LENGTH]],
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
) -> Vec<TlshMatch> {
    if k == 0 || rows.is_empty() || q.is_null() {
        return Vec::new();
    }

    // per-query header cost tables indexed by a row's L and Q bytes
    let mut l_costs = [0u32; 256];
    let mut q_costs = [0u32; 256];
    for v in 0..256u32 {
        if include_length {
            l_costs[v as usize] = l_cost(mod_diff(v, q.l().into(), 256));
        }
        q_costs[v as usize] = q_cost(mod_diff(v >> 4, q.q1().into(), 16))
            + q_cost(mod_diff(v & 0x0F, q.q2().into(), 16));
    }
    let body = BodyQuery::new(q);
    let checksum = q.checksum();

    let mut top = TopK::new(k, max_distance);
    for (i, r) in rows.iter().enumerate() {
        let header = l_costs[usize::from(r[0])]
            + q_costs[usize::from(r[1])]
            + u32::from(r[CHECKSUM] != checksum);
        if header > top.bound() {
            continue;
        }
        top.offer(TlshMatch {
            index: i as u64,
            distance: header + body.body(r),
        });
    }
    top.into_sorted()
}

/// Exact k nearest neighbours using the cell index (C++ `tlsh_knn_cells`,
/// `tlsh_cell_search.cpp`): cells are visited in [`HeaderOrder`], the L
/// loop stops at the first L cost above the current bound and the Q loop
/// at the first header cost above it, and within a cell only the checksum
/// and body kernel run. Returns exactly what [`knn_brute`] returns.
///
/// `cells` is the 65,537-entry prefix-sum cell index of the sorted `rows`
/// (the `0x7400` HINT payload): rows of cell `c` are
/// `rows[cells[c]..cells[c + 1]]`. `stats`, when given, is added to:
/// `cells` counts nonempty cells visited and `rows` their rows.
///
/// # Panics
///
/// If `cells` does not have [`CELL_COUNT`] + 1 entries, or an entry the
/// search reaches is decreasing or beyond `rows`. A cell index parsed by
/// [`super::cells`] has been checked against its rows.
pub fn knn_cells(
    rows: &[[u8; DIGEST_LENGTH]],
    cells: &[u64],
    q: &TlshDigest,
    k: usize,
    max_distance: u32,
    include_length: bool,
    mut stats: Option<&mut KnnStats>,
) -> Vec<TlshMatch> {
    assert_eq!(cells.len(), CELL_COUNT + 1, "cell index length");
    if k == 0 || q.is_null() {
        return Vec::new();
    }

    let order = HeaderOrder::new(q, include_length);
    let body = BodyQuery::new(q);
    let checksum = q.checksum();
    let mut top = TopK::new(k, max_distance);

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
            let (lb, le) = (cells[c] as usize, cells[c + 1] as usize);
            if lb == le {
                continue;
            }
            if let Some(s) = stats.as_deref_mut() {
                s.cells += 1;
                s.rows += (le - lb) as u64;
            }
            for (i, r) in rows[lb..le].iter().enumerate() {
                top.offer(TlshMatch {
                    index: (lb + i) as u64,
                    distance: ch + u32::from(r[CHECKSUM] != checksum) + body.body(r),
                });
            }
        }
    }
    top.into_sorted()
}
