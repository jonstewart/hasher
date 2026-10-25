//! Exact brute-force TLSH k-nearest-neighbour search over sorted rows
//! (`tlsh_search.cpp`), the reference every indexed search must equal.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

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
