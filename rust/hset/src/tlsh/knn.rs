//! Exact brute-force TLSH k-nearest-neighbour search over sorted rows
//! (`tlsh_search.cpp`), the reference every indexed search must equal.

use std::cmp::Ordering;

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
