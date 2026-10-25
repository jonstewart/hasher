//! `hset::tlsh` kNN search: the header-cost visiting order
//! (`test_tlsh_header_order.cpp`), the top-k collector, brute-force search
//! against a naive oracle and the reference digests
//! (`test_hset_tlsh.cpp`), and the cell-index search against brute force
//! (`test_tlsh_cell_search.cpp`).

use hset::tlsh::knn::{TlshMatch, TopK};

fn m(distance: u32, index: u64) -> TlshMatch {
    TlshMatch { index, distance }
}

#[test]
fn matches_order_by_distance_then_index() {
    // distance decides first, whatever the indexes
    assert!(m(1, 9) < m(2, 0));
    assert!(m(2, 0) > m(1, 9));
    // equal distance: ascending index
    assert!(m(5, 3) < m(5, 4));
    let mut v = vec![m(7, 1), m(3, 8), m(7, 0), m(3, 2)];
    v.sort();
    assert_eq!(v, vec![m(3, 2), m(3, 8), m(7, 0), m(7, 1)]);
}

#[test]
fn top_k_keeps_the_k_nearest_within_a_shrinking_bound() {
    let mut top = TopK::new(2, 10);
    assert_eq!(top.bound(), 10);
    assert!(top.offer(m(5, 0)));
    // beyond max_distance, even with room left
    assert!(!top.offer(m(11, 1)));
    // max_distance itself is inclusive
    assert!(top.offer(m(10, 2)));
    // full: the bound is the worst kept distance
    assert_eq!(top.bound(), 10);
    assert!(top.offer(m(3, 3)));
    assert_eq!(top.bound(), 5);
    // equal to the worst kept (5, 0) but a later index: not nearer
    assert!(!top.offer(m(5, 4)));
    assert!(top.offer(m(4, 5)));
    assert_eq!(top.bound(), 4);
    assert_eq!(top.into_sorted(), vec![m(3, 3), m(4, 5)]);
}

#[test]
fn top_k_takes_an_equal_distance_at_a_lower_index_out_of_order() {
    // indexed searches visit rows out of index order: (4, 2) must displace
    // (4, 7) because it is nearer in (distance, index)
    let mut top = TopK::new(1, 100);
    assert!(top.offer(m(4, 7)));
    assert!(top.offer(m(4, 2)));
    assert!(!top.offer(m(4, 3)));
    assert_eq!(top.into_sorted(), vec![m(4, 2)]);
}

#[test]
fn top_k_of_zero_keeps_nothing() {
    let mut top = TopK::new(0, 100);
    assert!(!top.offer(m(0, 0)));
    assert_eq!(top.into_sorted(), vec![]);
}

#[test]
fn top_k_below_k_keeps_everything_within_the_bound_sorted() {
    let mut top = TopK::new(10, 50);
    for (d, i) in [(30, 4), (7, 9), (51, 1), (30, 2), (0, 8)] {
        top.offer(m(d, i));
    }
    // never filled: the bound stays max_distance
    assert_eq!(top.bound(), 50);
    assert_eq!(
        top.into_sorted(),
        vec![m(0, 8), m(7, 9), m(30, 2), m(30, 4)]
    );
}
