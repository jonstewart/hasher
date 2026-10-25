//! `hset::tlsh` kNN search: the header-cost visiting order
//! (`test_tlsh_header_order.cpp`), the top-k collector, brute-force search
//! against a naive oracle and the reference digests
//! (`test_hset_tlsh.cpp`), and the cell-index search against brute force
//! (`test_tlsh_cell_search.cpp`).

use hset::tlsh::knn::TlshMatch;

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
