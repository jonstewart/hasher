//! `hset::tlsh::ivf::search`, the exact indexed kNN (C++ `tlsh_knn_ivf`),
//! ported from `test/test_tlsh_ivf.cpp` (index == brute grids, k 1000
//! beyond 144, edge cases) with test-local indexes in place of the BISECT
//! build, plus the list bound and the work counters, derived by hand from
//! `tlsh_ivf.cpp`.

use hset::tlsh::ivf::search::list_bound;

#[test]
fn list_bound_is_the_squared_gap_of_the_roots_less_a_hundredth() {
    // sqrt(100) - sqrt(25) = 5, squared 25, relaxed by 1e-2
    assert_eq!(list_bound(100, 25), 25.0f32 - 0.01f32);
    // query inside the radius: no bound
    assert_eq!(list_bound(25, 100), 0.0);
    assert_eq!(list_bound(49, 49), 0.0);
    assert_eq!(list_bound(0, 0), 0.0);
    // sqrt(1) - sqrt(0) = 1: 1 - 0.01
    assert_eq!(list_bound(1, 0), 1.0f32 - 0.01f32);
    // sqrt(101) - 10 = 0.0499; squared 0.0025 < 0.01: clamped to 0
    assert_eq!(list_bound(101, 100), 0.0);
    // sqrt(400) - sqrt(9) = 17, squared 289
    assert_eq!(list_bound(400, 9), 289.0f32 - 0.01f32);
}
