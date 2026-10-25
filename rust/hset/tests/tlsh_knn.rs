//! `hset::tlsh` kNN search: the header-cost visiting order
//! (`test_tlsh_header_order.cpp`), the top-k collector, brute-force search
//! against a naive oracle and the reference digests
//! (`test_hset_tlsh.cpp`), and the cell-index search against brute force
//! (`test_tlsh_cell_search.cpp`).

use hset::tlsh::TlshDigest;
use hset::tlsh::knn::{KnnStats, TlshMatch, TopK, knn_brute, knn_cells};
use hset::tlsh::order::HeaderOrder;
use hset_testkit::tlsh::{
    Perturbation, corpus, example_digests, naive_cell_index, naive_knn, perturb_corpus, ref_diff,
    sorted_rows,
};
use proptest::prelude::*;

fn m(distance: u32, index: u64) -> TlshMatch {
    TlshMatch { index, distance }
}

fn digest(hex: &str) -> TlshDigest {
    TlshDigest::from_hex(hex).unwrap()
}

/// The TLSH rows of `test_hset_tlsh.cpp`'s fixture: the 80 example digests
/// and digest 7 again, sorted (TNULL and the empty column are absent).
fn example_rows() -> (Vec<TlshDigest>, Vec<[u8; 36]>) {
    let digests: Vec<TlshDigest> = example_digests().iter().map(|h| digest(h)).collect();
    let mut all = digests.clone();
    all.push(digests[7]);
    let rows = sorted_rows(&all);
    (digests, rows)
}

/// The queries of `tlsh_knn_brute_matches_naive_and_reference`: five
/// members, a member with flipped body bits, and a member moved far away
/// in L and Q.
fn example_queries(digests: &[TlshDigest]) -> Vec<TlshDigest> {
    let mut qs: Vec<TlshDigest> = [0, 7, 13, 42, 79].iter().map(|&i| digests[i]).collect();
    // C++ q.lo[2] ^= 0x33; q.hi[9] ^= 0x81 (lo plane at 18, hi at 2)
    let mut b = digests[20].0;
    b[18 + 2] ^= 0x33;
    b[2 + 9] ^= 0x81;
    qs.push(TlshDigest(b));
    // C++ q.L += 100; q.Q ^= 0x77
    let mut b = digests[50].0;
    b[0] = b[0].wrapping_add(100);
    b[1] ^= 0x77;
    qs.push(TlshDigest(b));
    qs
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

fn header(l: u8, q1: u8, q2: u8) -> TlshDigest {
    TlshDigest::from_parts(l, q1, q2, 1, &[0; 128])
}

#[test]
fn header_order_lists_hand_computed_neighbours_first() {
    let o = HeaderOrder::new(&header(77, 3, 9), true);
    // L, L+1, L-1, L+2, L-2, ... at l_cost 0, 1, 1, 24, 24, 36
    assert_eq!(o.l()[..6], [77, 78, 76, 79, 75, 80]);
    assert_eq!(o.l_cost()[..6], [0, 1, 1, 24, 24, 36]);
    // ..., L-127 (= 206) at 12 * 127, and L+128 (= 205) once, last
    assert_eq!((o.l()[254], o.l_cost()[254]), (206, 1524));
    assert_eq!((o.l()[255], o.l_cost()[255]), (205, 1536));

    // (k1, k2) pairs by cost, stable in k1-major order: (0,0) 0; (0,1),
    // (1,0) 1; (1,1) 2; (0,2), (2,0) 12; (1,2), (2,1) 13. Each expands to
    // (q1+k1, q2+k2), (q1+k1, q2-k2), (q1-k1, q2+k2), (q1-k1, q2-k2),
    // dropping repeats when k is 0.
    assert_eq!(
        o.q()[..17],
        [
            0x39, // (0,0)
            0x3A, 0x38, // (0,1)
            0x49, 0x29, // (1,0)
            0x4A, 0x48, 0x2A, 0x28, // (1,1)
            0x3B, 0x37, // (0,2)
            0x59, 0x19, // (2,0)
            0x4B, 0x47, 0x2B, 0x27, // (1,2)
        ]
    );
    assert_eq!(
        o.q_cost()[..17],
        [0, 1, 1, 1, 1, 2, 2, 2, 2, 12, 12, 12, 12, 13, 13, 13, 13]
    );

    // without the length every L costs 0 and the order is 0..=255
    let x = HeaderOrder::new(&header(77, 3, 9), false);
    assert!(x.l().iter().enumerate().all(|(i, &l)| usize::from(l) == i));
    assert!(x.l_cost().iter().all(|&c| c == 0));
    assert_eq!(x.q(), o.q());
}

#[test]
fn header_order_is_a_cost_sorted_permutation() {
    // test_tlsh_header_order.cpp, plus wrap-around corners
    for (l, q1, q2) in [
        (0, 0, 0),
        (255, 15, 15),
        (77, 3, 9),
        (128, 8, 8),
        (1, 15, 0),
    ] {
        let q = header(l, q1, q2);
        for incl in [true, false] {
            let o = HeaderOrder::new(&q, incl);
            let mut ls = o.l().to_vec();
            ls.sort_unstable();
            ls.dedup();
            assert_eq!(ls.len(), 256);
            let mut qs = o.q().to_vec();
            qs.sort_unstable();
            qs.dedup();
            assert_eq!(qs.len(), 256);
            for i in 0..256 {
                let lc = if incl {
                    ref_l_cost(circ(o.l()[i], l, 256))
                } else {
                    0
                };
                assert_eq!(o.l_cost()[i], lc, "{l} {q1} {q2} {incl} l[{i}]");
                let qc = ref_q_cost(circ(o.q()[i] >> 4, q1, 16))
                    + ref_q_cost(circ(o.q()[i] & 0x0F, q2, 16));
                assert_eq!(o.q_cost()[i], qc, "{l} {q1} {q2} {incl} q[{i}]");
                if i > 0 {
                    assert!(o.l_cost()[i - 1] <= o.l_cost()[i]);
                    assert!(o.q_cost()[i - 1] <= o.q_cost()[i]);
                }
            }
            if incl {
                assert_eq!(o.l()[0], l);
            }
            assert_eq!(o.q()[0], (q1 << 4) | q2);
        }
    }
}

// Reference costs written from the TLSH rules, not the crate's tables.

fn circ(x: u8, y: u8, r: u32) -> u32 {
    let d = u32::from(x.abs_diff(y));
    d.min(r - d)
}

fn ref_l_cost(k: u32) -> u32 {
    match k {
        0 => 0,
        1 => 1,
        _ => 12 * k,
    }
}

fn ref_q_cost(k: u32) -> u32 {
    if k <= 1 { k } else { 12 * (k - 1) }
}

#[test]
fn brute_is_empty_for_k_zero_a_null_query_or_no_rows() {
    let (digests, rows) = example_rows();
    let q = digests[0];
    assert_eq!(knn_brute(&rows, &q, 0, 1000, true), vec![]);
    assert_eq!(knn_brute(&rows, &TlshDigest::NULL, 8, 1000, true), vec![]);
    assert_eq!(knn_brute(&[], &q, 5, 1000, true), vec![]);
}

#[test]
fn brute_matches_the_naive_oracle_on_the_reference_digests() {
    let (digests, rows) = example_rows();
    let n = rows.len();
    assert_eq!(n, 81);
    for q in example_queries(&digests) {
        for include_length in [true, false] {
            for k in [0, 1, 2, 5, 10, n, n + 50] {
                for maxd in [0, 1, 30, 100, 200, u32::MAX] {
                    let got = knn_brute(&rows, &q, k, maxd, include_length);
                    let want = naive_knn(&rows, &q, k, maxd, include_length);
                    assert_eq!(got, want, "q {q} k {k} maxd {maxd} incl {include_length}");
                    for w in got.windows(2) {
                        assert!(w[0] < w[1]);
                    }
                    for hit in &got {
                        let row = TlshDigest(rows[hit.index as usize]);
                        assert_eq!(ref_diff(&q, &row, include_length), Some(hit.distance));
                        assert!(hit.distance <= maxd);
                    }
                }
            }
        }
    }
}

#[test]
fn brute_finds_a_duplicated_member_twice_at_distance_zero() {
    let (digests, rows) = example_rows();
    let q = digests[7];
    let got = knn_brute(&rows, &q, 3, 0, true);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].distance, 0);
    assert_eq!(got[1].distance, 0);
    assert_eq!(got[0].index + 1, got[1].index);
    assert_eq!(rows[got[0].index as usize], q.0);
    assert_eq!(rows[got[1].index as usize], q.0);
}

/// A seeded corpus of `n` rows and a query near (or equal to) one of them,
/// or a fresh random digest when `n` is 0 or `near` is false.
fn corpus_and_query(seed: u64, n: usize, near: bool, pick: usize) -> (Vec<[u8; 36]>, TlshDigest) {
    let mut c = corpus(seed, n + 1);
    let fresh = c.pop().expect("n + 1 digests");
    let rows = sorted_rows(&c);
    let q = if near && !rows.is_empty() {
        let mut b = rows[pick % rows.len()];
        b[2 + pick % 16] ^= 1 << (pick % 8);
        TlshDigest(b)
    } else {
        fresh
    };
    (rows, q)
}

proptest! {
    #[test]
    fn brute_equals_the_naive_oracle(
        seed in any::<u64>(),
        n in 0usize..400,
        near in any::<bool>(),
        pick in any::<usize>(),
        k in 0usize..40,
        maxd in prop_oneof![0u32..400, Just(u32::MAX)],
        include_length in any::<bool>(),
    ) {
        let (rows, q) = corpus_and_query(seed, n, near, pick);
        prop_assert_eq!(
            knn_brute(&rows, &q, k, maxd, include_length),
            naive_knn(&rows, &q, k, maxd, include_length)
        );
    }

    #[test]
    fn cells_equal_the_naive_oracle(
        seed in any::<u64>(),
        n in 0usize..400,
        near in any::<bool>(),
        pick in any::<usize>(),
        k in 0usize..40,
        maxd in prop_oneof![0u32..400, Just(u32::MAX)],
        include_length in any::<bool>(),
    ) {
        let (rows, q) = corpus_and_query(seed, n, near, pick);
        let cells = naive_cell_index(&rows);
        prop_assert_eq!(
            knn_cells(&rows, &cells, &q, k, maxd, include_length, None),
            naive_knn(&rows, &q, k, maxd, include_length)
        );
    }
}

#[test]
fn cells_are_empty_for_k_zero_or_a_null_query() {
    let (digests, rows) = example_rows();
    let cells = naive_cell_index(&rows);
    let q = digests[0];
    assert_eq!(knn_cells(&rows, &cells, &q, 0, 100, true, None), vec![]);
    assert_eq!(
        knn_cells(&rows, &cells, &TlshDigest::NULL, 5, 100, true, None),
        vec![]
    );
    assert_eq!(
        knn_cells(&[], &naive_cell_index(&[]), &q, 5, 100, true, None),
        vec![]
    );
}

#[test]
fn cells_at_distance_zero_visit_only_the_query_cell() {
    let (digests, rows) = example_rows();
    let cells = naive_cell_index(&rows);
    // digest 7 is in the rows twice
    let q = digests[7];
    let in_cell = rows.iter().filter(|r| r[..2] == q.0[..2]).count() as u64;
    assert!(in_cell >= 2);
    let mut stats = KnnStats::default();
    let got = knn_cells(&rows, &cells, &q, 1, 0, true, Some(&mut stats));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].distance, 0);
    assert_eq!(rows[got[0].index as usize], q.0);
    assert_eq!(
        stats,
        KnnStats {
            cells: 1,
            lists: 0,
            rows: in_cell
        }
    );
    // the counters accumulate across searches
    knn_cells(&rows, &cells, &q, 1, 0, true, Some(&mut stats));
    assert_eq!(stats.cells, 2);
    assert_eq!(stats.rows, 2 * in_cell);
}

#[test]
fn cells_within_a_huge_radius_return_every_row_in_order() {
    let rows = sorted_rows(&corpus(23, 500));
    let cells = naive_cell_index(&rows);
    let q = TlshDigest(rows[5]);
    let mut stats = KnnStats::default();
    let all = knn_cells(&rows, &cells, &q, rows.len(), 1 << 30, true, Some(&mut stats));
    assert_eq!(all.len(), rows.len());
    assert_eq!(all, knn_brute(&rows, &q, rows.len(), 1 << 30, true));
    // every nonempty cell is visited and every row scanned
    let mut distinct: Vec<[u8; 2]> = rows.iter().map(|r| [r[0], r[1]]).collect();
    distinct.dedup();
    assert_eq!(stats.cells, distinct.len() as u64);
    assert_eq!(stats.rows, rows.len() as u64);
}

#[test]
fn cells_match_brute_force_on_a_generated_corpus() {
    // test_tlsh_cell_search.cpp's grid, on 3000 rows and 40 queries
    let rows = sorted_rows(&corpus(21, 3000));
    let cells = naive_cell_index(&rows);
    let seeds: Vec<TlshDigest> = rows.iter().map(|r| TlshDigest(*r)).collect();
    let p = Perturbation {
        bucket_flip_prob: 0.03,
        ..Perturbation::default()
    };
    for q in perturb_corpus(22, &seeds, 40, &p) {
        for k in [1, 5, 20] {
            for t in [10, 30, 100, 144, 400, 100_000] {
                for incl in [true, false] {
                    assert_eq!(
                        knn_cells(&rows, &cells, &q, k, t, incl, None),
                        knn_brute(&rows, &q, k, t, incl),
                        "q {q} k {k} t {t} incl {incl}"
                    );
                }
            }
        }
    }
}
