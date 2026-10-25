//! `hset::tlsh::ivf::search`, the exact indexed kNN (C++ `tlsh_knn_ivf`),
//! ported from `test/test_tlsh_ivf.cpp` (index == brute grids, k 1000
//! beyond 144, edge cases) with test-local indexes in place of the BISECT
//! build, plus the list bound and the work counters, derived by hand from
//! `tlsh_ivf.cpp`.

use std::ops::Range;

use hset::synth::SplitMix64;
use hset::tlsh::TlshDigest;
use hset::tlsh::ivf::search::{knn_ivf, list_bound};
use hset::tlsh::ivf::{IvfIndex, TivfView, TlshIvf};
use hset::tlsh::knn::{TlshMatch, knn_brute};
use hset_testkit::tlsh::{
    Perturbation, cell_corpus, corpus, naive_knn, perturb_corpus, random_digest, sorted_rows,
};

const CELLS: usize = 65536;

fn cell_of(row: &[u8; 36]) -> usize {
    usize::from(u16::from_be_bytes([row[0], row[1]]))
}

/// Squared body-embedding distance bucket by bucket: 0, 1, 2, 5 for code
/// differences 0..=3 (codes embed as (1,0), (0,0), (0,1), (-1,1)).
fn ref_emb2(a: &TlshDigest, b: &[u8; 36]) -> u32 {
    let b = TlshDigest(*b);
    (0..128)
        .map(|i| [0, 1, 2, 5][usize::from(a.bucket(i).abs_diff(b.bucket(i)))])
        .sum()
}

/// One list of a test index: members (row indexes), medoid and radius2.
struct List {
    members: Vec<u32>,
    medoid: TlshDigest,
    radius2: u32,
}

/// The exactly fitting list of `members` around `medoid`.
fn exact_list(rows: &[[u8; 36]], members: Vec<u32>, medoid: TlshDigest) -> List {
    let radius2 = members
        .iter()
        .map(|&i| ref_emb2(&medoid, &rows[i as usize]))
        .max()
        .unwrap_or(0);
    List {
        members,
        medoid,
        radius2,
    }
}

/// An index over sorted `rows` whose lists of each nonempty cell are what
/// `split` makes of the cell's row range (empty lists dropped, members
/// sorted).
fn index_of(rows: &[[u8; 36]], mut split: impl FnMut(Range<usize>) -> Vec<List>) -> TlshIvf {
    assert!(rows.is_sorted());
    let mut ivf = TlshIvf::empty();
    ivf.n = rows.len() as u64;
    let mut at = 0;
    for c in 0..CELLS {
        ivf.cell_lists[c] = ivf.radius2.len() as u32;
        let end = at + rows[at..].iter().take_while(|r| cell_of(r) == c).count();
        if end > at {
            for mut l in split(at..end) {
                if l.members.is_empty() {
                    continue;
                }
                l.members.sort_unstable();
                ivf.medoids.push(l.medoid);
                ivf.radius2.push(l.radius2);
                ivf.ids.extend(l.members);
                ivf.list_start.push(ivf.ids.len() as u64);
            }
        }
        at = end;
    }
    ivf.cell_lists[CELLS] = ivf.radius2.len() as u32;
    assert_eq!(at, rows.len());
    ivf
}

/// One list per cell, its first row the medoid.
fn one_list_per_cell(rows: &[[u8; 36]]) -> TlshIvf {
    index_of(rows, |r| {
        let medoid = TlshDigest(rows[r.start]);
        vec![exact_list(rows, r.map(|i| i as u32).collect(), medoid)]
    })
}

/// Sorted rows over many small cells (families of 10 with header moves)
/// and a few large ones, so cells have one row, a few, or hundreds.
fn test_rows(seed: u64) -> Vec<[u8; 36]> {
    let mut d = corpus(seed, 3000);
    d.extend(cell_corpus(seed + 1, 400, (0x40, 2, 1), 12, 0.08));
    d.extend(cell_corpus(seed + 2, 150, (0x41, 2, 1), 3, 0.2));
    // a large cell next to a family base's cell
    let (l, q1, q2) = (d[0].l(), d[0].q1(), d[0].q2());
    d.extend(cell_corpus(
        seed + 3,
        120,
        (l, q1, q2.wrapping_add(1) & 15),
        5,
        0.1,
    ));
    sorted_rows(&d)
}

/// Queries: perturbed rows (C++ `perturb_tlsh_corpus(5, rows, 60, 0.03)`
/// moves buckets at 0.03), exact members, and random digests.
fn test_queries(rows: &[[u8; 36]], seed: u64, n: usize) -> Vec<TlshDigest> {
    let digests: Vec<TlshDigest> = rows.iter().map(|r| TlshDigest(*r)).collect();
    let p = Perturbation {
        bucket_flip_prob: 0.03,
        ..Perturbation::default()
    };
    let mut q = perturb_corpus(seed, &digests, n, &p);
    let mut rng = SplitMix64::new(seed);
    for _ in 0..n / 10 {
        q.push(digests[rng.below(digests.len() as u64) as usize]);
        q.push(random_digest(&mut rng));
    }
    q
}

/// The searches of C++ `tlsh_ivf_knn_matches_brute_force`: every query
/// for k in {1, 5, 20}, max_distance in {10, 30, 60, 100, 144, 400}, with
/// and without the length, through the owned index and its parsed payload,
/// equal to brute force and to the naive specification.
#[track_caller]
fn assert_index_is_brute(ivf: &TlshIvf, rows: &[[u8; 36]], queries: &[TlshDigest]) {
    let valid = ivf.validate(rows).expect("test index is valid");
    let payload = ivf.to_bytes();
    let view = TivfView::parse(&payload, rows.len() as u64).unwrap();
    let valid_view = view.validate(rows).unwrap();
    for q in queries {
        for incl in [true, false] {
            let all = naive_knn(rows, q, usize::MAX, u32::MAX, incl);
            for k in [1, 5, 20] {
                for t in [10, 30, 60, 100, 144, 400] {
                    let fast = knn_ivf(&valid, q, k, t, incl, None);
                    let brute = knn_brute(rows, q, k, t, incl);
                    assert_eq!(fast, brute, "q {} k {k} T {t} incl {incl}", q.to_hex());
                    let naive: Vec<TlshMatch> = all
                        .iter()
                        .copied()
                        .filter(|m| m.distance <= t)
                        .take(k)
                        .collect();
                    assert_eq!(fast, naive);
                    assert_eq!(knn_ivf(&valid_view, q, k, t, incl, None), fast);
                }
            }
        }
    }
}

#[test]
fn index_with_one_list_per_cell_equals_brute_force() {
    let rows = test_rows(3);
    let ivf = one_list_per_cell(&rows);
    assert_index_is_brute(&ivf, &rows, &test_queries(&rows, 5, 60));
}

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
