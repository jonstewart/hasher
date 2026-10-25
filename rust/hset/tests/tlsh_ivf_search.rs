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
use hset::tlsh::knn::{KnnStats, TlshMatch, knn_brute};
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

/// Random partitions of each cell into up to 6 lists, each with a random
/// member as medoid and the exact radius: the shape of a fresh build.
fn random_partition(rows: &[[u8; 36]], seed: u64) -> TlshIvf {
    let mut rng = SplitMix64::new(seed);
    index_of(rows, |r| {
        let m = 1 + rng.below(r.len().min(6) as u64) as usize;
        let mut members = vec![Vec::new(); m];
        for i in r {
            members[rng.below(m as u64) as usize].push(i as u32);
        }
        members
            .into_iter()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let medoid = TlshDigest(rows[l[rng.below(l.len() as u64) as usize] as usize]);
                exact_list(rows, l, medoid)
            })
            .collect()
    })
}

/// Random partitions whose medoids need not be members and whose radii
/// need not be tight, as an index carried through merges may have (a
/// shrunk list keeps its medoid; a coalesced one takes the larger radius):
/// the medoid is a member, a perturbed member, or a random digest of any
/// header, and the radius is the exact one plus a random slack (sometimes
/// a large one).
fn loose_partition(rows: &[[u8; 36]], seed: u64) -> TlshIvf {
    let mut rng = SplitMix64::new(seed);
    let p = Perturbation::body_only(0.2);
    index_of(rows, |r| {
        let m = 1 + rng.below(r.len().min(4) as u64) as usize;
        let mut members = vec![Vec::new(); m];
        for i in r {
            members[rng.below(m as u64) as usize].push(i as u32);
        }
        members
            .into_iter()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let member = TlshDigest(rows[l[rng.below(l.len() as u64) as usize] as usize]);
                let medoid = match rng.below(3) {
                    0 => member,
                    1 => hset_testkit::tlsh::perturb(&mut rng, &member, &p),
                    _ => random_digest(&mut rng),
                };
                let mut list = exact_list(rows, l, medoid);
                list.radius2 += match rng.below(4) {
                    0 => 0,
                    1 => 1,
                    2 => rng.below(60) as u32,
                    _ => rng.below(5000) as u32,
                };
                list
            })
            .collect()
    })
}

#[test]
fn index_over_random_partitions_with_exact_radii_equals_brute_force() {
    let rows = test_rows(13);
    for seed in [1, 2] {
        let ivf = random_partition(&rows, seed);
        // more lists than cells: many cells have several
        assert!(ivf.lists() > one_list_per_cell(&rows).lists());
        assert_index_is_brute(&ivf, &rows, &test_queries(&rows, 50 + seed, 30));
    }
}

#[test]
fn index_with_loose_radii_and_non_member_medoids_equals_brute_force() {
    let rows = test_rows(23);
    let ivf = loose_partition(&rows, 7);
    assert_index_is_brute(&ivf, &rows, &test_queries(&rows, 70, 40));
}

#[test]
fn index_with_duplicate_rows_equals_brute_force() {
    // a records file keeps equal rows; they share a cell and may share or
    // split lists
    let mut d: Vec<TlshDigest> = corpus(31, 600);
    d.extend_from_slice(&d.clone()[..200]);
    d.extend(cell_corpus(32, 60, (7, 7, 7), 1, 0.0));
    let rows = sorted_rows(&d);
    assert!(rows.windows(2).any(|w| w[0] == w[1]));
    for ivf in [
        one_list_per_cell(&rows),
        random_partition(&rows, 3),
        loose_partition(&rows, 4),
    ] {
        assert_index_is_brute(&ivf, &rows, &test_queries(&rows, 33, 20));
    }
}

#[test]
fn index_is_exact_beyond_144() {
    // C++ tlsh_ivf_knn_is_exact_beyond_144: k 1000, max_distance 100000
    let rows = test_rows(4);
    let digests: Vec<TlshDigest> = rows.iter().map(|r| TlshDigest(*r)).collect();
    let q = perturb_corpus(6, &digests, 1, &Perturbation::body_only(0.2))[0];
    for ivf in [random_partition(&rows, 9), loose_partition(&rows, 10)] {
        let valid = ivf.validate(&rows).unwrap();
        let fast = knn_ivf(&valid, &q, 1000, 100_000, true, None);
        assert_eq!(fast.len(), 1000);
        assert_eq!(fast, knn_brute(&rows, &q, 1000, 100_000, true));
        let fast_x = knn_ivf(&valid, &q, 1000, 100_000, false, None);
        assert_eq!(fast_x, knn_brute(&rows, &q, 1000, 100_000, false));
        // every row, when k exceeds n
        let all = knn_ivf(&valid, &q, rows.len() + 5, 100_000, true, None);
        assert_eq!(all, naive_knn(&rows, &q, usize::MAX, u32::MAX, true));
    }
}

#[test]
fn edge_cases_give_nothing_or_the_exact_member() {
    // C++ tlsh_ivf_knn_edge_cases
    let rows = test_rows(8);
    let ivf = random_partition(&rows, 8);
    let valid = ivf.validate(&rows).unwrap();
    let member = TlshDigest(rows[123]);
    let mut stats = KnnStats::default();
    assert_eq!(knn_ivf(&valid, &member, 0, 100, true, Some(&mut stats)), []);
    assert_eq!(
        knn_ivf(&valid, &TlshDigest::NULL, 5, 100, true, Some(&mut stats)),
        []
    );
    // nothing visited for k 0 or a null query
    assert_eq!(stats, KnnStats::default());

    // exact member found at distance 0
    let r = knn_ivf(&valid, &member, 1, 0, true, None);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].distance, 0);
    assert_eq!(rows[r[0].index as usize], rows[123]);

    // the index of no rows
    let empty = TlshIvf::empty();
    let none = empty.validate(&[]).unwrap();
    assert_eq!(knn_ivf(&none, &member, 5, 1000, true, Some(&mut stats)), []);
    assert_eq!(stats, KnnStats::default());
}

//
// work counters, hand-derived from tlsh_knn_ivf
//

/// A digest with L 100, the given Q1, Q2 and checksum, buckets
/// `0..buckets` set to `code` and the rest 0.
fn hd(q1: u8, q2: u8, checksum: u8, buckets: usize, code: u8) -> TlshDigest {
    let mut codes = [0u8; 128];
    codes[..buckets].fill(code);
    TlshDigest::from_parts(100, q1, q2, checksum, &codes)
}

/// The hand-built index of the counter tests and its rows. The query is
/// `hd(5, 7, 1, 0, 0)`; body distances per bucket are 1, 2, 6 for code
/// differences 1, 2, 3 and squared embedding distances 1, 2, 5. Cells in
/// visiting order (header cost `ch`):
///
/// * A = (5, 7), ch 0: one list of 3 rows (unbounded), distances 1, 2, 4.
/// * B = (5, 8), ch 1: one list of 5 rows, medoid 100 (squared) from the
///   query, radius 0: bound 99.99; distances 121, 122 (x2), ...
/// * C = (5, 6), ch 1: three lists, in index order
///   0: 2 rows at bound 99.99 (distances 121, 122),
///   1: 2 rows at bound 15.99 (distances 17, 18),
///   2: 1 row at bound 3.99 (distance 5).
/// * D = (6, 7), ch 1: one list of 2 rows (unbounded), distances 121, 122.
///
/// Q pairs of cost 1 come as (0, 1) then (1, 0): (q1, q2+1), (q1, q2-1),
/// (q1+1, q2), (q1-1, q2), so B, C, D after A.
struct CounterIndex {
    rows: Vec<[u8; 36]>,
    ivf: TlshIvf,
    query: TlshDigest,
}

fn counter_index() -> CounterIndex {
    let far = |q1, q2, cs| hd(q1, q2, cs, 20, 3);
    let lists: Vec<(Vec<TlshDigest>, TlshDigest)> = vec![
        (
            vec![hd(5, 7, 1, 1, 1), hd(5, 7, 1, 2, 1), hd(5, 7, 1, 4, 1)],
            hd(5, 7, 1, 1, 1),
        ),
        ((1..=5).map(|cs| far(5, 8, cs)).collect(), far(5, 8, 0)),
        ((1..=2).map(|cs| far(5, 6, cs)).collect(), far(5, 6, 0)),
        (
            (1..=2).map(|cs| hd(5, 6, cs, 16, 1)).collect(),
            hd(5, 6, 0, 16, 1),
        ),
        (vec![hd(5, 6, 1, 4, 1)], hd(5, 6, 1, 4, 1)),
        ((1..=2).map(|cs| far(6, 7, cs)).collect(), far(6, 7, 1)),
    ];
    let mut digests: Vec<TlshDigest> = lists.iter().flat_map(|l| l.0.clone()).collect();
    digests.sort();
    assert!(digests.windows(2).all(|w| w[0] < w[1]));
    let rows: Vec<[u8; 36]> = digests.iter().map(|d| d.0).collect();
    // lists in the order given; cells A < C < B < D in sorted order would
    // reorder them, so build cell by cell
    let mut ivf = TlshIvf::empty();
    ivf.n = rows.len() as u64;
    let cell = |d: &TlshDigest| usize::from(d.cell());
    let mut order: Vec<usize> = (0..lists.len()).collect();
    order.sort_by_key(|&i| cell(&lists[i].1));
    for i in order {
        let (members, medoid) = &lists[i];
        let mut ids: Vec<u32> = members
            .iter()
            .map(|m| digests.binary_search(m).unwrap() as u32)
            .collect();
        ids.sort();
        let l = exact_list(&rows, ids, *medoid);
        ivf.medoids.push(l.medoid);
        ivf.radius2.push(l.radius2);
        ivf.ids.extend(l.members);
        ivf.list_start.push(ivf.ids.len() as u64);
        for c in &mut ivf.cell_lists[cell(medoid) + 1..] {
            *c += 1;
        }
    }
    CounterIndex {
        rows,
        ivf,
        query: hd(5, 7, 1, 0, 0),
    }
}

impl CounterIndex {
    /// Search and return the matches as `(distance, digest)` and the
    /// counters, through the owned index and its payload (which must
    /// agree).
    fn search(&self, k: usize, t: u32) -> (Vec<(u32, TlshDigest)>, KnnStats) {
        let valid = (&self.ivf).validate(&self.rows).unwrap();
        let mut stats = KnnStats::default();
        let m = knn_ivf(&valid, &self.query, k, t, true, Some(&mut stats));
        assert_eq!(m, knn_brute(&self.rows, &self.query, k, t, true));

        let payload = self.ivf.to_bytes();
        let view = TivfView::parse(&payload, self.rows.len() as u64).unwrap();
        let valid = view.validate(&self.rows).unwrap();
        let mut view_stats = KnnStats::default();
        assert_eq!(
            knn_ivf(&valid, &self.query, k, t, true, Some(&mut view_stats)),
            m
        );
        assert_eq!(view_stats, stats);

        let m = m
            .iter()
            .map(|m| (m.distance, TlshDigest(self.rows[m.index as usize])))
            .collect();
        (m, stats)
    }
}

fn counts(cells: u64, lists: u64, rows: u64) -> KnnStats {
    KnnStats { cells, lists, rows }
}

#[test]
fn counter_index_is_as_documented() {
    let x = counter_index();
    let q = x.query;
    assert_eq!(x.ivf.lists(), 6);
    // cells: A (5,7) has list 0; C (5,6) sorts before it with lists 0..3
    let c = |q1: u8, q2: u8| usize::from(100u16 << 8 | u16::from(q1 << 4 | q2));
    let range = |cell: usize| x.ivf.cell_lists[cell]..x.ivf.cell_lists[cell + 1];
    assert_eq!(range(c(5, 6)), 0..3);
    assert_eq!(range(c(5, 7)), 3..4);
    assert_eq!(range(c(5, 8)), 4..5);
    assert_eq!(range(c(6, 7)), 5..6);
    let d2 = |l: usize| ref_emb2(&q, &x.ivf.medoids[l].0);
    assert_eq!([d2(0), d2(1), d2(2), d2(4)], [100, 16, 4, 100]);
    assert_eq!(x.ivf.radius2, [0, 0, 0, 3, 0, 0]);
    assert_eq!(list_bound(100, 0), 100.0 - 0.01);
    assert_eq!(list_bound(16, 0), 16.0 - 0.01);
    assert_eq!(list_bound(4, 0), 4.0 - 0.01);
}

#[test]
fn counters_with_room_to_spare() {
    // k 10, T 50: A scanned (3 rows); B bounded and pruned (1 list);
    // C's 3 lists evaluated, list 0 pruned, lists 2 then 1 scanned (3
    // rows); D scanned unbounded (2 rows, none within 50)
    let x = counter_index();
    let (m, stats) = x.search(10, 50);
    assert_eq!(stats, counts(4, 4, 8));
    assert_eq!(
        m,
        [
            (1, hd(5, 7, 1, 1, 1)),
            (2, hd(5, 7, 1, 2, 1)),
            (4, hd(5, 7, 1, 4, 1)),
            (5, hd(5, 6, 1, 4, 1)),
            (17, hd(5, 6, 1, 16, 1)),
            (18, hd(5, 6, 2, 16, 1)),
        ]
    );
}

#[test]
fn counters_follow_the_bound_order_within_a_cell() {
    // k 4, T 50: A fills 3; in C list 2 (bound 3.99) is scanned before
    // list 1 (bound 15.99) although it comes later in the index; its row
    // at 5 fills k and tau becomes 5, so list 1 (1 + 15.99 > 5) is never
    // scanned. In index order list 1 would be scanned first (rows 3+2+1).
    let x = counter_index();
    let (m, stats) = x.search(4, 50);
    assert_eq!(stats, counts(4, 4, 3 + 1 + 2));
    assert_eq!(
        m.iter().map(|m| m.0).collect::<Vec<_>>(),
        [1, 2, 4, 5],
        "{m:?}"
    );
}

#[test]
fn counters_once_the_bound_has_shrunk() {
    // k 1, T 50: A's row at 1 makes tau 1; the ch-1 cells are still
    // visited: B pruned (1 list), C's 3 lists all above 1, D scanned
    // unbounded (2 rows); the ch-2 cells end the Q loop and the L 1
    // cells the L loop
    let x = counter_index();
    let (m, stats) = x.search(1, 50);
    assert_eq!(stats, counts(4, 4, 3 + 2));
    assert_eq!(m, [(1, hd(5, 7, 1, 1, 1))]);
}

#[test]
fn counters_when_every_list_is_in_range() {
    // T 200: every bound passes; B is a bounded single list that is
    // scanned (1 list, 5 rows); all 15 rows are within 200
    let x = counter_index();
    let (m, stats) = x.search(100, 200);
    assert_eq!(stats, counts(4, 4, 15));
    assert_eq!(m.len(), 15);
}

#[test]
fn counters_with_max_distance_0() {
    // tau 0: only cost-0 cells (A) are visited and no row is within 0
    let x = counter_index();
    let (m, stats) = x.search(5, 0);
    assert_eq!(stats, counts(1, 0, 3));
    assert_eq!(m, []);
}

#[test]
fn counters_add_to_what_they_hold() {
    let x = counter_index();
    let valid = (&x.ivf).validate(&x.rows).unwrap();
    let mut stats = counts(10, 20, 30);
    knn_ivf(&valid, &x.query, 10, 50, true, Some(&mut stats));
    assert_eq!(stats, counts(14, 24, 38));
}

//
// cross-check against the C++ fixtures
//

const FTOC: u32 = u32::from_be_bytes(*b"FTOC");
const HDAT: u32 = u32::from_be_bytes(*b"HDAT");
const TIVF: u32 = u32::from_be_bytes(*b"TIVF");
const TVEC: u32 = u32::from_be_bytes(*b"TVEC");

/// The `(HDAT, TIVF)` payload pairs of a hash set file, by a minimal walk
/// of its FTOC (chunk header: BE u32 type, LE u64 length; FTOC entries: LE
/// u64 offset, BE u32 type). A TIVF follows its section's HDAT (and RIDX,
/// if any). Empty for a file that is not a chunked hash set or has a TVEC
/// chunk (which a loader must reject).
fn tivf_sections(file: &[u8]) -> Vec<(&[u8], &[u8])> {
    let chunk = |off: usize| -> Option<(u32, &[u8])> {
        let ty = u32::from_be_bytes(file.get(off..off + 4)?.try_into().ok()?);
        let len = u64::from_le_bytes(file.get(off + 4..off + 12)?.try_into().ok()?);
        Some((
            ty,
            file.get(off + 12..off + 12 + usize::try_from(len).ok()?)?,
        ))
    };
    let Some((FTOC, toc)) = chunk(40) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut hdat: Option<&[u8]> = None;
    for e in toc.as_chunks::<12>().0 {
        let off = u64::from_le_bytes(e[..8].try_into().unwrap()) as usize;
        let Some((ty, data)) = chunk(off) else {
            return Vec::new();
        };
        match ty {
            TVEC => return Vec::new(),
            HDAT => hdat = Some(data),
            TIVF => out.push((hdat.expect("TIVF after an HDAT"), data)),
            _ => {}
        }
    }
    out
}

#[test]
fn index_equals_brute_force_on_cpp_fixtures() {
    let dir = hset_testkit::fixtures::fixtures_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("no fixtures directory {}; skipped", dir.display());
        return;
    };
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "hset"))
        .collect();
    paths.sort();
    let mut sections = 0;
    for path in paths {
        let file = std::fs::read(&path).unwrap();
        for (hdat, tivf) in tivf_sections(&file) {
            let name = path.display();
            let (rows, rest) = hdat.as_chunks::<36>();
            assert!(rest.is_empty(), "{name}: HDAT is not 36-byte rows");
            let view = TivfView::parse(tivf, rows.len() as u64)
                .unwrap_or_else(|e| panic!("{name}: TIVF does not parse: {e}"));
            let valid = view
                .validate(rows)
                .unwrap_or_else(|e| panic!("{name}: TIVF is invalid: {e}"));
            sections += 1;
            if rows.is_empty() {
                continue;
            }
            let mut queries = test_queries(rows, sections, 6);
            queries.extend([0, rows.len() / 2, rows.len() - 1].map(|i| TlshDigest(rows[i])));
            for q in &queries {
                for (k, t) in [(1, 30), (10, 144), (50, 400)] {
                    for incl in [true, false] {
                        assert_eq!(
                            knn_ivf(&valid, q, k, t, incl, None),
                            knn_brute(rows, q, k, t, incl),
                            "{name}: q {} k {k} T {t} incl {incl}",
                            q.to_hex()
                        );
                    }
                }
            }
        }
    }
    eprintln!(
        "{sections} TIVF sections cross-checked in {}",
        dir.display()
    );
}
