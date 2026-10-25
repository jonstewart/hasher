//! The BISECT TIVF builder `hset::tlsh::ivf::bisect`, ported from the
//! BISECT cases of `test/test_tlsh_ivf.cpp`: list shapes on hand-built
//! cells, determinism across thread counts, and that every built index
//! validates and gives the brute-force kNN answers.

use hset::Error;
use hset::synth::SplitMix64;
use hset::tlsh::{TlshDigest, emb_body_dist2};
use hset::tlsh::ivf::bisect::{IvfBuildOptions, build_tlsh_ivf, nearer};
use hset::tlsh::CELL_COUNT;
use hset::tlsh::ivf::{FLAT_MAX, IvfIndex, TlshIvf};
use hset::tlsh::mt64::Mt19937_64;
use hset_testkit::tlsh::random_digest_with_header;

/// `n` random rows of the one cell (L 0x40, Q 0x21), sorted and
/// deduplicated (C++ `one_cell_corpus`).
fn one_cell_corpus(seed: u64, n: usize) -> Vec<[u8; 36]> {
    let mut rng = SplitMix64::new(seed);
    let mut rows: Vec<[u8; 36]> = (0..n)
        .map(|_| random_digest_with_header(&mut rng, 0x40, 2, 1).0)
        .collect();
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// BISECT build with target `t` and seed `seed` on the default threads.
fn build(rows: &[[u8; 36]], t: usize, seed: u64) -> TlshIvf {
    let opts = IvfBuildOptions {
        target_list_size: t,
        seed,
        ..IvfBuildOptions::default()
    };
    build_tlsh_ivf(rows, &opts).expect("build")
}

#[test]
fn one_row_is_one_list_of_radius_zero() {
    let rows = one_cell_corpus(61, 1);
    let ivf = build(&rows, 32, 7);
    assert_eq!(ivf.lists(), 1);
    assert_eq!(ivf.medoids, vec![TlshDigest(rows[0])]);
    assert_eq!(ivf.radius2, vec![0]);
    assert_eq!(ivf.ids, vec![0]);
    assert_eq!(ivf.list_start, vec![0, 1]);
    assert_eq!(ivf.n, 1);
    // the cell of L 0x40, Q 0x21 holds list 0
    let cell = 0x4021;
    assert!(ivf.cell_lists[..=cell].iter().all(|&c| c == 0));
    assert!(ivf.cell_lists[cell + 1..].iter().all(|&c| c == 1));
    ivf.validate(&rows).expect("valid");
}

#[test]
fn no_rows_give_the_empty_index() {
    let ivf = build(&[], 32, 7);
    assert_eq!(ivf, TlshIvf::empty());
}

#[test]
fn zero_target_list_size_is_an_input_error() {
    let rows = one_cell_corpus(61, 1);
    let err = build_tlsh_ivf(
        &rows,
        &IvfBuildOptions {
            target_list_size: 0,
            ..IvfBuildOptions::default()
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Input(_)), "{err}");
}

#[test]
fn unsorted_rows_are_an_input_error() {
    let mut rows = one_cell_corpus(62, 3);
    rows.swap(0, 2);
    let err = build_tlsh_ivf(&rows, &IvfBuildOptions::default()).unwrap_err();
    assert!(matches!(err, Error::Input(_)), "{err}");
}

#[test]
fn defaults_are_the_cpp_defaults() {
    // T = 32, seed 0x7175657279 ("query"), threads 0 = available parallelism
    assert_eq!(
        IvfBuildOptions::default(),
        IvfBuildOptions {
            target_list_size: 32,
            seed: 0x71_7565_7279,
            threads: 0,
        }
    );
}

/// Largest squared body-embedding distance from `c` to a member of list
/// `l` (C++ `max_dist2_about`).
fn max_dist2_about(ivf: &TlshIvf, rows: &[[u8; 36]], l: usize, c: &TlshDigest) -> u32 {
    ivf.list_ids(l)
        .map(|i| emb_body_dist2(c, &TlshDigest(rows[i as usize])))
        .max()
        .unwrap_or(0)
}

/// Every list's medoid is a member, radius2 is the attained largest
/// distance from it, and no member has a smaller one: a 1-center (C++
/// `check_one_centers`).
fn check_one_centers(ivf: &TlshIvf, rows: &[[u8; 36]]) {
    for l in 0..ivf.lists() {
        let mut member = false;
        let mut best = u32::MAX;
        for i in ivf.list_ids(l) {
            let r = TlshDigest(rows[i as usize]);
            member |= r == ivf.medoids[l];
            best = best.min(max_dist2_about(ivf, rows, l, &r));
        }
        assert!(member, "list {l}: medoid is not a member");
        assert_eq!(
            ivf.radius2[l],
            max_dist2_about(ivf, rows, l, &ivf.medoids[l]),
            "list {l}"
        );
        assert_eq!(ivf.radius2[l], best, "list {l}: not a 1-center");
    }
}

#[test]
fn exactly_t_rows_are_one_list_about_their_one_center() {
    let t = one_cell_corpus(62, 40);
    assert!(t.len() >= 32);
    let rows = &t[..32];
    let ivf = build(rows, 32, 7);
    assert_eq!(ivf.lists(), 1);
    check_one_centers(&ivf, rows);
    ivf.validate(rows).expect("valid");
}

#[test]
fn equal_rows_are_allowed() {
    // records files keep duplicate rows; both copies are indexed
    let one = one_cell_corpus(63, 1);
    let rows = vec![one[0], one[0]];
    let ivf = build(&rows, 32, 7);
    assert_eq!(ivf.ids, vec![0, 1]);
    assert_eq!(ivf.radius2, vec![0]);
}

#[test]
fn nearer_compares_squared_distances_exactly() {
    // N_a / n_a^2 < N_b / n_b^2 (C++ tlsh_ivf_nearer table)
    assert!(nearer(3, 2, 1, 1)); // 3/4 < 1
    assert!(!nearer(1, 1, 3, 2));
    assert!(nearer(0, 5, 1, 1));
    assert!(!nearer(0, 5, 0, 1)); // 0 == 0
    assert!(nearer(1, 4096, 1, 4095));
    assert!(!nearer(1, 4095, 1, 4096));
    assert!(!nearer(1, 4096, 0, 1));

    // equal distances with different denominators: neither is nearer
    assert!(!nearer(4, 2, 1, 1));
    assert!(!nearer(1, 1, 4, 2));
    assert!(!nearer(9 * 50, 3 * 10, 50, 10)); // 450 / 900 == 50 / 100

    // at the bound N = 2^34, n = 4096: 2^34 / 2^24 == 1024 / 1, and one
    // unit less in N is nearer, which a 32-bit or float product would miss
    let big = 1u64 << 34;
    assert!(!nearer(big, 4096, 1024, 1));
    assert!(!nearer(1024, 1, big, 4096));
    assert!(nearer(big - 1, 4096, 1024, 1));
    assert!(nearer(big - 1, 4096, big, 4096));
    assert!(!nearer(big, 4096, big - 1, 4096));
}

/// Row `d` with checksum `c`.
fn with_checksum(d: &[u8; 36], c: u8) -> [u8; 36] {
    let mut r = *d;
    r[34] = c;
    r
}

/// `n` rows of one cell sharing one body, differing in the checksum only
/// (`i as u8`, so beyond 256 rows they repeat), sorted (C++
/// `same_body_corpus`).
fn same_body_corpus(n: usize) -> Vec<[u8; 36]> {
    let d = one_cell_corpus(31, 1)[0];
    let mut rows: Vec<[u8; 36]> = (0..n).map(|i| with_checksum(&d, i as u8)).collect();
    rows.sort_unstable();
    rows
}

/// `copies[b]` rows of each of the distinct `bodies` (checksums 0, 1, ..),
/// sorted.
fn copies_of(bodies: &[[u8; 36]], copies: &[usize]) -> Vec<[u8; 36]> {
    let mut rows = Vec::new();
    for (d, &k) in bodies.iter().zip(copies) {
        rows.extend((0..k).map(|i| with_checksum(d, i as u8)));
    }
    rows.sort_unstable();
    rows
}

/// List sizes of an index, in list order.
fn sizes(ivf: &TlshIvf) -> Vec<u64> {
    (0..ivf.lists()).map(|l| ivf.list_len(l)).collect()
}

/// List counts of a BISECT build with target `t` (C++
/// `check_bisect_shape`), per nonempty cell of `m` rows, `F = FLAT_MAX`:
/// at most `ceil(m / T)` lists when `m <= F`; otherwise every flat node
/// has more than `F / 8` rows, so `lists * T * F <= m F + 8 m (T - 1)`.
/// Every list is nonempty.
fn check_bisect_shape(ivf: &TlshIvf, t: u64) {
    let f = FLAT_MAX as u64;
    for c in 0..CELL_COUNT {
        let (fl, el) = (ivf.cell_lists[c] as usize, ivf.cell_lists[c + 1] as usize);
        if fl == el {
            continue;
        }
        let m = ivf.list_start[el] - ivf.list_start[fl];
        let lists = (el - fl) as u64;
        if m <= f {
            assert!(lists <= m.div_ceil(t), "cell {c:#06x}: {lists} lists of {m} rows");
        } else {
            assert!(
                lists * t * f <= m * f + 8 * m * (t - 1),
                "cell {c:#06x}: {lists} lists of {m} rows"
            );
        }
        for l in fl..el {
            assert!(ivf.list_len(l) > 0, "list {l} is empty");
        }
    }
}

#[test]
fn identical_bodies_are_one_list_of_radius_zero() {
    // one distinct body, k = ceil(200 / 32) = 7: seeding finds no second
    // centroid, so the node is one list of radius 0
    let rows = same_body_corpus(200);
    let ivf = build(&rows, 32, 7);
    assert_eq!(ivf.ids.len(), rows.len());
    assert_eq!(ivf.lists(), 1);
    assert_eq!(ivf.radius2, vec![0]);
    check_bisect_shape(&build(&same_body_corpus(250), 32, 7), 32);
}

#[test]
fn fewer_bodies_than_lists_give_one_list_per_body() {
    // three distinct bodies x 70 rows, k = ceil(210 / 32) = 7
    let bodies = one_cell_corpus(32, 3);
    assert_eq!(bodies.len(), 3);
    let rows = copies_of(&bodies, &[70, 70, 70]);
    let ivf = build(&rows, 32, 7);
    assert_eq!(ivf.ids.len(), rows.len());
    assert_eq!(sizes(&ivf), vec![70, 70, 70]);
    assert_eq!(ivf.radius2, vec![0, 0, 0]);
    ivf.validate(&rows).expect("valid");
}

#[test]
fn small_groups_stay_apart() {
    // four bodies with 70, 70, 10, 10 copies, s = 160, k = 5: seeding finds
    // four centroids, each a body; a fresh build does not coalesce the two
    // lists of 10
    let bodies = one_cell_corpus(33, 4);
    assert_eq!(bodies.len(), 4);
    for i in 0..4 {
        for j in i + 1..4 {
            assert!(emb_body_dist2(&TlshDigest(bodies[i]), &TlshDigest(bodies[j])) > 0);
        }
    }
    let rows = copies_of(&bodies, &[70, 70, 10, 10]);
    let ivf = build(&rows, 32, 7);
    assert_eq!(ivf.ids.len(), rows.len());
    let mut got = sizes(&ivf);
    got.sort_unstable();
    assert_eq!(got, vec![10, 10, 70, 70]);
    assert_eq!(ivf.radius2, vec![0; 4]);
}

/// `nf` families of `per` rows in one cell (L 3, Q 0x45): random leading
/// 4 bytes of both planes (32 noise buckets), and of the three 4-byte
/// blocks of the trailing 12 bytes, family f has block f all code 3 and
/// the others all code 0. Families differ by at least 2 x 32 x 5 = 320,
/// members of one family by at most 32 x 5 = 160. Sorted, which
/// interleaves the families (C++ `family_cell_corpus`).
fn family_cell_corpus(nf: usize, per: usize) -> Vec<[u8; 36]> {
    let mut rng = Mt19937_64::new(5);
    let mut rows = Vec::new();
    for f in 0..nf {
        for _ in 0..per {
            let mut d = [0u8; 36];
            d[0] = 3;
            d[1] = 0x45;
            for b in 0..4 {
                d[HI + b] = rng.next_u64() as u8;
                d[LO + b] = rng.next_u64() as u8;
            }
            for b in 4..16 {
                let v = if (b - 4) / 4 == f { 0xFF } else { 0 };
                d[HI + b] = v;
                d[LO + b] = v;
            }
            rows.push(d);
        }
    }
    rows.sort_unstable();
    rows
}

/// Offsets of the planes in a row.
const HI: usize = 2;
const LO: usize = 18;

/// The family of a `family_cell_corpus` row.
fn family_of(d: &[u8; 36]) -> usize {
    (0..3).find(|&f| d[HI + 4 + 4 * f] != 0).unwrap_or(0)
}

#[test]
fn families_come_out_as_pure_lists() {
    // nf families of 30 rows, T = 32: k = nf lists, one per family
    for nf in [2, 3] {
        let rows = family_cell_corpus(nf, 30);
        let ivf = build(&rows, 32, 7);
        assert_eq!(ivf.lists(), nf);
        let mut seen: Vec<usize> = Vec::new();
        for l in 0..nf {
            assert_eq!(ivf.list_len(l), 30);
            let fams: Vec<usize> = ivf.list_ids(l).map(|i| family_of(&rows[i as usize])).collect();
            assert!(fams.iter().all(|&f| f == fams[0]), "list {l} mixes families");
            seen.push(fams[0]);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), nf);
    }
}

/// A digest of cell (L 9, Q 0x12) whose body is all code 1 (the zero
/// embedding) except code 0 (coordinate 2b = 1) in `buckets` (C++
/// `unit_body`).
fn unit_body(buckets: &[usize], checksum: u8) -> [u8; 36] {
    let mut d = [0u8; 36];
    d[0] = 9;
    d[1] = 0x12;
    d[34] = checksum;
    d[LO..LO + 16].fill(0xFF);
    for &b in buckets {
        d[LO + (b >> 3)] &= !(1u8 << (b & 7));
    }
    d
}

#[test]
fn rows_go_to_the_nearest_mean_not_the_nearest_medoid() {
    // One flat node, T = 16, s = 23, k = 2 (C++
    // tlsh_ivf_bisect_assigns_to_the_nearest_mean): P = x_0..x_5 with code
    // 0 in buckets 2i, 2i + 1; t with code 0 in 12, 13; Q = 16 copies of f
    // with code 0 in 12..17. d(x_i, t) = 4 > d(t, f) = 3, but d(t, mean P)
    // = 2 + 12/36 < 3: by means t belongs with P.
    let mut rows: Vec<[u8; 36]> = (0..6).map(|i| unit_body(&[2 * i, 2 * i + 1], 0)).collect();
    let t = unit_body(&[12, 13], 0);
    rows.push(t);
    let f = unit_body(&[12, 13, 14, 15, 16], 0);
    rows.extend((0..16).map(|c| unit_body(&[12, 13, 14, 15, 16], c)));
    let d = |a: &[u8; 36], b: &[u8; 36]| emb_body_dist2(&TlshDigest(*a), &TlshDigest(*b));
    assert_eq!(d(&rows[0], &rows[1]), 4);
    assert_eq!(d(&rows[0], &t), 4);
    assert_eq!(d(&t, &f), 3);
    assert_eq!(d(&rows[0], &f), 7);
    rows.sort_unstable();

    for seed in [1, 7, 99] {
        let ivf = build(&rows, 16, seed);
        assert_eq!(ivf.lists(), 2, "seed {seed}");
        for l in 0..2 {
            let has_t = ivf.list_ids(l).any(|i| rows[i as usize] == t);
            let copies_of_f = ivf.list_ids(l).filter(|&i| d(&rows[i as usize], &f) == 0).count();
            assert_eq!(ivf.list_len(l), if has_t { 7 } else { 16 }, "seed {seed}");
            assert_eq!(copies_of_f, if has_t { 0 } else { 16 }, "seed {seed}");
        }
    }
}
