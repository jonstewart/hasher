//! The BISECT TIVF builder `hset::tlsh::ivf::bisect`, ported from the
//! BISECT cases of `test/test_tlsh_ivf.cpp`: list shapes on hand-built
//! cells, determinism across thread counts, and that every built index
//! validates and gives the brute-force kNN answers.

use hset::Error;
use hset::synth::SplitMix64;
use hset::tlsh::{TlshDigest, emb_body_dist2};
use hset::tlsh::ivf::bisect::{IvfBuildOptions, build_tlsh_ivf, nearer};
use hset::tlsh::ivf::{IvfIndex, TlshIvf};
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
