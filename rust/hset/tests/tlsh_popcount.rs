//! The popcount kernel choice ([`Popcount`], [`with_popcount`]): the
//! choice is scoped to a thread and restored, an unavailable kind falls
//! back to the portable one, and every TLSH scan (brute, cells, TIVF
//! search, BISECT build, validation) returns the same result under each
//! kind, equal to a bucket-by-bucket reference.

use hset::tlsh::distance::{Popcount, popcount, with_popcount};
use hset::tlsh::ivf::bisect::{IvfBuildOptions, build_tlsh_ivf};
use hset::tlsh::ivf::check_index;
use hset::tlsh::ivf::search::knn_ivf;
use hset::tlsh::knn::{knn_brute, knn_cells};
use hset::tlsh::{TlshDigest, TlshMatch};
use hset_testkit::tlsh::{corpus, naive_cell_index, ref_distance, sorted_rows};
use proptest::prelude::*;

const KINDS: [Popcount; 2] = [Popcount::Portable, Popcount::Popcnt];

/// Whether this CPU has POPCNT, from `/proc/cpuinfo` (independent of the
/// crate's detection); `None` where that file is not there to ask.
fn cpuinfo_popcnt() -> Option<bool> {
    let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let flags = info.lines().find(|l| l.starts_with("flags"))?;
    Some(flags.split_whitespace().any(|f| f == "popcnt"))
}

#[test]
fn portable_is_always_available() {
    assert!(Popcount::Portable.is_available());
    assert!(Popcount::detected().is_available());
}

#[test]
fn detection_agrees_with_cpuinfo_on_x86_64() {
    if cfg!(target_arch = "x86_64")
        && let Some(has) = cpuinfo_popcnt()
    {
        assert_eq!(Popcount::Popcnt.is_available(), has);
        let want = if has {
            Popcount::Popcnt
        } else {
            Popcount::Portable
        };
        assert_eq!(Popcount::detected(), want);
    }
    if !cfg!(target_arch = "x86_64") {
        assert!(!Popcount::Popcnt.is_available());
        assert_eq!(Popcount::detected(), Popcount::Portable);
    }
}

#[test]
fn the_choice_is_scoped_and_restored() {
    assert_eq!(popcount(), Popcount::detected());
    let effective_popcnt = if Popcount::Popcnt.is_available() {
        Popcount::Popcnt
    } else {
        Popcount::Portable
    };
    with_popcount(Popcount::Portable, || {
        assert_eq!(popcount(), Popcount::Portable);
        with_popcount(Popcount::Popcnt, || {
            assert_eq!(popcount(), effective_popcnt);
        });
        assert_eq!(popcount(), Popcount::Portable);
    });
    assert_eq!(popcount(), Popcount::detected());
}

#[test]
fn the_choice_is_restored_after_a_panic() {
    let r = std::panic::catch_unwind(|| {
        with_popcount(Popcount::Portable, || panic!("inside"));
    });
    assert!(r.is_err());
    assert_eq!(popcount(), Popcount::detected());
}

#[test]
fn the_choice_is_per_thread() {
    with_popcount(Popcount::Portable, || {
        let other = std::thread::spawn(popcount).join().unwrap();
        assert_eq!(other, Popcount::detected());
    });
}

fn arb_digest() -> impl Strategy<Value = TlshDigest> {
    (any::<[u8; 32]>(), any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(body, l, q, cs)| {
        let mut b = [0u8; 36];
        b[0] = l;
        b[1] = q;
        b[2..34].copy_from_slice(&body);
        b[34] = cs | 1; // never null
        TlshDigest(b)
    })
}

proptest! {
    /// Brute force with k = n and no bound returns every row's distance:
    /// each one is the reference distance, under each kernel.
    #[test]
    fn every_kernel_scans_rows_at_the_reference_distance(
        q in arb_digest(),
        digests in proptest::collection::vec(arb_digest(), 1..64),
        include_length in any::<bool>(),
    ) {
        let rows = sorted_rows(&digests);
        let mut want: Vec<TlshMatch> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| TlshMatch {
                index: i as u64,
                distance: ref_distance(&q, &TlshDigest(*r), include_length),
            })
            .collect();
        want.sort();
        let cells = naive_cell_index(&rows);
        for p in KINDS {
            let n = rows.len();
            let brute = with_popcount(p, || knn_brute(&rows, &q, n, u32::MAX, include_length));
            prop_assert_eq!(&brute, &want, "brute, {:?}", p);
            let cell = with_popcount(p, || {
                knn_cells(&rows, &cells, &q, n, u32::MAX, include_length, None)
            });
            prop_assert_eq!(&cell, &want, "cells, {:?}", p);
        }
    }
}

#[test]
fn every_kernel_builds_the_same_index_and_searches_it_alike() {
    let rows = sorted_rows(&corpus(0x5EED, 6000));
    let opts = IvfBuildOptions {
        target_list_size: 8,
        ..IvfBuildOptions::default()
    };
    let built: Vec<Vec<u8>> = KINDS
        .iter()
        .map(|&p| with_popcount(p, || build_tlsh_ivf(&rows, &opts).unwrap().to_bytes()))
        .collect();
    assert_eq!(built[0], built[1]);

    let ivf = build_tlsh_ivf(&rows, &opts).unwrap();
    let qs: Vec<TlshDigest> = (0..10).map(|i| TlshDigest(rows[i * 577])).collect();
    for p in KINDS {
        with_popcount(p, || check_index(&ivf, &rows)).unwrap();
        for q in &qs {
            let want = knn_brute(&rows, q, 20, 200, true);
            let got = with_popcount(p, || knn_ivf(&ivf, &rows, q, 20, 200, true, None).unwrap());
            assert_eq!(got, want, "{p:?}");
        }
    }
}
