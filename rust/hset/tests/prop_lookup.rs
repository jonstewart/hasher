//! Every lookup strategy (hint kind, search config, hash length) agrees
//! with the linear-scan `NaiveSet` oracle.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use hset::lookup::{BatchMode, HintSpec, SearchConfig, SingleMode};
use hset_testkit::{
    checks::check_lookup,
    strategies::{LookupCase, lookup_case},
};
use proptest::prelude::*;

proptest! {
    // 128 cases, not the default 256: in debug builds a case costs about
    // 85 ms (about 70 ms in `NaiveSet`'s linear scans over up to 2000 rows
    // for every query and stored hash, the rest generating the case), so
    // 256 cases took about 22 s and pushed `just test` to 25 s warm.
    // `just prop` and `PROPTEST_CASES` still override this.
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn strategies_match_naive(case in lookup_case()) {
        check_lookup(&case);
    }
}

/// Run `check_lookup` on another thread so a search that never terminates
/// fails the test instead of hanging the suite.
fn check_lookup_within(case: LookupCase, limit: Duration) {
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        check_lookup(&case);
        let _ = tx.send(());
    });
    match rx.recv_timeout(limit) {
        Ok(()) => worker.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The check panicked: re-raise its panic here.
            if let Err(p) = worker.join() {
                std::panic::resume_unwind(p);
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("check_lookup did not finish in {limit:?}"),
    }
}

/// Found by `strategies_match_naive` as a hang (hand-minimised: proptest
/// cannot shrink a case that never returns). With `window_prefetch_bytes`
/// below eight hashes, the k-ary single search kept stepping a window of
/// width 1 that `kary_step` (which needs more than 8 hashes) never shrank.
#[test]
fn kary_terminates_with_prefetch_below_eight_hashes() {
    let case = LookupCase {
        hlen: 4,
        data: vec![1, 0, 0, 0, 2, 0, 0, 0],
        hint: HintSpec::None,
        cfg: SearchConfig {
            single: SingleMode::KAry,
            window_prefetch_bytes: 1,
            ..SearchConfig::default()
        },
        queries: vec![0, 0, 0, 0],
    };
    check_lookup_within(case, Duration::from_secs(10));
}

/// k-ary search with a prefetch budget below one hash must stop stepping
/// once the window is down to eight hashes, wherever the window sits (the
/// stored hashes past index 8 are the ones that exercise this).
#[test]
fn kary_stops_at_eight_hashes_anywhere_in_the_array() {
    let data: Vec<u8> = (0..32u32).flat_map(|i| (i << 27).to_be_bytes()).collect();
    let case = LookupCase {
        hlen: 4,
        queries: data.clone(),
        data,
        hint: HintSpec::None,
        cfg: SearchConfig {
            single: SingleMode::KAry,
            window_prefetch_bytes: 1,
            ..SearchConfig::default()
        },
    };
    check_lookup_within(case, Duration::from_secs(10));
}

/// Sixteen 4-byte hashes: twelve with leading words 0..12 (expected index
/// 0, deviations 0..=11) and four at 0x8000_0000.. (expected index 8 of 16,
/// deviations 4..=7), so a 1-bit flat hint has blocks (0, 11) and (4, 7).
fn two_block_set() -> Vec<u8> {
    (0..12u32)
        .chain((0..4).map(|j| 0x8000_0000 + j))
        .flat_map(u32::to_be_bytes)
        .collect()
}

/// Recursive lane batches start at the model's centre clamped into the
/// window. For 0xB0000000 (expected index 11) block 1 gives the window
/// [15, 16) and the centre 11 + (4 + 7) / 2 = 16, one past the last hash.
#[test]
fn lanes_clamp_the_first_probe_into_the_window() {
    let data = two_block_set();
    let mut queries = [0xB0u8, 0, 0, 0].repeat(4);
    queries.extend_from_slice(&data[..16]);
    let case = LookupCase {
        hlen: 4,
        data,
        hint: HintSpec::Block { bits: 1 },
        cfg: SearchConfig {
            single: SingleMode::Recursive,
            batch: BatchMode::Lanes,
            window_prefetch_bytes: 0,
            ..SearchConfig::default()
        },
        queries,
    };
    check_lookup_within(case, Duration::from_secs(10));
}

/// Recursive lane batches clamp each re-aimed probe into the bracket.
/// Ninety tiny keys then ten from 2^63 upwards: for hash 95 (key
/// 21/32 * 2^64) the first probe is index 65, and the density step from
/// key 65 is 65 positions, aiming at 131, far past the last index, 99.
#[test]
fn lanes_clamp_re_aimed_probes_into_the_bracket() {
    let data: Vec<u8> = (0..100u64)
        .flat_map(|i| {
            let key = if i < 90 {
                i
            } else {
                (1 << 63) + ((i - 90) << 59)
            };
            [key.to_be_bytes(), i.to_be_bytes()].concat()
        })
        .collect();
    let mut queries = data[95 * 16..96 * 16].repeat(4);
    queries.extend_from_slice(&data[..4 * 16]);
    let case = LookupCase {
        hlen: 16,
        data,
        hint: HintSpec::None,
        cfg: SearchConfig {
            single: SingleMode::Recursive,
            batch: BatchMode::Lanes,
            window_prefetch_bytes: 0,
            ..SearchConfig::default()
        },
        queries,
    };
    check_lookup_within(case, Duration::from_secs(10));
}

/// The passes batch prefetches recursive regions from each query's own
/// hash: the flat model reads its expected index from it.
#[test]
fn passes_prefetch_regions_from_each_query_hash() {
    let data = two_block_set();
    let case = LookupCase {
        hlen: 4,
        queries: data.clone(),
        data,
        hint: HintSpec::Block { bits: 1 },
        cfg: SearchConfig {
            single: SingleMode::Recursive,
            batch: BatchMode::Passes,
            window_prefetch_bytes: 0,
            ..SearchConfig::default()
        },
    };
    check_lookup_within(case, Duration::from_secs(10));
}
