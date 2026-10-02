//! Every lookup strategy (hint kind, search config, hash length) agrees
//! with the linear-scan `NaiveSet` oracle.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use hset::lookup::{HintSpec, SearchConfig, SingleMode};
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
