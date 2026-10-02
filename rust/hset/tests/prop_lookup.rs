//! Every lookup strategy (hint kind, search config, hash length) agrees
//! with the linear-scan `NaiveSet` oracle.

use hset_testkit::{checks::check_lookup, strategies::lookup_case};
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
