//! Corrupted files (FTOC and chunk-header edits, byte overwrites,
//! truncation) never panic the decoder or lookups, and never pass the
//! digest unless nothing changed.

use hset_testkit::checks::check_corruption;
use hset_testkit::strategies::{corruption, doc};
use proptest::prelude::*;

proptest! {
    // 64 cases, not the default 256 (the plan allows this file a reduced
    // count): a case costs about 7.5 ms in debug builds (20000 cases took
    // 150 s), so 64 keeps the gate's share near 0.5 s. `just prop` and
    // `PROPTEST_CASES` still override this.
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn corruption_is_safe(d in doc(), c in corruption()) {
        check_corruption(&d, &c);
    }
}
