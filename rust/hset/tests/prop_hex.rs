//! The hex codec (`hset::hex`) at every SIMD level, against the
//! from-scratch `hex_oracle`: per-level encode/decode agreement and digit
//! rejection, the row APIs, and odd-length rejection.

use hset_testkit::checks::{check_hex, check_hex_rows};
use proptest::collection::vec;
use proptest::prelude::*;

proptest! {
    // 256 cases (the default) made this test alone cost about 4.5 s: each
    // case checks up to 300 bytes at 2 SIMD levels, and for each level
    // tries 4 bad digits at up to 64 positions against both decode APIs
    // (`check_hex`'s rejection sweep), so the per-case cost is dominated
    // by that sweep rather than by exploring the input space. 64 cases
    // keeps this file well under a second while still exercising every
    // code path; `just prop` and `PROPTEST_CASES` still override this.
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn levels_agree_with_oracle(bytes in vec(any::<u8>(), 0..=300)) {
        check_hex(&bytes);
    }
}

proptest! {
    #[test]
    fn rows_agree_with_oracle(
        rows in vec(any::<u8>(), 0..=400),
        width in 1usize..=70,
        sep in vec(any::<u8>(), 0..=3),
    ) {
        let data = &rows[..rows.len() / width * width];
        check_hex_rows(data, width, &sep);
    }

    #[test]
    fn odd_length_rejected(s in "[0-9a-fA-F]*") {
        prop_assert_eq!(hset::hex::decode(&s).is_ok(), s.len() % 2 == 0);
    }
}
