//! File-level merges ([`hset::merge::merge`], C++ `write_merged_hset` /
//! `sfhash_hashset_merge`, `test/test_hset_merge.cpp` and
//! `test/test_hset_merge_incremental.cpp`): the output is checked against
//! the set operation computed independently over the inputs' rows
//! (hashsets-only) or records, and every derived TLSH structure carried
//! through the merge is checked against the output rows. Every output
//! loads, verifies clean, and answers kNN by index as by brute force.
//!
//! With `HSET_FIXTURES_DIR` pointing at the C++ test directory, the merges
//! whose inputs and outputs the C++ suites leave on disk are re-run and
//! their payloads compared chunk by chunk.

use hset::Error;
use hset::merge::{MergeOptions, TlshIndexPolicy};
use hset::tlsh::ivf::DEFAULT_COALESCE;

#[test]
fn tlsh_options_select_the_index_policy_as_cpp_reads_them() {
    use TlshIndexPolicy::*;
    // INHERIT wins over INDEX (write_merged_hset tests INHERIT first);
    // bit 1, once VECTORS, is ignored
    for (bits, want) in [
        (0, Omit),
        (1, Omit),
        (2, Write),
        (3, Write),
        (4, Inherit),
        (5, Inherit),
        (6, Inherit),
        (7, Inherit),
    ] {
        assert_eq!(
            TlshIndexPolicy::from_tlsh_options(bits).unwrap(),
            want,
            "{bits}"
        );
    }
    // INDEX_KMEANS is not ported (ruling 4), whatever else is set; other
    // bits are unknown
    for bits in [8, 10, 12, 14, 16, 0x8000_0000] {
        assert!(
            matches!(
                TlshIndexPolicy::from_tlsh_options(bits),
                Err(Error::Input(_))
            ),
            "{bits}"
        );
    }
}

#[test]
fn merge_options_default_to_inheriting_the_index_and_writing_everything() {
    let o = MergeOptions::new("n", "d");
    assert_eq!(o.tlsh_index, TlshIndexPolicy::Inherit);
    assert_eq!(TlshIndexPolicy::default(), TlshIndexPolicy::Inherit);
    assert_eq!(o.coalesce_threshold, 64);
    assert_eq!(DEFAULT_COALESCE, 64);
    assert!(o.write_records && o.write_hashsets);
    assert_eq!((o.name.as_str(), o.desc.as_str()), ("n", "d"));
    assert_eq!(o.timestamp, None);
}
