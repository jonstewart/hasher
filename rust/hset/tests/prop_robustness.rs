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

/// A valid four-hash MD5 file with a 2-bit flat block hint whose four
/// `(min, max)` deviation entries are overwritten with `entries`. Every
/// entry has `min <= max`, so the loader treats every block as non-empty.
fn file_with_block_hint_entries(entries: [(i64, i64); 4]) -> Vec<u8> {
    use hset::format::{Hint, decode};
    use hset::{BuildOptions, Builder, HashType, HintSpec};

    let mut b = Builder::new(&[HashType::Md5]).unwrap();
    for top in [0x00u8, 0x40, 0x80, 0xC0] {
        let mut md5 = [0x11u8; 16];
        md5[0] = top;
        b.add_record(&[Some(&md5)]).unwrap();
    }
    let opts = BuildOptions::new("extreme", "flat hint bounds")
        .timestamp("2026-10-02T00:00:00Z")
        .hint(HintSpec::Block { bits: 2 });
    let mut bytes = b.build(&opts).unwrap();

    let at = {
        let file = decode(&bytes).unwrap();
        let Some(Hint::Block { bits: 2, table }) = file.sections[0].hint else {
            panic!(
                "expected a 2-bit block hint, got {:?}",
                file.sections[0].hint
            );
        };
        table.as_ptr() as usize - bytes.as_ptr() as usize
    };
    for (k, (lo, hi)) in entries.iter().enumerate() {
        let e = at + 16 * k;
        bytes[e..e + 8].copy_from_slice(&lo.to_le_bytes());
        bytes[e + 8..e + 16].copy_from_slice(&hi.to_le_bytes());
    }
    bytes
}

/// Fuzz finding (`decode_bytes`, crash-20aa62e8…, a mutated
/// `test/good.hset`): a flat block hint whose `(min, max)` deviation
/// entries hold extreme `i64`s panicked with an arithmetic overflow in
/// `FlatBlocks::mean_window` (`hi - lo + 1`) while loading. The artifact
/// is 21 KiB of raw bytes, so this rebuilds the same shape: a valid file
/// with a 2-bit block hint, one extreme entry per block. The decoder
/// checks a hint's shape, not its values, so the file must still load; a
/// wrong hint may only make lookups miss.
#[test]
fn flat_block_hint_with_extreme_bounds_does_not_panic() {
    let bytes = file_with_block_hint_entries([
        (i64::MIN, 0),
        (0, i64::MAX),
        (i64::MAX, i64::MAX),
        (i64::MIN, i64::MAX),
    ]);
    assert!(hset_testkit::checks::exercise_loaded(&bytes), "should load");
}

/// The same finding, centre side: entries of `(i64::MIN, i64::MIN)` put
/// the model's predicted centre near `i64::MIN`, and the region-radius
/// sample taken at construction computed `index - centre`, overflowing
/// for every stored hash at or past its expected index.
#[test]
fn flat_block_hint_with_minimal_centre_does_not_panic() {
    let bytes = file_with_block_hint_entries([(i64::MIN, i64::MIN); 4]);
    assert!(hset_testkit::checks::exercise_loaded(&bytes), "should load");
}

/// Fuzz finding (`corrupt_doc`, crash-398d5600…): an empty SHA-1 hash set
/// with four byte overwrites in its header aborted with "memory allocation
/// of 601295421460 bytes failed" instead of being rejected or loaded.
#[test]
fn corrupt_empty_sha1_section_does_not_over_allocate() {
    use hset::{BitsPolicy, HashType, HintSpec};
    use hset_testkit::corrupt::Corruption;
    use hset_testkit::doc::{Doc, Field, Opts};

    let doc = Doc {
        fields: vec![Field {
            htype: HashType::Sha1,
            name: "sha1".to_string(),
        }],
        records: vec![],
        opts: Opts {
            name: String::new(),
            desc: String::new(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            with_records: false,
            with_hashsets: true,
            hint: HintSpec::None,
            bits_policy: BitsPolicy {
                budget: 0.0,
                min_bits: 0,
                max_bits: 10,
            },
            ..Opts::default_for_tests()
        },
    };
    let c = Corruption {
        truncate_to: None,
        overwrites: vec![
            (35980, 0),
            (10127624197330698240, 140),
            (10123402072680074380, 140),
            (10127624197330734220, 125),
        ],
        chunk_edits: vec![],
    };
    let bytes = doc.build().expect("build");
    let m = c.apply(&bytes);
    assert!(hset_testkit::checks::exercise_loaded(&m), "should load");
}
