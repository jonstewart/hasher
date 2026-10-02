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

/// Fuzz finding (`decode_bytes`, crash-20aa62e8…, a mutated
/// `test/good.hset`): a flat block hint whose `(min, max)` deviation
/// entries hold extreme `i64`s panicked with an arithmetic overflow in
/// `FlatBlocks::mean_window` (`hi - lo + 1`) while loading. The artifact
/// is 21 KiB of raw bytes, so this rebuilds the same shape: a valid file
/// with a 2-bit block hint, one entry per extreme, one hash per block.
#[test]
fn flat_block_hint_with_extreme_bounds_does_not_panic() {
    use hset::format::{Hint, decode};
    use hset::{BuildOptions, Builder, HashType, HintSpec};
    use hset_testkit::checks::exercise_loaded;

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
    let entries: [(i64, i64); 4] = [
        (i64::MIN, 0),
        (0, i64::MAX),
        (i64::MAX, i64::MAX),
        (i64::MIN, i64::MAX),
    ];
    for (k, (lo, hi)) in entries.iter().enumerate() {
        let e = at + 16 * k;
        bytes[e..e + 8].copy_from_slice(&lo.to_le_bytes());
        bytes[e + 8..e + 16].copy_from_slice(&hi.to_le_bytes());
    }
    exercise_loaded(&bytes);
}
