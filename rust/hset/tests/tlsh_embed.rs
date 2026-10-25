//! `hset::tlsh::embed`, ported from `test/test_tlsh_embedding.cpp`: the
//! `i8` body embedding the BISECT build clusters on, and the 264-dimension
//! `f32` embedding whose squared distance lower-bounds the TLSH distance
//! (`docs/TLSH_EMBEDDING.md` section 1).

use hset::tlsh::TlshDigest;
use hset::tlsh::embed::{EMBED_BODY_DIMS, embed_body_i8};

/// The code table of `docs/TLSH_EMBEDDING.md`: code -> (x, y).
const BX: [i8; 4] = [1, 0, 0, -1];
const BY: [i8; 4] = [0, 0, 1, 1];

fn codes_mod4() -> [u8; 128] {
    std::array::from_fn(|i| (i % 4) as u8)
}

#[test]
fn i8_body_of_codes_0123_follows_the_table_with_norm_128() {
    // squared norms 1 + 0 + 1 + 2 per four buckets, 32 x 4 = 128
    let d = TlshDigest::from_parts(77, 3, 12, 5, &codes_mod4());
    let mut v = [0x55i8; EMBED_BODY_DIMS];
    assert_eq!(embed_body_i8(&d.0, &mut v), 128);
    for i in 0..128 {
        assert_eq!((v[2 * i], v[2 * i + 1]), (BX[i % 4], BY[i % 4]), "bucket {i}");
    }
}
