//! `hset::tlsh::embed`, ported from `test/test_tlsh_embedding.cpp`: the
//! `i8` body embedding the BISECT build clusters on, and the 264-dimension
//! `f32` embedding whose squared distance lower-bounds the TLSH distance
//! (`docs/TLSH_EMBEDDING.md` section 1).

use hset::tlsh::embed::{EMBED_BODY_DIMS, embed_body_i8};
use hset::tlsh::{TlshDigest, emb_body_dist2};
use proptest::prelude::*;

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

/// The all-code-1 body, whose embedding is the zero vector, with a
/// header that is not all zero.
fn origin() -> TlshDigest {
    TlshDigest::from_parts(1, 2, 3, 4, &[1; 128])
}

#[test]
fn i8_body_of_all_code_1_is_the_zero_vector() {
    let mut v = [0x55i8; EMBED_BODY_DIMS];
    assert_eq!(embed_body_i8(&origin().0, &mut v), 0);
    assert!(v.iter().all(|&x| x == 0));
}

/// A digest with `origin`'s header and the given bit planes.
fn with_planes(hi: [u8; 16], lo: [u8; 16]) -> TlshDigest {
    let mut d = origin();
    d.0[2..18].copy_from_slice(&hi);
    d.0[18..34].copy_from_slice(&lo);
    d
}

proptest! {
    #[test]
    fn i8_body_follows_the_table_and_its_norm_is_the_distance_to_all_code_1(
        hi in any::<[u8; 16]>(),
        lo in any::<[u8; 16]>(),
    ) {
        let d = with_planes(hi, lo);
        let mut v = [0x55i8; EMBED_BODY_DIMS];
        let norm2 = embed_body_i8(&d.0, &mut v);
        for i in 0..128 {
            let c = usize::from(d.bucket(i));
            prop_assert_eq!((v[2 * i], v[2 * i + 1]), (BX[c], BY[c]), "bucket {}", i);
        }
        let sum: u32 = v.iter().map(|&x| u32::from(x.unsigned_abs())).sum();
        prop_assert_eq!(norm2, sum);
        prop_assert_eq!(norm2, emb_body_dist2(&d, &origin()));
    }
}
