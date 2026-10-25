//! `hset::tlsh::embed`, ported from `test/test_tlsh_embedding.cpp`: the
//! `i8` body embedding the BISECT build clusters on, and the 264-dimension
//! `f32` embedding whose squared distance lower-bounds the TLSH distance
//! (`docs/TLSH_EMBEDDING.md` section 1).

use hset::tlsh::embed::{
    EMBED_BODY_DIMS, EMBED_DIMS, EMBED_L_DIM, EMBED_MAX_BOUNDED_DIFF, embed, embed_body_i8,
    embed_dist2,
};
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

/// Assert `|got - want| <= eps * |want|` (Catch's `Approx(want).epsilon`).
fn assert_approx(got: f64, want: f64, eps: f64, what: &str) {
    assert!(
        (got - want).abs() <= eps * want.abs(),
        "{what}: {got} is not within {eps} of {want}"
    );
}

#[test]
fn full_embedding_dims_and_layout() {
    assert_eq!(EMBED_DIMS, 264);
    assert_eq!(EMBED_BODY_DIMS, 256);
    assert_eq!(EMBED_L_DIM, 256);
    assert_eq!(EMBED_MAX_BOUNDED_DIFF, 144);

    let v = embed(&TlshDigest::from_parts(77, 3, 12, 0b101, &codes_mod4()));
    // body coordinates are in {-1, 0, 1} and follow the code table
    for i in 0..128 {
        assert_eq!(v[2 * i], f32::from(BX[i % 4]), "bucket {i} x");
        assert_eq!(v[2 * i + 1], f32::from(BY[i % 4]), "bucket {i} y");
    }
    assert_eq!(v[256], 77.0);
    // Q points lie on the circle of radius 1 / (2 sin(pi/16))
    let r = 1.0 / (2.0 * (std::f64::consts::PI / 16.0).sin());
    let hypot = |x: f32, y: f32| f64::from(x).hypot(f64::from(y));
    assert_approx(hypot(v[257], v[258]), r, 1e-5, "Q1 radius");
    assert_approx(hypot(v[259], v[260]), r, 1e-5, "Q2 radius");
    // Q1 = 3 -> angle 3 * 2pi / 16, Q2 = 12 -> angle 12 * 2pi / 16
    let angle = |q: f64| q * 2.0 * std::f64::consts::PI / 16.0;
    assert_approx(f64::from(v[257]), r * angle(3.0).cos(), 1e-5, "Q1 x");
    assert_approx(f64::from(v[258]), r * angle(3.0).sin(), 1e-5, "Q1 y");
    assert_approx(f64::from(v[260]), r * angle(12.0).sin(), 1e-5, "Q2 y");
    // checksum bits 0, 1, 2 scaled by 1/sqrt(3)
    let cs = 1.0 / 3f64.sqrt();
    assert_approx(f64::from(v[261]), cs, 1e-6, "checksum bit 0");
    assert_eq!(v[262], 0.0);
    assert_approx(f64::from(v[263]), cs, 1e-6, "checksum bit 2");
}
