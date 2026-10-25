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

/// `(x, y)` f32 bit patterns of the Q 16-gon vertex for q = 0..16, as
/// `sfhash_tlsh_embed` of libhasher (x86-64, glibc) writes them into dims
/// 257, 258 (and 259, 260 for Q2). The near-zero values (q = 4, 8, 12) are
/// the double rounding errors of cos(pi/2), sin(pi), cos(3 pi/2).
const CPP_Q_BITS: [(u32, u32); 16] = [
    (0x402406cf, 0x00000000),
    (0x40178a72, 0x3f7b14be),
    (0x3fe7f7f8, 0x3fe7f7f8),
    (0x3f7b14be, 0x40178a72),
    (0x2534ee8a, 0x402406cf),
    (0xbf7b14be, 0x40178a72),
    (0xbfe7f7f8, 0x3fe7f7f8),
    (0xc0178a72, 0x3f7b14be),
    (0xc02406cf, 0x25b4ee8a),
    (0xc0178a72, 0xbf7b14be),
    (0xbfe7f7f8, 0xbfe7f7f8),
    (0xbf7b14be, 0xc0178a72),
    (0xa607b2e7, 0xc02406cf),
    (0x3f7b14be, 0xc0178a72),
    (0x3fe7f7f8, 0xbfe7f7f8),
    (0x40178a72, 0xbf7b14be),
];

#[test]
fn q_and_checksum_coordinates_are_the_cpp_bits() {
    for (q, &(x, y)) in CPP_Q_BITS.iter().enumerate() {
        let q = q as u8;
        let v = embed(&TlshDigest::from_parts(50, q, 15 - q, 7, &[0; 128]));
        assert_eq!((v[257].to_bits(), v[258].to_bits()), (x, y), "Q1 = {q}");
        assert_eq!(
            (v[259].to_bits(), v[260].to_bits()),
            CPP_Q_BITS[usize::from(15 - q)],
            "Q2 = {}",
            15 - q
        );
        // checksum 7: all three bits, (float)(1 / sqrt(3.0))
        for dim in 261..264 {
            assert_eq!(v[dim].to_bits(), 0x3f13cd3a, "dim {dim}");
        }
    }
}

/// The first six example digests (`example_data.128.1.len.out_EXP`).
const EXAMPLES: [&str; 6] = [
    "T11FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE",
    "T145D18407A78523B35A030267671FA2C2F725402973629B25545EB43C3356679477F7FC",
    "T1C8E1E8277B98A6255FA70063B70FBAE1F6618229332C9438084FB331178ADEE53B41D5",
    "T1E951784702042376169012B1BA5A76EAF36092FC3311A595B4856235278F9F973763EF",
    "T106D29517F780237185070293B60E36FAB735C0F833D66460688DA22D6756E751B7BAEB",
    "T135214031F3C6AEA059EB1ABA870E8C4758D70024C63224B5D4C89354E46315D26BF736",
];

fn example(i: usize) -> TlshDigest {
    TlshDigest::from_hex(EXAMPLES[i]).unwrap()
}

#[test]
fn embed_dist2_of_example_pairs_is_the_cpp_bits() {
    // sfhash_tlsh_embed_dist2(phi(e0), phi(ei), incl) from libhasher, as
    // f32 bit patterns: (i, with length, without length)
    let cpp = [
        (1, 0x42cf8d85, 0x42bd8d85),
        (2, 0x4333f0d8, 0x4323f0d8),
        (3, 0x432f4d2d, 0x43164d2d),
        (4, 0x43ed83b2, 0x42e40ec8),
        (5, 0x4388dbce, 0x4351b79c),
    ];
    let e0 = embed(&example(0));
    for (i, incl, excl) in cpp {
        let ei = embed(&example(i));
        assert_eq!(embed_dist2(&e0, &ei, true).to_bits(), incl, "e0, e{i}, with length");
        assert_eq!(embed_dist2(&e0, &ei, false).to_bits(), excl, "e0, e{i}, without length");
    }
}
