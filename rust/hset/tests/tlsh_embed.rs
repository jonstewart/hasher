//! `hset::tlsh::embed`, ported from `test/test_tlsh_embedding.cpp`: the
//! `i8` body embedding the BISECT build clusters on, and the 264-dimension
//! `f32` embedding whose squared distance lower-bounds the TLSH distance
//! (`docs/TLSH_EMBEDDING.md` section 1).

use hset::tlsh::embed::{
    EMBED_BODY_DIMS, EMBED_DIMS, EMBED_L_DIM, EMBED_MAX_BOUNDED_DIFF, embed, embed_body_i8,
    embed_dist2,
};
use hset::tlsh::mt64::Mt19937_64;
use hset::tlsh::{TlshDigest, diff, emb_body_dist2};
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
        assert_eq!(
            (v[2 * i], v[2 * i + 1]),
            (BX[i % 4], BY[i % 4]),
            "bucket {i}"
        );
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
        let checksum_bits = v[261..264].iter().map(|x| x.to_bits());
        assert!(checksum_bits.eq([0x3f13cd3a; 3]), "{:?}", &v[261..264]);
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
        assert_eq!(
            embed_dist2(&e0, &ei, true).to_bits(),
            incl,
            "e0, e{i}, with length"
        );
        assert_eq!(
            embed_dist2(&e0, &ei, false).to_bits(),
            excl,
            "e0, e{i}, without length"
        );
    }
}

/// `embed_dist2` of the embeddings of two digests.
fn d2(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> f32 {
    embed_dist2(&embed(a), &embed(b), include_length)
}

/// The TLSH distance of two non-null digests.
fn tlsh(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> u32 {
    diff(a, b, include_length).expect("non-null digests")
}

#[test]
fn body_component_bounds_every_code_pair() {
    // every pair of codes in a single bucket, all else equal: TLSH costs
    // 0, 1, 2, 6 and squared embedding distances 0, 1, 2, 5 by |ca - cb|
    let cost = [0, 1, 2, 6];
    let expected = [0.0, 1.0, 2.0, 5.0];
    for bucket in [0, 1, 64, 127] {
        for ca in 0..4u8 {
            for cb in 0..4u8 {
                let (mut codes_a, mut codes_b) = ([0; 128], [0; 128]);
                codes_a[bucket] = ca;
                codes_b[bucket] = cb;
                let a = TlshDigest::from_parts(50, 0, 0, 0, &codes_a);
                let b = TlshDigest::from_parts(50, 0, 0, 0, &codes_b);
                let k = usize::from(ca.abs_diff(cb));
                for incl in [true, false] {
                    let e = d2(&a, &b, incl);
                    assert_eq!(e, expected[k], "bucket {bucket}, codes {ca} {cb}");
                    assert!(e <= cost[k] as f32);
                    assert_eq!(tlsh(&a, &b, incl), cost[k]);
                }
            }
        }
    }
}

#[test]
fn length_component_is_k_squared_and_bounded_up_to_k_12() {
    let a = TlshDigest::from_parts(100, 0, 0, 0, &[0; 128]);
    for k in 0..=12u8 {
        let b = TlshDigest::from_parts(100 + k, 0, 0, 0, &[0; 128]);
        let e = d2(&a, &b, true);
        assert_eq!(e, f32::from(k) * f32::from(k), "k = {k}");
        assert!(e <= tlsh(&a, &b, true) as f32, "k = {k}");
        assert_eq!(d2(&a, &b, false), 0.0, "k = {k}");
    }
    // beyond k = 12 the TLSH distance exceeds 144 and the bound is not
    // promised (k = 13: 169 against 156 here)
    let far = TlshDigest::from_parts(113, 0, 0, 0, &[0; 128]);
    assert!(tlsh(&a, &far, true) > EMBED_MAX_BOUNDED_DIFF);
}

#[test]
fn length_wraparound_is_not_bounded() {
    // TLSH charges L mod 256 (255 vs 0 is a difference of 1), the
    // embedding is linear (255^2): the documented terabyte-input caveat
    let a = TlshDigest::from_parts(255, 0, 0, 0, &[1; 128]);
    let b = TlshDigest::from_parts(0, 0, 0, 0, &[1; 128]);
    assert_eq!(tlsh(&a, &b, true), 1);
    assert_eq!(d2(&a, &b, true), 255.0 * 255.0);
    // without the length both are 0
    assert_eq!((tlsh(&a, &b, false), d2(&a, &b, false)), (0, 0.0));
}

#[test]
fn q_components_are_bounded_for_every_pair() {
    for which in [1, 2] {
        for qa in 0..16u8 {
            for qb in 0..16u8 {
                let with_q = |q: u8| {
                    let (q1, q2) = if which == 1 { (q, 0) } else { (0, q) };
                    TlshDigest::from_parts(50, q1, q2, 0, &[0; 128])
                };
                let (a, b) = (with_q(qa), with_q(qb));
                let e = d2(&a, &b, true);
                assert!(
                    e <= tlsh(&a, &b, true) as f32 + 1e-4,
                    "Q{which} {qa} {qb}: {e}"
                );
                assert_eq!(d2(&a, &b, false), e, "Q{which} {qa} {qb}");
                let k = qa.abs_diff(qb).min(16 - qa.abs_diff(qb));
                if k == 1 {
                    assert_approx(f64::from(e), 1.0, 1e-5, "adjacent Q");
                }
            }
        }
    }
}

#[test]
fn checksum_component_is_at_most_1() {
    for ca in (0..=255u8).step_by(7) {
        for cb in (0..=255u8).step_by(5) {
            let a = TlshDigest::from_parts(50, 0, 0, ca, &[0; 128]);
            let b = TlshDigest::from_parts(50, 0, 0, cb, &[0; 128]);
            let e = d2(&a, &b, true);
            let cost = if ca == cb { 0.0 } else { 1.0 };
            assert!(e <= cost + 1e-6, "checksums {ca} {cb}: {e}");
            // popcount of the differing low three bits, over 3
            let bits = ((ca ^ cb) & 7).count_ones() as f32;
            assert!((e - bits / 3.0).abs() <= 1e-5, "checksums {ca} {cb}: {e}");
        }
    }
}

/// A random non-null digest with `L` in `lo..=hi`.
fn random_digest(g: &mut Mt19937_64, lo: u8, hi: u8) -> TlshDigest {
    let mut d = [0u8; 36];
    for b in &mut d[1..35] {
        *b = g.next_u64() as u8;
    }
    d[0] = lo + (g.next_u64() % (u64::from(hi - lo) + 1)) as u8;
    d[34] |= 1; // never null
    TlshDigest(d)
}

/// `d` with every bucket redrawn with probability `p`, L moved by up to
/// 2, Q1 and Q2 by up to 1 (mod 16) and the checksum redrawn half the
/// time: a near pair, as `perturb_tlsh_corpus` makes them.
fn perturb(g: &mut Mt19937_64, d: &TlshDigest, p: f64) -> TlshDigest {
    let mut codes = [0u8; 128];
    for (i, c) in codes.iter_mut().enumerate() {
        let redraw = (g.next_u64() % 1_000_000) as f64 / 1e6 < p;
        *c = if redraw {
            (g.next_u64() % 4) as u8
        } else {
            d.bucket(i)
        };
    }
    let step = |g: &mut Mt19937_64, max: u64| (g.next_u64() % (2 * max + 1)) as i32 - max as i32;
    let l = (i32::from(d.l()) + step(g, 2)) as u8;
    let q1 = (i32::from(d.q1()) + step(g, 1)).rem_euclid(16) as u8;
    let q2 = (i32::from(d.q2()) + step(g, 1)).rem_euclid(16) as u8;
    let cs = if g.next_u64().is_multiple_of(2) {
        d.checksum()
    } else {
        g.next_u64() as u8 | 1
    };
    TlshDigest::from_parts(l, q1, q2, cs, &codes)
}

#[test]
fn lower_bound_on_near_and_random_pairs() {
    // test_tlsh_embedding.cpp tlsh_embed_lower_bound_on_corpus_pairs: near
    // pairs (a digest against a perturbation of itself) and random pairs,
    // both distance variants; L kept clear of the mod-256 wrap
    let mut g = Mt19937_64::new(4242);
    let (mut bounded_pairs, mut tightness) = (0usize, 0f64);
    for i in 0..6000 {
        let a = random_digest(&mut g, 3, 252);
        let b = if i < 3000 {
            perturb(&mut g, &a, 0.05)
        } else {
            random_digest(&mut g, 3, 252)
        };
        for incl in [true, false] {
            let t = tlsh(&a, &b, incl);
            let e = d2(&a, &b, incl);
            if !incl || t <= EMBED_MAX_BOUNDED_DIFF {
                assert!(e <= t as f32 + 1e-3, "{a} {b} incl {incl}: {e} > {t}");
                if incl && t > 0 {
                    bounded_pairs += 1;
                    tightness += f64::from(e) / f64::from(t);
                }
            }
        }
    }
    assert!(bounded_pairs > 100, "{bounded_pairs} bounded pairs");
    // the bound should be reasonably tight on near pairs
    let mean = tightness / bounded_pairs as f64;
    assert!(mean > 0.5, "mean tightness {mean}");
}

/// Any 36-byte digest with a zero reserved byte.
fn any_digest() -> impl Strategy<Value = TlshDigest> {
    any::<[u8; 35]>().prop_map(|b| {
        let mut d = [0u8; 36];
        d[..35].copy_from_slice(&b);
        TlshDigest(d)
    })
}

proptest! {
    #[test]
    fn without_length_the_bound_holds_for_every_pair(a in any_digest(), b in any_digest()) {
        prop_assume!(!a.is_null() && !b.is_null());
        prop_assert!(d2(&a, &b, false) <= tlsh(&a, &b, false) as f32 + 1e-3);
    }

    #[test]
    fn with_length_the_bound_holds_up_to_144_without_wrap(
        a in any_digest(),
        edits in prop::collection::vec((0..128usize, 0..4u8), 0..8),
        dl in -8i32..=8,
        dq1 in -1i32..=1,
        dq2 in -1i32..=1,
        checksum in any::<u8>(),
    ) {
        // b is near a: a few buckets recoded, L moved by at most 8 without
        // crossing the mod-256 wrap, Q1 and Q2 by at most 1; at most
        // 1 + 96 + 2 + 48 = 147, so nearly every pair is under the cap
        let l = (i32::from(a.l()) + dl).clamp(0, 255);
        let mut codes: [u8; 128] = std::array::from_fn(|i| a.bucket(i));
        for (i, c) in edits {
            codes[i] = c;
        }
        let q = |q: u8, dq: i32| (i32::from(q) + dq).rem_euclid(16) as u8;
        let b = TlshDigest::from_parts(l as u8, q(a.q1(), dq1), q(a.q2(), dq2), checksum, &codes);
        prop_assume!(!a.is_null() && !b.is_null());
        let t = tlsh(&a, &b, true);
        if t <= EMBED_MAX_BOUNDED_DIFF {
            prop_assert!(d2(&a, &b, true) <= t as f32 + 1e-3);
        }
    }

    #[test]
    fn body_of_the_full_embedding_is_the_i8_embedding(d in any_digest()) {
        let v = embed(&d);
        let mut b = [0i8; EMBED_BODY_DIMS];
        embed_body_i8(&d.0, &mut b);
        for j in 0..EMBED_BODY_DIMS {
            prop_assert_eq!(v[j], f32::from(b[j]), "dim {}", j);
        }
    }

    #[test]
    fn body_part_of_embed_dist2_is_emb_body_dist2(a in any_digest(), b in any_digest()) {
        // with equal headers only the body differs
        let mut b = b;
        b.0[0] = a.0[0];
        b.0[1] = a.0[1];
        b.0[34] = a.0[34];
        prop_assert_eq!(d2(&a, &b, true), emb_body_dist2(&a, &b) as f32);
    }
}
