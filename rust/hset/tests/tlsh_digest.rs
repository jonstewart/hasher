//! `hset::tlsh` digest, hex and distance, ported from `test/test_tlsh.cpp`:
//! hex round trips and rejections, the decoded fields, distances against
//! the reference implementation's vendored scores, the cost tables, and
//! the body kernel against a bucket-by-bucket reference.

use hset::tlsh::{
    BodyQuery, TlshDigest, body_diff, diff, emb_body_dist2, header_diff, l_cost, mod_diff, q_cost,
};
use hset_testkit::tlsh::{VEC_HEX, example_digest_of, example_digests, example_scores};
use proptest::prelude::*;

fn digest(hex: &str) -> TlshDigest {
    TlshDigest::from_hex(hex).unwrap()
}

// Independent reference costs, written from the reference implementation's
// rules rather than calling the crate's tables.

fn circ(x: u8, y: u8, r: i32) -> i32 {
    let d = (i32::from(x) - i32::from(y)).abs();
    d.min(r - d)
}

fn ref_l_cost(k: i32) -> u32 {
    match k {
        0 => 0,
        1 => 1,
        _ => 12 * k as u32,
    }
}

fn ref_q_cost(k: i32) -> u32 {
    if k <= 1 {
        k as u32
    } else {
        12 * (k as u32 - 1)
    }
}

fn ref_header(a: &TlshDigest, b: &TlshDigest, include_length: bool) -> u32 {
    let l = if include_length {
        ref_l_cost(circ(a.l(), b.l(), 256))
    } else {
        0
    };
    u32::from(a.checksum() != b.checksum())
        + l
        + ref_q_cost(circ(a.q1(), b.q1(), 16))
        + ref_q_cost(circ(a.q2(), b.q2(), 16))
}

/// Sum over buckets of `cost[|code_a - code_b|]`.
fn ref_body(a: &TlshDigest, b: &TlshDigest, cost: [u32; 4]) -> u32 {
    (0..128)
        .map(|i| cost[usize::from(a.bucket(i).abs_diff(b.bucket(i)))])
        .sum()
}

const TLSH_BODY: [u32; 4] = [0, 1, 2, 6];
const EMB_BODY: [u32; 4] = [0, 1, 2, 5];

fn arb_digest() -> impl Strategy<Value = TlshDigest> {
    (
        any::<u8>(),
        0u8..16,
        0u8..16,
        any::<u8>(),
        proptest::array::uniform32(0u8..4),
        proptest::array::uniform32(0u8..4),
        proptest::array::uniform32(0u8..4),
        proptest::array::uniform32(0u8..4),
    )
        .prop_map(|(l, q1, q2, cs, c0, c1, c2, c3)| {
            let mut codes = [0u8; 128];
            for (k, part) in [c0, c1, c2, c3].iter().enumerate() {
                codes[32 * k..32 * (k + 1)].copy_from_slice(part);
            }
            TlshDigest::from_parts(l, q1, q2, cs, &codes)
        })
}

#[test]
fn cost_tables_match_hand_values() {
    assert_eq!(
        [l_cost(0), l_cost(1), l_cost(2), l_cost(128)],
        [0, 1, 24, 1536]
    );
    assert_eq!([q_cost(0), q_cost(1), q_cost(2), q_cost(8)], [0, 1, 12, 84]);
    assert_eq!(mod_diff(1, 255, 256), 2);
    assert_eq!(mod_diff(255, 1, 256), 2);
    assert_eq!(mod_diff(0, 128, 256), 128);
    assert_eq!(mod_diff(3, 10, 16), 7);
    assert_eq!(mod_diff(2, 15, 16), 3);
    assert_eq!(mod_diff(7, 7, 16), 0);
}

#[test]
fn diff_of_null_is_none() {
    let d = digest(VEC_HEX);
    assert_eq!(diff(&d, &TlshDigest::NULL, true), None);
    assert_eq!(diff(&TlshDigest::NULL, &d, false), None);
    assert_eq!(diff(&TlshDigest::NULL, &TlshDigest::NULL, true), None);
    assert_eq!(diff(&d, &d, true), Some(0));
}

#[test]
fn single_bucket_costs() {
    // every pair of codes in one bucket, all else equal
    for bucket in [0, 7, 8, 63, 64, 127] {
        for ca in 0u8..4 {
            for cb in 0u8..4 {
                let mut codes_a = [0u8; 128];
                let mut codes_b = [0u8; 128];
                codes_a[bucket] = ca;
                codes_b[bucket] = cb;
                let a = TlshDigest::from_parts(50, 3, 4, 7, &codes_a);
                let b = TlshDigest::from_parts(50, 3, 4, 7, &codes_b);
                let want = [0, 1, 2, 6][usize::from(ca.abs_diff(cb))];
                let want_emb = [0, 1, 2, 5][usize::from(ca.abs_diff(cb))];
                assert_eq!(body_diff(&a, &b), want, "bucket {bucket} {ca} {cb}");
                assert_eq!(diff(&a, &b, true), Some(want));
                assert_eq!(emb_body_dist2(&a, &b), want_emb);
                assert_eq!(BodyQuery::new(&a).body(&b.0), want);
                assert_eq!(BodyQuery::new(&a).emb_body(&b.0), want_emb);
            }
        }
    }
}

#[test]
fn header_costs() {
    let z = [0u8; 128];
    let base = TlshDigest::from_parts(100, 5, 9, 42, &z);
    for k in 0u32..256 {
        let o = TlshDigest::from_parts(((100 + k) % 256) as u8, 5, 9, 42, &z);
        let md = k.min(256 - k);
        let want = match md {
            0 => 0,
            1 => 1,
            _ => 12 * md,
        };
        assert_eq!(diff(&base, &o, true), Some(want), "L + {k}");
        assert_eq!(diff(&base, &o, false), Some(0), "L + {k}");
        assert_eq!(header_diff(&base, &o, true), want);
    }
    for k in 0u32..16 {
        let md = k.min(16 - k);
        let want = if md <= 1 { md } else { 12 * (md - 1) };
        let q1 = TlshDigest::from_parts(100, ((5 + k) % 16) as u8, 9, 42, &z);
        let q2 = TlshDigest::from_parts(100, 5, ((9 + k) % 16) as u8, 42, &z);
        assert_eq!(diff(&base, &q1, true), Some(want), "Q1 + {k}");
        assert_eq!(diff(&base, &q2, true), Some(want), "Q2 + {k}");
        assert_eq!(diff(&base, &q2, false), Some(want), "Q2 + {k}");
    }
    let cs = TlshDigest::from_parts(100, 5, 9, 43, &z);
    assert_eq!(diff(&base, &cs, true), Some(1));
    assert_eq!(diff(&base, &cs, false), Some(1));
}

proptest! {
    #[test]
    fn kernels_match_the_bucket_reference(q in arb_digest(), r in arb_digest()) {
        let body = ref_body(&q, &r, TLSH_BODY);
        let emb = ref_body(&q, &r, EMB_BODY);
        let qb = BodyQuery::new(&q);
        prop_assert_eq!(qb.body(&r.0), body);
        prop_assert_eq!(qb.emb_body(&r.0), emb);
        prop_assert_eq!(body_diff(&q, &r), body);
        prop_assert_eq!(emb_body_dist2(&q, &r), emb);
        for incl in [true, false] {
            prop_assert_eq!(header_diff(&q, &r, incl), ref_header(&q, &r, incl));
            let want = (!q.is_null() && !r.is_null()).then(|| ref_header(&q, &r, incl) + body);
            prop_assert_eq!(diff(&q, &r, incl), want);
            prop_assert_eq!(diff(&r, &q, incl), want);
        }
    }

    #[test]
    fn hex_round_trips_any_digest(d in arb_digest()) {
        let hex = d.to_hex();
        prop_assert_eq!(TlshDigest::from_hex(&hex).unwrap(), d);
        if d.is_null() {
            prop_assert_eq!(hex, "TNULL");
        } else {
            prop_assert_eq!(hex.len(), 72);
            prop_assert!(hex.starts_with("T1"));
        }
    }

    #[test]
    fn any_70_hex_digits_parse_and_format_in_uppercase(
        s in "[0-9a-fA-F]{70}",
        prefix in any::<bool>(),
    ) {
        let input = if prefix { format!("T1{s}") } else { s.clone() };
        let d = TlshDigest::from_hex(&input).unwrap();
        let want = if s.bytes().all(|c| c == b'0') {
            "TNULL".to_string()
        } else {
            format!("T1{}", s.to_uppercase())
        };
        prop_assert_eq!(d.to_hex(), want);
    }
}

#[test]
fn diff_matches_reference_scores() {
    for include_length in [true, false] {
        for (a, b, score) in example_scores(include_length) {
            let da = digest(&example_digest_of(&a));
            let db = digest(&example_digest_of(&b));
            assert_eq!(diff(&da, &db, include_length), Some(score), "{a} {b}");
            assert_eq!(diff(&db, &da, include_length), Some(score), "{b} {a}");
        }
    }
}

#[test]
fn hex_round_trips() {
    let d = TlshDigest::from_hex(VEC_HEX).unwrap();
    assert_eq!(d.to_hex(), VEC_HEX);
}

#[test]
fn hex_decodes_to_hand_computed_fields() {
    // "T1" 1F A1 B3 57 F7 .. FF CE: checksum 0x1F and L 0xA1 nibble-swapped,
    // Q 0xB3; body byte 0 is the last pair (0xCE: codes 2, 3, 0, 3 from the
    // low bits up), body byte 31 the first (0x57: codes 3, 1, 1, 1).
    let d = TlshDigest::from_hex(VEC_HEX).unwrap();
    assert_eq!(d.checksum(), 0xF1);
    assert_eq!(d.l(), 0x1A);
    assert_eq!(d.q(), 0xB3);
    assert_eq!((d.q1(), d.q2()), (11, 3));
    assert_eq!(
        [d.bucket(0), d.bucket(1), d.bucket(2), d.bucket(3)],
        [2, 3, 0, 3]
    );
    assert_eq!(
        [d.bucket(124), d.bucket(125), d.bucket(126), d.bucket(127)],
        [3, 1, 1, 1]
    );
    assert_eq!(d.cell(), 0x1AB3);
    assert!(!d.is_null());
    // canonical bytes: buckets 0..8 are 2,3,0,3,3,3,3,3 -> hi 0xFB, lo 0xFA;
    // buckets 120..128 are 3,1,3,3,3,1,1,1 -> hi 0x1D, lo 0xFF.
    let b = d.as_bytes();
    assert_eq!((b[0], b[1], b[34], b[35]), (0x1A, 0xB3, 0xF1, 0));
    assert_eq!((b[2], b[18]), (0xFB, 0xFA));
    assert_eq!((b[17], b[33]), (0x1D, 0xFF));
}

#[test]
fn hex_without_prefix_in_lowercase_parses() {
    let lower = VEC_HEX[2..].to_lowercase();
    assert_eq!(
        TlshDigest::from_hex(&lower).unwrap(),
        TlshDigest::from_hex(VEC_HEX).unwrap()
    );
}

#[test]
fn tnull_is_the_null_digest() {
    let d = TlshDigest::from_hex("TNULL").unwrap();
    assert!(d.is_null());
    assert_eq!(d, TlshDigest::NULL);
    assert_eq!(d.as_bytes(), &[0u8; 36]);
    assert_eq!(TlshDigest::NULL.to_hex(), "TNULL");
    // 70 zero digits decode to the same all-zero digest
    let zeros = format!("T1{}", "0".repeat(70));
    assert!(TlshDigest::from_hex(&zeros).unwrap().is_null());
}

#[test]
fn hex_rejects_garbage() {
    let mut bad_digit = VEC_HEX.to_string();
    bad_digit.replace_range(10..11, "G");
    let rejected = [
        String::new(),
        "T1".to_string(),
        format!("T2{}", &VEC_HEX[2..]),
        VEC_HEX[..71].to_string(),
        format!("{VEC_HEX}A"),
        bad_digit,
        "TNULLX".to_string(),
        "tnull".to_string(),
        format!("t1{}", &VEC_HEX[2..]),
        // 72 hex digits without the prefix
        format!("11{}", &VEC_HEX[2..]),
        // Rust is strict where C++ accepts a non-hex character after the
        // 70th digit
        format!("{VEC_HEX} "),
        format!("{VEC_HEX}\n"),
        format!("{VEC_HEX}x"),
        format!("{} ", &VEC_HEX[2..]),
        format!(" {VEC_HEX}"),
    ];
    for s in &rejected {
        let e = TlshDigest::from_hex(s).unwrap_err();
        assert!(matches!(e, hset::Error::Input(_)), "{s:?}: {e}");
    }
}

#[test]
fn example_digests_round_trip() {
    let digests = example_digests();
    let mut parsed: Vec<TlshDigest> = digests
        .iter()
        .map(|h| TlshDigest::from_hex(h).unwrap())
        .collect();
    for (hex, d) in digests.iter().zip(&parsed) {
        assert_eq!(&d.to_hex(), hex);
        assert!(!d.is_null());
    }
    parsed.sort();
    parsed.dedup();
    assert_eq!(parsed.len(), 80);
}

#[test]
fn from_parts_lays_out_the_canonical_bytes() {
    let mut codes = [0u8; 128];
    codes[0] = 1; // lo plane byte 0 bit 0
    codes[9] = 2; // hi plane byte 1 bit 1
    codes[127] = 3; // both planes, byte 15 bit 7
    let d = TlshDigest::from_parts(200, 0xA, 0x5, 0x77, &codes);
    let mut want = [0u8; 36];
    want[0] = 200;
    want[1] = 0xA5;
    want[18] = 0x01;
    want[2 + 1] = 0x02;
    want[2 + 15] = 0x80;
    want[18 + 15] = 0x80;
    want[34] = 0x77;
    assert_eq!(d.0, want);
    assert_eq!(
        (d.bucket(0), d.bucket(9), d.bucket(127), d.bucket(1)),
        (1, 2, 3, 0)
    );
    assert_eq!(d.cell(), (200 << 8) | 0xA5);
    // as make_tlsh_digest: only the low bits of q1, q2 and the codes count
    let masked = TlshDigest::from_parts(200, 0xFA, 0xF5, 0x77, &codes.map(|c| c | 0xFC));
    assert_eq!(masked, d);
}

#[test]
#[should_panic(expected = "out of range")]
fn bucket_128_panics() {
    TlshDigest::NULL.bucket(128);
}

#[test]
fn from_bytes_requires_a_zero_reserved_byte() {
    let d = TlshDigest::from_hex(VEC_HEX).unwrap();
    assert_eq!(TlshDigest::from_bytes(&d.0).unwrap(), d);
    assert_eq!(TlshDigest::from_bytes(&[0; 36]).unwrap(), TlshDigest::NULL);
    let mut bad = d.0;
    bad[35] = 1;
    let e = TlshDigest::from_bytes(&bad).unwrap_err();
    assert!(matches!(e, hset::Error::Input(_)), "{e}");
    assert!(e.to_string().contains("reserved"), "{e}");
}

#[test]
fn display_from_str_and_write_hex_agree_with_to_hex() {
    let d: TlshDigest = VEC_HEX.parse().unwrap();
    assert_eq!(d.to_string(), VEC_HEX);
    let mut out = Vec::new();
    d.write_hex(&mut out).unwrap();
    TlshDigest::NULL.write_hex(&mut out).unwrap();
    assert_eq!(out, format!("{VEC_HEX}TNULL").as_bytes());
    assert_eq!(format!("{}", TlshDigest::NULL), "TNULL");
    assert!("T1".parse::<TlshDigest>().is_err());
    assert_eq!(format!("{d:?}"), format!("TlshDigest({VEC_HEX})"));
    let mut r = d;
    r.0[35] = 0x42;
    assert_eq!(
        format!("{r:?}"),
        format!("TlshDigest({VEC_HEX}, reserved=0x42)")
    );
}

#[test]
fn canonical_order_is_bytewise() {
    // L, then Q1, then Q2 dominate the order
    let z = [0u8; 128];
    let a = TlshDigest::from_parts(10, 15, 15, 255, &z);
    let b = TlshDigest::from_parts(11, 0, 0, 0, &z);
    let c = TlshDigest::from_parts(11, 1, 0, 0, &z);
    let d = TlshDigest::from_parts(11, 1, 1, 0, &z);
    assert!(a < b && b < c && c < d);
    // then the body before the checksum
    let mut one = z;
    one[0] = 1;
    let e = TlshDigest::from_parts(11, 1, 1, 0, &one);
    let f = TlshDigest::from_parts(11, 1, 1, 255, &z);
    assert!(f < e);
}
