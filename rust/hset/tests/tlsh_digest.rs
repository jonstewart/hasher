//! `hset::tlsh` digest, hex and distance, ported from `test/test_tlsh.cpp`:
//! hex round trips and rejections, the decoded fields, distances against
//! the reference implementation's vendored scores, the cost tables, and
//! the body kernel against a bucket-by-bucket reference.

use hset::tlsh::{TlshDigest, diff};
use hset_testkit::tlsh::{VEC_HEX, example_digest_of, example_digests, example_scores};

fn digest(hex: &str) -> TlshDigest {
    TlshDigest::from_hex(hex).unwrap()
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
