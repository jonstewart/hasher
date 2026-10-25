//! `hset::tlsh` digest, hex and distance, ported from `test/test_tlsh.cpp`:
//! hex round trips and rejections, the decoded fields, distances against
//! the reference implementation's vendored scores, the cost tables, and
//! the body kernel against a bucket-by-bucket reference.

use hset::tlsh::TlshDigest;
use hset_testkit::tlsh::VEC_HEX;

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
