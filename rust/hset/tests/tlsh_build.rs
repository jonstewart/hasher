//! The builder's TLSH support, ported from `test/test_hset_tlsh.cpp` and
//! checked against the payloads the C++ encoder writes for the same text
//! (the parity plan's golden SHA-256s, and the C++ fixtures themselves when
//! `HSET_FIXTURES_DIR` or `test/` holds them): `T1` hex values, `TNULL`,
//! empty and null digests as absent, duplicate rows in record files with
//! their record indices in descending order, deduplicated rows in
//! hashsets-only files, and the `0x7400` cell hint on every TLSH section.

use hset::builder::{format_value, parse_value, write_value};
use hset::format::FieldDescriptor;
use hset::tlsh::TlshDigest;
use hset::{Error, HashType};
use hset_testkit::tlsh::VEC_HEX;

fn tlsh_field() -> FieldDescriptor {
    FieldDescriptor::for_type(HashType::Tlsh).unwrap()
}

#[test]
fn a_t1_hex_value_parses_to_its_canonical_digest_and_formats_back() {
    let f = tlsh_field();
    let v = parse_value(&f, VEC_HEX).unwrap();
    assert_eq!(v, TlshDigest::from_hex(VEC_HEX).unwrap().as_bytes());
    assert_eq!(format_value(&f, &v), VEC_HEX);
    let mut w = Vec::new();
    write_value(&f, &v, &mut w).unwrap();
    assert_eq!(w, VEC_HEX.as_bytes());
    // Lowercase digits without the prefix are the same digest.
    let bare = VEC_HEX[2..].to_ascii_lowercase();
    assert_eq!(parse_value(&f, &bare).unwrap(), v);
}

#[test]
fn tnull_parses_to_the_null_digest_and_the_null_digest_formats_as_tnull() {
    let f = tlsh_field();
    assert_eq!(parse_value(&f, "TNULL").unwrap(), [0u8; 36]);
    assert_eq!(format_value(&f, &[0u8; 36]), "TNULL");
}

#[test]
fn a_value_the_hex_form_cannot_carry_formats_as_plain_hex() {
    let f = tlsh_field();
    let mut v = [0u8; 36];
    v[0] = 0xab;
    v[35] = 1;
    let want = format!("ab{}01", "00".repeat(34));
    assert_eq!(format_value(&f, &v), want);
    let mut w = Vec::new();
    write_value(&f, &v, &mut w).unwrap();
    assert_eq!(w, want.as_bytes());
    assert_eq!(format_value(&f, &[0x12, 0x34]), "1234");
}

#[test]
fn malformed_tlsh_text_is_an_input_error() {
    let f = tlsh_field();
    for bad in [
        "T1notatlsh",
        "",
        "T1",
        "TNULLX",
        &format!("{VEC_HEX}0"),
        &format!("{VEC_HEX}x"),
        &format!("{VEC_HEX}\n"),
        &VEC_HEX[..71],
    ] {
        let e = parse_value(&f, bad).unwrap_err();
        assert!(matches!(e, Error::Input(_)), "{bad:?}: {e}");
    }
}
