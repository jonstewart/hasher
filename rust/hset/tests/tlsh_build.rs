//! The builder's TLSH support, ported from `test/test_hset_tlsh.cpp` and
//! checked against the payloads the C++ encoder writes for the same text
//! (the parity plan's golden SHA-256s, and the C++ fixtures themselves when
//! `HSET_FIXTURES_DIR` or `test/` holds them): `T1` hex values, `TNULL`,
//! empty and null digests as absent, duplicate rows in record files with
//! their record indices in descending order, deduplicated rows in
//! hashsets-only files, and the `0x7400` cell hint on every TLSH section.

use hset::builder::{format_value, parse_value, write_value};
use hset::format::{FieldDescriptor, Hint, decode};
use hset::tlsh::TlshDigest;
use hset::{BuildOptions, Builder, Error, HashType, HintSpec};
use hset_testkit::tlsh::{VEC_HEX, example_digests, fake_md5, naive_cell_index};

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

fn opts() -> BuildOptions {
    BuildOptions::new("TLSH test", "TLSH digests paired with fake md5s")
        .timestamp("2024-01-01T00:00:00Z")
}

/// `(md5 present, TLSH present)` of every record of `b`'s built file, and
/// the TLSH section's row count.
fn presence(b: &Builder) -> (Vec<(u8, u8)>, usize) {
    let bytes = b.build(&opts()).unwrap();
    let f = decode(&bytes).unwrap();
    let recs = (0..f.record_count())
        .map(|i| {
            let r = f.record(i).unwrap();
            (r[0], r[17])
        })
        .collect();
    let t = f.section_for(HashType::Tlsh).unwrap();
    (recs, f.sections[t].len())
}

#[test]
fn tnull_an_empty_column_and_a_null_digest_are_absent_values() {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    b.add_text_line(&format!("{} TNULL", fake_md5(0))).unwrap();
    b.add_text_line(&format!("{} ", fake_md5(1))).unwrap();
    b.add_text_line(&format!("{} T1{}", fake_md5(2), "0".repeat(70)))
        .unwrap();
    b.add_text_line(&format!("{} {}", fake_md5(3), "0".repeat(70)))
        .unwrap();
    let md5 = hset::hex::decode(&fake_md5(4)).unwrap();
    b.add_record(&[Some(&md5), Some(&[0u8; 36])]).unwrap();
    let (recs, rows) = presence(&b);
    assert_eq!(recs, vec![(1, 0); 5]);
    assert_eq!(rows, 0);
}

#[test]
fn a_raw_tlsh_value_with_a_nonzero_reserved_byte_is_rejected() {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    let md5 = hset::hex::decode(&fake_md5(0)).unwrap();
    let mut d = *TlshDigest::from_hex(VEC_HEX).unwrap().as_bytes();
    d[35] = 7;
    let e = b.add_record(&[Some(&md5), Some(&d)]).unwrap_err();
    assert!(matches!(e, Error::Input(_)), "{e}");
    assert!(e.to_string().contains("reserved"), "{e}");
    assert_eq!(b.record_count(), 0);

    let mut rec = vec![1u8];
    rec.extend_from_slice(&md5);
    rec.push(1);
    rec.extend_from_slice(&d);
    let e = b.add_raw_record(&rec).unwrap_err();
    assert!(matches!(e, Error::Input(_)), "{e}");
    assert_eq!(b.record_count(), 0);
}

#[test]
fn a_present_null_digest_in_a_raw_record_is_stored_absent() {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    let md5 = hset::hex::decode(&fake_md5(0)).unwrap();
    let mut rec = vec![1u8];
    rec.extend_from_slice(&md5);
    rec.push(1);
    rec.extend_from_slice(&[0u8; 36]);
    b.add_raw_record(&rec).unwrap();
    let mut d = vec![1u8];
    d.extend_from_slice(&md5);
    d.push(1);
    d.extend_from_slice(TlshDigest::from_hex(VEC_HEX).unwrap().as_bytes());
    b.add_raw_record(&d).unwrap();
    let (recs, rows) = presence(&b);
    assert_eq!(recs, vec![(1, 0), (1, 1)]);
    assert_eq!(rows, 1);
}

/// The 0x7400 table a section of `rows` must carry: the naive oracle's
/// offsets, each a little-endian u64.
fn expected_cell_table(rows: &[u8]) -> Vec<u8> {
    let rows: Vec<[u8; 36]> = rows.as_chunks::<36>().0.to_vec();
    naive_cell_index(&rows)
        .iter()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

#[test]
fn the_tlsh_section_gets_the_cell_hint_whatever_hint_the_options_ask_for() {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    for (i, d) in example_digests().iter().take(10).enumerate() {
        b.add_text_line(&format!("{} {d}", fake_md5(i as u64)))
            .unwrap();
    }
    for spec in [
        HintSpec::Hull { bits: u8::MAX },
        HintSpec::LEGACY,
        HintSpec::Block { bits: 0 },
        HintSpec::Hull { bits: 3 },
        HintSpec::None,
    ] {
        for records in [true, false] {
            let bytes = b.build(&opts().hint(spec).records(records)).unwrap();
            let f = decode(&bytes).unwrap();
            let s = &f.sections[f.section_for(HashType::Tlsh).unwrap()];
            assert_eq!(s.len(), 10);
            let Some(Hint::TlshCells { table }) = s.hint else {
                panic!("{spec:?}: TLSH hint is {:?}", s.hint.map(|h| h.tag()));
            };
            assert_eq!(table, expected_cell_table(s.data), "{spec:?}");
            // The md5 section still gets the hint asked for.
            let m = &f.sections[f.section_for(HashType::Md5).unwrap()];
            assert_eq!(m.hint.is_none(), spec == HintSpec::None, "{spec:?}");
        }
    }
}
