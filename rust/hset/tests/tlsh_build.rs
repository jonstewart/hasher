//! The builder's TLSH support, ported from `test/test_hset_tlsh.cpp` and
//! checked against the payloads the C++ encoder writes for the same text
//! (the parity plan's golden SHA-256s, and the C++ fixtures themselves when
//! `HSET_FIXTURES_DIR` or `test/` holds them): `T1` hex values, `TNULL`,
//! empty and null digests as absent, duplicate rows in record files with
//! their record indices in descending order, deduplicated rows in
//! hashsets-only files, and the `0x7400` cell hint on every TLSH section.

use hset::builder::{format_value, parse_value, write_value};
use hset::format::{FieldDescriptor, Hint, decode};
use hset::tlsh::{IvfIndex, TivfView, TlshDigest};
use hset::{BuildOptions, Builder, Error, HashType, HintSpec};
use hset_testkit::tlsh::{VEC_HEX, example_digests, example_text, fake_md5, naive_cell_index};
use sha2::{Digest, Sha256};

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

/// The SHA-256 of `b` in hex.
fn sha256(b: &[u8]) -> String {
    hset::hex::encode(&Sha256::digest(b))
}

/// A HINT chunk's payload: the tag, big-endian, then the table.
fn hint_payload(h: Hint) -> Vec<u8> {
    let (tag, table) = match h {
        Hint::Block { table, .. } | Hint::Hull { table, .. } | Hint::TlshCells { table } => {
            (h.tag(), table)
        }
        Hint::Unknown { tag, data } => (tag, data),
    };
    let mut v = tag.to_be_bytes().to_vec();
    v.extend_from_slice(table);
    v
}

/// The SHA-256s of one section's payloads: HDAT, HINT, RIDX.
#[derive(Debug, PartialEq)]
struct SectionShas {
    rows: usize,
    hdat: String,
    hint: Option<String>,
    ridx: Option<String>,
    /// The TIVF payload's SHA-256 and list count.
    tivf: Option<(String, usize)>,
}

/// The payload SHA-256s of a file: RDAT, the md5 and TLSH sections, and
/// the record count.
struct FileShas {
    rdat: Option<String>,
    md5: SectionShas,
    tlsh: SectionShas,
    records: usize,
}

fn payload_shas(bytes: &[u8]) -> FileShas {
    let f = decode(bytes).unwrap();
    let shas = |t| {
        let s = &f.sections[f.section_for(t).unwrap()];
        SectionShas {
            rows: s.len(),
            hdat: sha256(s.data),
            hint: s.hint.map(|h| sha256(&hint_payload(h))),
            ridx: s.ridx.map(sha256),
            tivf: s.tivf.map(|t| {
                let lists = TivfView::parse(t, s.len() as u64).unwrap().lists();
                (sha256(t), lists)
            }),
        }
    };
    FileShas {
        rdat: f.rdat.map(sha256),
        md5: shas(HashType::Md5),
        tlsh: shas(HashType::Tlsh),
        records: f.record_count(),
    }
}

/// The file `test_hset_tlsh.cpp` writes from `example_text(tlsh_first)`,
/// built here with the legacy hint so the md5 section's hint is C++'s too.
fn build_example(tlsh_first: bool, with_records: bool) -> Vec<u8> {
    let types = if tlsh_first {
        [HashType::Tlsh, HashType::Md5]
    } else {
        [HashType::Md5, HashType::Tlsh]
    };
    let mut b = Builder::new(&types).unwrap();
    assert_eq!(b.add_text(&example_text(tlsh_first)).unwrap(), 83);
    b.build(&opts().hint(HintSpec::LEGACY).records(with_records))
        .unwrap()
}

const TLSH_HDAT: &str = "1fff9e9fd92b2476394602397d5b50da43c541228f673d04c6e750453edfd8eb";
const TLSH_HINT: &str = "8259168b3f4538826c863bfdfbad819ca9007f80a421c31f124ce9317aec4669";
const MD5_HDAT: &str = "e078787ee34651399985009d7378dd4ebbc5cb946093e35cbd73cbd3ab74d467";
/// The TIVF payload of the records files (76 lists over 81 rows).
const TLSH_TIVF: &str = "4526562d16fc0251141dd786fc6a810f8bdda64dbd1db43dac06928bc7d901ef";
const MD5_LEGACY_HINT: &str = "42b51c20c1c4fa6b9c11f24e56eb5f3af6987b6aa4e21cb07a656b2cb824b4fe";

fn some(x: &str) -> Option<String> {
    Some(x.to_string())
}

/// md5_tlsh.hset: the parity plan's golden payloads (3.1); the md5 RIDX
/// SHA is the C++ fixture's.
#[test]
fn md5_tlsh_payloads_equal_the_cpp_encoders() {
    let got = payload_shas(&build_example(false, true));
    assert_eq!(got.records, 83);
    assert_eq!(
        got.rdat,
        some("408953dc8344947baffec8bb2c03081998cd0425dabcad56661e289bf437eae7")
    );
    assert_eq!(
        got.tlsh,
        SectionShas {
            rows: 81,
            hdat: TLSH_HDAT.into(),
            hint: some(TLSH_HINT),
            ridx: some("25bf41f60bad0e594fab58cfd12b94becb4e9c9fbab619f9bdd50c0d41636694"),
            tivf: Some((TLSH_TIVF.into(), 76)),
        }
    );
    assert_eq!(
        got.md5,
        SectionShas {
            rows: 83,
            hdat: MD5_HDAT.into(),
            hint: some(MD5_LEGACY_HINT),
            ridx: some("46dcdd0fd4a6c98d5e49ec05a41487b7d38bd67c1aff3efa400ed7ce1917231a"),
            tivf: None,
        }
    );
}

/// tlsh_md5.hset, the same text with the TLSH column first: the same
/// sections, records laid out TLSH first (RDAT and RIDX SHAs from the C++
/// fixture; the plan lists their prefixes 0a3d7b47 and 047ed8f9).
#[test]
fn tlsh_md5_payloads_equal_the_cpp_encoders() {
    let got = payload_shas(&build_example(true, true));
    assert_eq!(got.records, 83);
    assert_eq!(
        got.rdat,
        some("0a3d7b4710b199c256f5953a6cdfa12d25c13961d5f40e310a9853af7dbfe7ee")
    );
    assert_eq!(
        got.tlsh,
        SectionShas {
            rows: 81,
            hdat: TLSH_HDAT.into(),
            hint: some(TLSH_HINT),
            ridx: some("047ed8f99a69dd4e7e6dd0a9b59fe6958a52379bc2bf281f77b1dc318fe38498"),
            tivf: Some((TLSH_TIVF.into(), 76)),
        }
    );
    assert_eq!(
        got.md5,
        SectionShas {
            rows: 83,
            hdat: MD5_HDAT.into(),
            hint: some(MD5_LEGACY_HINT),
            ridx: some("3a2c8daacc6449a3ac403ed5e69f8a6a33792edd242c5762b88d20f59f93e8ef"),
            tivf: None,
        }
    );
}

/// md5_tlsh_ho.hset: hashsets only, so the 81 TLSH values dedup to 80
/// rows and nothing has a RIDX.
#[test]
fn md5_tlsh_hashsets_only_payloads_equal_the_cpp_encoders() {
    let got = payload_shas(&build_example(false, false));
    assert_eq!(got.records, 0);
    assert_eq!(got.rdat, None);
    assert_eq!(
        got.tlsh,
        SectionShas {
            rows: 80,
            hdat: "dfd6efe8bb7bc40136077922ea3cfa77c7e46a2bcc9886c5ccb1fb83a3cb980b".into(),
            hint: some("1c91d0c2f3f28dd89e301a02da13adfd903a57cdc7d8702ba2ff729d158d8258"),
            ridx: None,
            tivf: Some((
                "06f4d2ff581774066559d1094f0eda30e3421836615e255069c32026ec1d0d88".into(),
                76
            )),
        }
    );
    assert_eq!(
        got.md5,
        SectionShas {
            rows: 83,
            hdat: MD5_HDAT.into(),
            hint: some(MD5_LEGACY_HINT),
            ridx: None,
            tivf: None,
        }
    );
}

/// Without the legacy hint the md5 section gets the Rust default hint, and
/// everything else is unchanged.
#[test]
fn only_the_md5_hint_depends_on_the_hint_spec() {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    b.add_text(&example_text(false)).unwrap();
    let got = payload_shas(&b.build(&opts()).unwrap());
    let legacy = payload_shas(&build_example(false, true));
    assert_eq!(got.tlsh, legacy.tlsh);
    assert_eq!(got.rdat, legacy.rdat);
    assert_eq!(got.md5.hdat, legacy.md5.hdat);
    assert_eq!(got.md5.ridx, legacy.md5.ridx);
    assert_ne!(got.md5.hint, legacy.md5.hint);
}

/// The C++ files themselves, when `make check` has written them: every
/// payload, the TIVF index included, is the C++ encoder's.
#[test]
fn payloads_equal_the_cpp_fixtures_when_present() {
    for (name, tlsh_first, with_records) in [
        ("md5_tlsh.hset", false, true),
        ("tlsh_md5.hset", true, true),
        ("md5_tlsh_ho.hset", false, false),
    ] {
        let path = hset_testkit::fixtures::fixtures_dir().join(name);
        let Ok(theirs) = std::fs::read(&path) else {
            eprintln!(
                "SKIP: {} is absent (run the C++ make check)",
                path.display()
            );
            continue;
        };
        let ours = build_example(tlsh_first, with_records);
        let (a, b) = (decode(&ours).unwrap(), decode(&theirs).unwrap());
        assert_eq!(a.fhdr.name, b.fhdr.name, "{name}");
        assert_eq!(a.fhdr.desc, b.fhdr.desc, "{name}");
        assert_eq!(a.rhdr, b.rhdr, "{name}");
        assert_eq!(a.rdat, b.rdat, "{name}");
        assert_eq!(a.sections.len(), b.sections.len(), "{name}");
        for (x, y) in a.sections.iter().zip(&b.sections) {
            assert_eq!(x.header, y.header, "{name}");
            assert_eq!(x.data, y.data, "{name} {}", x.header.name);
            assert_eq!(x.hint, y.hint, "{name} {}", x.header.name);
            assert_eq!(x.ridx, y.ridx, "{name} {}", x.header.name);
            assert_eq!(x.tivf, y.tivf, "{name} {}", x.header.name);
            assert_eq!(
                x.tivf.is_some(),
                x.header.htype == HashType::Tlsh,
                "{name} {}",
                x.header.name
            );
        }
    }
}

#[test]
fn a_line_with_a_bad_tlsh_column_is_an_input_error() {
    // test_hset_tlsh.cpp hset_tlsh_bad_digest_throws
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    let md5 = fake_md5(0);
    for line in [
        format!("{md5} T1notatlsh"),
        format!("{md5} {VEC_HEX}junk"),
        format!("{md5} {VEC_HEX} junk"),
        format!("{md5} TNULL "),
    ] {
        let e = b.add_text_line(&line).unwrap_err();
        assert!(matches!(e, Error::Input(_)), "{line:?}: {e}");
    }
    let e = b.add_text(&format!("{md5} {VEC_HEX}\n{md5} T1notatlsh\n"));
    assert!(
        matches!(e, Err(Error::Input(ref m)) if m.starts_with("line 2")),
        "{e:?}"
    );
    assert_eq!(b.record_count(), 1);
}

/// The duplicated digest 7 is two rows, one per record, the later record
/// first (the plan's rows 57 and 58, records 82 and 7: md5s are distinct
/// and sort the records, and fake_md5(82) sorts last of the 83).
#[test]
fn duplicate_tlsh_rows_list_their_records_in_descending_order() {
    let bytes = build_example(false, true);
    let f = decode(&bytes).unwrap();
    let s = &f.sections[f.section_for(HashType::Tlsh).unwrap()];
    let dup = TlshDigest::from_hex(&example_digests()[7]).unwrap();
    let rows: Vec<usize> = (0..s.len())
        .filter(|&i| s.hash(i) == dup.as_bytes())
        .collect();
    assert_eq!(rows, [57, 58]);
    assert_eq!(s.record_index(57), Some(82));
    assert_eq!(s.record_index(58), Some(7));
    let md5_of = |r: u64| hset::hex::encode(&f.record(r as usize).unwrap()[1..17]);
    assert_eq!(md5_of(82), fake_md5(82));
    assert_eq!(md5_of(7), fake_md5(7));
}
