//! Build, decode, verify and rebuild generated documents against the
//! `Doc` format oracle, plus the boundary and error examples.

use hset::format::{FieldDescriptor, decode};
use hset::lookup::BitsPolicy;
use hset::{BuildOptions, Builder, Error, HashType, HintSpec};
use hset_testkit::doc::{Doc, Field, Opts};
use hset_testkit::{checks::check_doc_roundtrip, strategies::doc};
use proptest::prelude::*;

proptest! {
    #[test]
    fn build_decode_matches_oracle(d in doc()) {
        check_doc_roundtrip(&d);
    }
}

const TS: &str = "2024-01-01T00:00:00Z";

fn md5_field(name: String) -> FieldDescriptor {
    FieldDescriptor {
        htype: HashType::Md5,
        name,
        length: 16,
    }
}

/// Review Focus 2: pstrings of exactly 65535 bytes are written and decode
/// intact; 65536 bytes is an input error, for the name, the description
/// and a field name.
#[test]
fn pstring_length_boundary() {
    let max = "a".repeat(65535);
    let over = "a".repeat(65536);
    let md5 = || Builder::new(&[HashType::Md5]).unwrap();

    let bytes = md5()
        .build(&BuildOptions::new(max.clone(), "d").timestamp(TS))
        .unwrap();
    assert_eq!(decode(&bytes).unwrap().fhdr.name.len(), 65535);
    let r = md5().build(&BuildOptions::new(over.clone(), "d").timestamp(TS));
    assert!(matches!(r, Err(Error::Input(_))), "name of 65536: {r:?}");

    let bytes = md5()
        .build(&BuildOptions::new("n", max.clone()).timestamp(TS))
        .unwrap();
    assert_eq!(decode(&bytes).unwrap().fhdr.desc.len(), 65535);
    let r = md5().build(&BuildOptions::new("n", over.clone()).timestamp(TS));
    assert!(matches!(r, Err(Error::Input(_))), "desc of 65536: {r:?}");

    let opts = BuildOptions::new("n", "d").timestamp(TS);
    let bytes = Builder::with_fields(vec![md5_field(max)])
        .build(&opts)
        .unwrap();
    let file = decode(&bytes).unwrap();
    assert_eq!(file.rhdr.as_ref().unwrap().fields[0].name.len(), 65535);
    assert_eq!(file.sections[0].header.name.len(), 65535);
    let r = Builder::with_fields(vec![md5_field(over)]).build(&opts);
    assert!(
        matches!(r, Err(Error::Input(_))),
        "field name of 65536: {r:?}"
    );
}

/// A document that asks for neither records nor hash sets does not build.
#[test]
fn both_outputs_disabled_is_an_error() {
    let mut opts = Opts::default_for_tests();
    opts.with_records = false;
    opts.with_hashsets = false;
    let doc = Doc {
        fields: vec![Field::canonical(HashType::Md5)],
        records: vec![vec![Some(vec![0x11; 16])]],
        opts,
    };
    let r = doc.build();
    assert!(matches!(r, Err(Error::Input(_))), "{r:?}");
}

/// Shrunk proptest case: two SHA-512 hashes in one hull block at 10 bits
/// (`80 ff ff ff ff 80 ..` and `80 ff ff ff ff ff ..`). `verify` reported
/// "hint window excludes a stored hash" on hset's own output.
#[test]
fn hull_two_hashes_in_one_block_verify() {
    let hash = |b5: u8| {
        let mut h = vec![0u8; 64];
        h[..6].copy_from_slice(&[0x80, 0xff, 0xff, 0xff, 0xff, b5]);
        Some(h)
    };
    let mut opts = Opts::default_for_tests();
    opts.name = String::new();
    opts.desc = String::new();
    opts.hint = HintSpec::Hull { bits: 10 };
    opts.bits_policy = BitsPolicy {
        budget: 0.0,
        min_bits: 0,
        max_bits: 0,
    };
    let doc = Doc {
        fields: vec![Field {
            htype: HashType::Sha2_512,
            name: "Y 2 v7-_Qpy l__N _X".to_string(),
        }],
        records: vec![vec![hash(0xff)], vec![hash(0x80)]],
        opts,
    };
    check_doc_roundtrip(&doc);
}

/// Fuzz finding (`text_input`, crash-9ccfbb73…, bytes `0d 0d a6`, which
/// `Arbitrary for &str` decodes to `"\r\r"`): `add_text_line` trimmed
/// every trailing `'\r'`/`'\n'`, so a line of two carriage returns was
/// taken as blank. Like the C++ line reader, only one `'\r'` is a line
/// ending; the second is content, and not a valid column. (`add_text`
/// splits with `str::lines`, which already takes the `"\r\n"` of a
/// `"\r\r\n"` ending, so that line keeps one `'\r'` and is accepted.)
#[test]
fn text_line_strips_only_one_carriage_return() {
    let md5 = "00112233445566778899aabbccddeeff";
    for (text, ok) in [
        ("\r\r", false),
        (&format!("{md5}\r\r") as &str, false),
        (&format!("{md5}\r\r\n") as &str, true),
        ("\r", true),
        (&format!("{md5}\r\n{md5}\r") as &str, true),
    ] {
        let mut b = Builder::new(&[HashType::Md5]).unwrap();
        let r = b.add_text(text);
        assert_eq!(r.is_ok(), ok, "{text:?}: {r:?}");
    }
}
