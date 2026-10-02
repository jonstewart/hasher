//! Build, decode, verify and rebuild generated documents against the
//! `Doc` format oracle, plus the boundary and error examples.

use hset::format::{FieldDescriptor, decode};
use hset::{BuildOptions, Builder, Error, HashType};
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
