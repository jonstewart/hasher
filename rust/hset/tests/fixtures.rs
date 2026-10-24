//! Interoperability with files written by the reference C++ implementation
//! (the `test/*.hset` fixtures in the repository root).

use std::path::PathBuf;

use hset::format::{Hint, decode};
use hset::{BuildOptions, Builder, HashType, Hashset, HintSpec, SetOp, hex, ops};

fn fixture_path(name: &str) -> PathBuf {
    hset_testkit::fixtures::fixtures_dir().join(name)
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| panic!("reading fixture {name}: {e}"))
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn good_hset_matches_reference_expectations() {
    let bytes = fixture("good.hset");
    let hs = Hashset::load(&bytes).unwrap();
    assert_eq!(hs.name(), "Test Name");
    assert_eq!(hs.description(), "Test Description");
    assert_eq!(hs.timestamp(), "2023-01-09T17:02:18Z");
    assert_eq!(
        hex::encode(hs.sha2_256()),
        "2e407e9e82dcd606e9edb1062dbfcd1b32a75acfe5c0d2fdd903a32ee2af772a"
    );
    assert!(hs.verify_digest());
    assert_eq!(hs.section_count(), 1);
    let s = hs.section(0);
    assert_eq!(s.header.htype, HashType::Sha1);
    assert_eq!(s.header.name, "sha1");
    assert_eq!(s.header.hash_length, 20);
    assert_eq!(s.len(), 665);
    assert!(matches!(s.hint, Some(Hint::Block { bits: 8, .. })));
    assert!(hs.record_header().is_none());

    let idx = hs.index_for_type(HashType::Sha1).unwrap();
    let cases = [
        ("0053e9b602c2fa8473262b590f6d24a406ae1cc2", false), // before first
        ("0053e9b602c2fa8473262b590f6d24a406ae1cc3", true),  // first
        ("286ba1181663193d119d7ca18331395cd451de91", true),
        ("bc658126e1443d6455287378e4c273b08f947d3c", true),
        ("baaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaad", false),
        ("ff36a8ea9b657f9c068d91a67195dd0764fd75ff", true), // last
        ("ff36a8ea9b657f9c068d91a67195dd0764fd7600", false), // after last
    ];
    let mut batch_in = Vec::new();
    for (hash, expect) in cases {
        let hb = h(hash);
        assert_eq!(hs.contains(idx, &hb), expect, "{hash}");
        batch_in.extend_from_slice(&hb);
    }
    let mut out = vec![false; cases.len()];
    hs.contains_batch(idx, &batch_in, &mut out);
    assert_eq!(out, cases.iter().map(|c| c.1).collect::<Vec<_>>());
    assert_eq!(
        hs.find(idx, &h("0053e9b602c2fa8473262b590f6d24a406ae1cc3")),
        Some(0)
    );
    assert_eq!(
        hs.find(idx, &h("ff36a8ea9b657f9c068d91a67195dd0764fd75ff")),
        Some(664)
    );

    // Every stored hash is found, and the legacy hint is sound.
    for i in 0..s.len() {
        assert_eq!(hs.find(idx, s.hash(i)), Some(i));
    }
    let report = hs.verify();
    assert!(report.is_ok(), "{:?}", report.problems);
}

#[test]
fn all_fixtures_decode_and_verify() {
    let dir = fixture_path("");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        // Skip macOS AppleDouble sidecar files that may accompany the fixtures.
        if p.extension().is_some_and(|e| e == "hset") && !name.starts_with("._") {
            let bytes = std::fs::read(&p).unwrap();
            // tlsh_bad.hset is what the C++ hset_tlsh_bad_digest_throws test
            // leaves behind when the writer throws partway through
            if name == "bogus.hset" || name == "tlsh_bad.hset" {
                assert!(Hashset::load(&bytes).is_err(), "{name} should not load");
                continue;
            }
            let hs = match Hashset::load(&bytes) {
                Ok(hs) => hs,
                // 0123456789_*.hset and test1.hset are version-1 files, which
                // neither this crate nor the C++ decoder reads.
                Err(e) if e.to_string().contains("version 1") => continue,
                // The C++ suite also writes files with TLSH (2^15) hash sets
                // or record fields, which this crate does not read yet.
                Err(e) if e.to_string().ends_with("type 2^15") => continue,
                Err(e) => panic!("{name}: {e}"),
            };
            let report = hs.verify();
            // Every invariant must hold, including soundness of the legacy
            // hints and the record indices (the C++ encoder scrambled RIDX
            // until tlsh-embedding's 300ace3 fixed its proxy-iterator sort).
            assert!(report.problems.is_empty(), "{name}: {:?}", report.problems);
            assert!(report.digest_ok, "{name}: digest");
            for (i, s) in hs.sections().iter().enumerate() {
                for j in 0..s.len() {
                    assert!(hs.contains(i, s.hash(j)), "{name}: section {i} hash {j}");
                }
            }
            seen += 1;
        }
    }
    assert!(seen >= 6, "expected the reference fixtures, found {seen}");
}

#[test]
fn scrambled_record_indices_are_detected() {
    // Reverse the first section's RIDX entries in md5_sha1_a.hset, as the
    // C++ encoder's sort once scrambled them: most entries then point at a
    // record that does not contain the hash, and the verifier must notice.
    let mut bytes = fixture("md5_sha1_a.hset");
    let (off, len) = {
        let f = decode(&bytes).unwrap();
        let ridx = f.sections[0].ridx.unwrap();
        (ridx.as_ptr() as usize - bytes.as_ptr() as usize, ridx.len())
    };
    let entries: Vec<[u8; 8]> = bytes[off..off + len]
        .as_chunks::<8>()
        .0
        .iter()
        .rev()
        .copied()
        .collect();
    bytes[off..off + len].copy_from_slice(entries.as_flattened());
    let hs = Hashset::load(&bytes).unwrap();
    let report = hs.verify();
    assert!(
        report.problems.iter().any(|p| p.contains("record indices")),
        "{:?}",
        report.problems
    );
}

#[test]
fn records_are_linked_to_hashes() {
    let text = std::fs::read_to_string(fixture_path("md5_sha1_a")).unwrap();
    let mut b = Builder::new(&[HashType::Md5, HashType::Sha1]).unwrap();
    b.add_text(&text).unwrap();
    let bytes = b.build(&BuildOptions::new("a", "a")).unwrap();
    let hs = Hashset::load(&bytes).unwrap();
    assert!(hs.verify().is_ok());
    let rhdr = hs.record_header().unwrap();
    assert_eq!(rhdr.fields.len(), 2);
    assert_eq!(rhdr.fields[0].htype, HashType::Md5);
    assert_eq!(rhdr.fields[1].htype, HashType::Sha1);
    assert_eq!(rhdr.record_length, 1 + 16 + 1 + 20);

    let md5 = hs.index_for_type(HashType::Md5).unwrap();
    let sha1 = hs.index_for_type(HashType::Sha1).unwrap();
    // First line of test/md5_sha1_a
    let m = h("d404b125f9f11f2e2a86a6090def8a23");
    let s = h("7f8d4622dbd32bda0f546bc4a6027c96d2bead90");
    let recs = hs.records_for(md5, &m);
    assert_eq!(recs.len(), 1);
    assert_eq!(hs.field_value(recs[0], HashType::Sha1).unwrap(), &s[..]);
    let recs = hs.records_for(sha1, &s);
    assert_eq!(recs.len(), 1);
    assert_eq!(hs.field_value(recs[0], HashType::Md5).unwrap(), &m[..]);
}

#[test]
fn text_input_reproduces_fixture_records() {
    let text = std::fs::read_to_string(fixture_path("md5_sha1_a")).unwrap();
    let mut b = Builder::new(&[HashType::Md5, HashType::Sha1]).unwrap();
    b.add_text(&text).unwrap();
    let built = b.build(&BuildOptions::new("x", "y")).unwrap();
    let ours = decode(&built).unwrap();
    let theirs_bytes = fixture("md5_sha1_a.hset");
    let theirs = decode(&theirs_bytes).unwrap();
    assert_eq!(ours.rdat, theirs.rdat);
    assert_eq!(
        ours.rhdr.as_ref().unwrap().fields,
        theirs.rhdr.as_ref().unwrap().fields
    );
    for (a, b) in ours.sections.iter().zip(&theirs.sections) {
        assert_eq!(a.data, b.data);
        assert_eq!(a.ridx, b.ridx);
    }
    assert!(Hashset::load(&built).unwrap().verify().is_ok());
}

#[test]
fn reencoding_with_the_legacy_hint_is_byte_exact() {
    let theirs = fixture("md5_sha1_a.hset");
    let f = decode(&theirs).unwrap();
    let rhdr = f.rhdr.clone().unwrap();
    let mut b = Builder::with_fields(rhdr.fields.clone());
    for i in 0..f.record_count() {
        b.add_raw_record(f.record(i).unwrap()).unwrap();
    }
    let opts = BuildOptions::new(f.fhdr.name.clone(), f.fhdr.desc.clone())
        .timestamp(f.fhdr.time.clone())
        .hint(HintSpec::LEGACY);
    let ours = b.build(&opts).unwrap();
    assert_eq!(ours.len(), theirs.len());
    assert_eq!(decode(&ours).unwrap().toc, f.toc, "chunk layout differs");
    // RIDX and the digest that covers it included, since the C++ encoder's
    // RIDX fix (tlsh-embedding's 300ace3)
    assert!(
        ours == theirs,
        "re-encoded file differs from the C++ fixture"
    );
}

fn setop_fixture_matches(op: SetOp, expected: &str) {
    let a = fixture("md5_sha1_a.hset");
    let b = fixture("md5_sha1_b.hset");
    let fa = decode(&a).unwrap();
    let fb = decode(&b).unwrap();
    let builder = ops::apply(op, &fa, &fb).unwrap();
    let out = builder.build(&BuildOptions::new("c", op.name())).unwrap();
    let ours = decode(&out).unwrap();
    let exp_bytes = fixture(expected);
    let exp = decode(&exp_bytes).unwrap();
    assert_eq!(
        ours.rhdr.as_ref().unwrap().fields,
        exp.rhdr.as_ref().unwrap().fields
    );
    assert_eq!(ours.record_count(), exp.record_count(), "{}", op.name());
    assert_eq!(ours.rdat, exp.rdat, "{} records differ", op.name());
    for (x, y) in ours.sections.iter().zip(&exp.sections) {
        assert_eq!(x.header.htype, y.header.htype);
        assert_eq!(
            x.data,
            y.data,
            "{} {} hashes differ",
            op.name(),
            x.header.name
        );
    }
    assert!(Hashset::load(&out).unwrap().verify().is_ok());
}

#[test]
fn set_operations_match_reference_fixtures() {
    setop_fixture_matches(SetOp::Union, "md5_sha1_aub.hset");
    setop_fixture_matches(SetOp::Intersect, "md5_sha1_anb.hset");
    setop_fixture_matches(SetOp::Subtract, "md5_sha1_a-b.hset");
}
