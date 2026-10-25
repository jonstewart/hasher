#![no_main]

//! The TLSH digest's hex form, checked constructor and distance.
//!
//! The input as UTF-8 goes to `TlshDigest::from_hex`, which must accept
//! exactly `"TNULL"` and 70 hex digits with or without `"T1"` and give a
//! digest whose `to_hex` re-parses to it. The first 72 bytes are two raw
//! digests for `from_bytes` (reserved byte rule) and the distance (symmetric,
//! `Some` iff neither is null, equal to the kit's bucket-by-bucket
//! reference).

use hset::tlsh::{
    BodyQuery, DIGEST_LENGTH, TlshDigest, body_diff, diff, emb_body_dist2, header_diff,
};
use hset_testkit::tlsh::ref_diff;
use libfuzzer_sys::fuzz_target;

/// What `from_hex` accepts, written from its contract: `"TNULL"`, or 70
/// ASCII hex digits after an optional `"T1"`.
fn hex_accepted(s: &str) -> bool {
    let digits = s.strip_prefix("T1").unwrap_or(s);
    s == "TNULL" || (digits.len() == 70 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn check_from_hex(s: &str) {
    let parsed = TlshDigest::from_hex(s);
    assert_eq!(parsed.is_ok(), hex_accepted(s), "from_hex({s:?}) = {parsed:?}");
    let Ok(d) = parsed else { return };
    assert_eq!(s.parse::<TlshDigest>().ok(), Some(d));
    assert_eq!(d.as_bytes()[35], 0, "from_hex sets the reserved byte");

    let hex = d.to_hex();
    assert_eq!(TlshDigest::from_hex(&hex).ok(), Some(d), "{s:?} -> {hex:?}");
    assert_eq!(d.to_string(), hex);
    let mut w = Vec::new();
    d.write_hex(&mut w).unwrap();
    assert_eq!(w, hex.as_bytes());

    // The 35 hex bytes map one to one onto L, Q, body and checksum, so the
    // canonical form is the input's digits in upper case, except that all
    // zeros (and "TNULL") are the null digest.
    let digits = s.strip_prefix("T1").unwrap_or(s);
    if s == "TNULL" || digits.bytes().all(|b| b == b'0') {
        assert!(d.is_null());
        assert_eq!(hex, "TNULL");
    } else {
        assert!(!d.is_null());
        assert_eq!(hex, format!("T1{}", digits.to_ascii_uppercase()));
    }
}

fn check_digest(raw: &[u8; DIGEST_LENGTH]) {
    let checked = TlshDigest::from_bytes(raw);
    assert_eq!(checked.is_ok(), raw[35] == 0, "{raw:?}");
    if let Ok(d) = checked {
        assert_eq!(d.as_bytes(), raw);
    }
    // The hex form drops the reserved byte.
    let d = TlshDigest(*raw);
    let mut cleared = *raw;
    cleared[35] = 0;
    assert_eq!(
        TlshDigest::from_hex(&d.to_hex()).unwrap(),
        TlshDigest(cleared)
    );
}

fn check_pair(a: &TlshDigest, b: &TlshDigest) {
    for include_length in [false, true] {
        let ab = diff(a, b, include_length);
        assert_eq!(ab, diff(b, a, include_length), "diff is symmetric");
        assert_eq!(ab.is_some(), !a.is_null() && !b.is_null());
        assert_eq!(ab, ref_diff(a, b, include_length));
        assert_eq!(
            header_diff(a, b, include_length),
            header_diff(b, a, include_length)
        );
    }
    let body = body_diff(a, b);
    let emb = emb_body_dist2(a, b);
    assert_eq!(BodyQuery::new(a).body(b.as_bytes()), body);
    assert_eq!(BodyQuery::new(a).emb_body(b.as_bytes()), emb);
    assert_eq!(emb, emb_body_dist2(b, a));
    assert!(emb <= body, "embedding distance {emb} > body distance {body}");
    if !a.is_null() {
        assert_eq!(diff(a, a, true), Some(0));
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        check_from_hex(s);
    }
    if let Some((a, rest)) = data.split_first_chunk::<DIGEST_LENGTH>() {
        check_digest(a);
        // Any 35 bytes in hex parse; this reaches the round trip without
        // waiting for the fuzzer to spell 70 digits.
        let hex: String = a[..35].iter().map(|b| format!("{b:02x}")).collect();
        check_from_hex(&hex);
        check_from_hex(&format!("T1{hex}"));
        let b = rest.first_chunk::<DIGEST_LENGTH>().unwrap_or(a);
        check_digest(b);
        check_pair(&TlshDigest(*a), &TlshDigest(*b));
    }
});
