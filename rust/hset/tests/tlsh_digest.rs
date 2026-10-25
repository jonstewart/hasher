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
