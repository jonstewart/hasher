#![no_main]

use hset_testkit::checks::check_doc_roundtrip;
use hset_testkit::doc::Doc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|doc: Doc| {
    check_doc_roundtrip(&doc);
});
