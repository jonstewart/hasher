#![no_main]

use hset_testkit::checks::check_corruption;
use hset_testkit::corrupt::Corruption;
use hset_testkit::doc::Doc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Doc, Corruption)| {
    check_corruption(&input.0, &input.1);
});
