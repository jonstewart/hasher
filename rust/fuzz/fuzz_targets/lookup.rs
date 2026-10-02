#![no_main]

use hset_testkit::checks::check_lookup;
use hset_testkit::strategies::LookupCase;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|case: LookupCase| {
    check_lookup(&case);
});
