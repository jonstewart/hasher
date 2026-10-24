#![no_main]

use hset_testkit::checks::check_text_input;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    check_text_input(text);
});
