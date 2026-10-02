#![no_main]

use hset_testkit::checks::exercise_loaded;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    exercise_loaded(data);
});
