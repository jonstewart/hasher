#![no_main]

use hset_testkit::checks::{check_hex, check_hex_rows};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_hex(data);
    if data.len() >= 2 {
        // Byte 0 picks the row width, byte 1 the separator length; the
        // separator is taken from the input itself and the rows follow it.
        let width = 1 + data[0] as usize % 64;
        let sep_end = (1 + (data[1] % 4) as usize).min(data.len());
        let sep = &data[1..sep_end];
        let rest = &data[sep_end..];
        let rows = &rest[..rest.len() / width * width];
        check_hex_rows(rows, width, sep);
    }
});
