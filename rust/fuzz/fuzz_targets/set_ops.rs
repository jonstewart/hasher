#![no_main]

use hset::SetOp;
use hset_testkit::checks::check_set_op;
use hset_testkit::doc::Doc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Doc, Doc, u8)| {
    let op = match input.2 % 3 {
        0 => SetOp::Union,
        1 => SetOp::Intersect,
        _ => SetOp::Subtract,
    };
    check_set_op(op, &input.0, &input.1);
});
