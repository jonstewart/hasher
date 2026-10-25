//! Write a synthetic `.hset` of uniformly random hashes for benchmarking.
//!
//! ```text
//! cargo run --release --example synth_hset -- <count> <hash_len> <out.hset> [hull|block|legacy|none] [bits] [adversarial]
//! ```

use std::process::ExitCode;

use hset::format::{Document, FORMAT_VERSION, HashsetIn, encode};
use hset::lookup::{self, BitsPolicy, HintSpec};
use hset::{HashType, synth};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!(
            "usage: synth_hset <count> <hash_len> <out.hset> [hull|block|legacy|none] [bits] [adversarial]"
        );
        return ExitCode::from(2);
    }
    let count: usize = args[0].parse().expect("count");
    let hlen: usize = args[1].parse().expect("hash_len");
    let out = &args[2];
    let kind = args.get(3).map(String::as_str).unwrap_or("hull");
    let bits: Option<u8> = args.get(4).and_then(|b| b.parse().ok());
    let adversarial = args.get(5).is_some_and(|a| a == "adversarial");

    let t = std::time::Instant::now();
    let data = if adversarial {
        synth::adversarial_hashes(count, hlen, 0xADFE_EDFA_CE00_0003)
    } else {
        synth::sorted_unique_hashes(count, hlen, 0x7ACE_7357_C0FF_EE01)
    };
    let n = data.len() / hlen;
    eprintln!("generated {n} hashes in {:.2?}", t.elapsed());

    let spec = match kind {
        "hull" => HintSpec::Hull {
            bits: bits.unwrap_or(u8::MAX),
        },
        "block" => HintSpec::Block {
            bits: bits.unwrap_or(0),
        },
        "legacy" => HintSpec::LEGACY,
        "none" => HintSpec::None,
        other => {
            eprintln!("unknown hint kind {other}");
            return ExitCode::from(2);
        }
    };
    let spec = lookup::resolve_bits(spec, n, hlen, &BitsPolicy::default());
    let t = std::time::Instant::now();
    let hint = lookup::build_hint(hlen, &data, spec).expect("hint");
    eprintln!("built hint {spec:?} in {:.2?}", t.elapsed());

    let htype = match hlen {
        16 => HashType::Md5,
        20 => HashType::Sha1,
        28 => HashType::Sha2_224,
        32 => HashType::Sha2_256,
        48 => HashType::Sha2_384,
        64 => HashType::Sha2_512,
        _ => HashType::Sha1,
    };
    let doc = Document {
        version: FORMAT_VERSION,
        name: "synthetic",
        desc: &format!("{n} uniform random {hlen}-byte hashes"),
        time: &hset::builder::now_utc(),
        records: None,
        hashsets: vec![HashsetIn {
            htype,
            name: htype.field_name(),
            hash_length: hlen,
            data: &data,
            hint: hint.as_ref().map(|(t, b)| (*t, b.as_slice())),
            ridx: None,
            tivf: None,
        }],
    };
    let bytes = encode(&doc).expect("encode");
    std::fs::write(out, &bytes).expect("write");
    eprintln!("wrote {out} ({} bytes)", bytes.len());
    ExitCode::SUCCESS
}
