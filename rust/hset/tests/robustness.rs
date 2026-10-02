//! Corrupted and truncated input must never panic: it either loads (and then
//! every query and `verify` must be safe) or returns an error.

use hset::synth::SplitMix64;
use hset::{BuildOptions, Builder, HashType, Hashset, HintSpec};
use hset_testkit::checks::exercise_loaded;

fn sample() -> Vec<u8> {
    let mut b = Builder::new(&[HashType::Md5, HashType::Sha1, HashType::Size]).unwrap();
    let mut rng = SplitMix64::new(77);
    for i in 0..300u64 {
        let mut md5 = [0u8; 16];
        let mut sha = [0u8; 20];
        rng.fill(&mut md5);
        rng.fill(&mut sha);
        let size = (i * 7919).to_le_bytes();
        let m: Option<&[u8]> = if i % 5 == 0 { None } else { Some(&md5) };
        let s: Option<&[u8]> = if i % 7 == 0 { None } else { Some(&sha) };
        b.add_record(&[m, s, Some(&size)]).unwrap();
    }
    b.build(&BuildOptions::new("robust", "fuzz sample").hint(HintSpec::Hull { bits: 5 }))
        .unwrap()
}

#[test]
fn truncations_never_panic() {
    let bytes = sample();
    let mut ok = 0;
    for cut in (0..bytes.len())
        .step_by(7)
        .chain([bytes.len() - 1, bytes.len()])
    {
        let b = &bytes[..cut];
        if exercise_loaded(b) {
            ok += 1;
        }
    }
    assert_eq!(ok, 1, "only the untruncated file should load");
}

#[test]
fn random_corruption_never_panics() {
    let bytes = sample();
    let mut rng = SplitMix64::new(0xC0FFEE);
    for _ in 0..3000 {
        let mut b = bytes.clone();
        let flips = 1 + rng.below(4) as usize;
        for _ in 0..flips {
            let pos = rng.below(b.len() as u64) as usize;
            let val = rng.next_u64() as u8;
            // Bias towards the structured head where offsets and lengths live.
            let pos = if rng.below(2) == 0 { pos % 600 } else { pos };
            b[pos] = val;
        }
        exercise_loaded(&b);
    }
}

#[test]
fn hostile_lengths_are_rejected() {
    // Patch the FTOC's first HDAT entry offset to point into the void.
    let bytes = sample();
    let f = hset::format::decode(&bytes).unwrap();
    let toc = f.toc.clone();
    drop(f);
    let mut b = bytes.clone();
    let hdat_pos = toc
        .iter()
        .position(|(_, t)| *t == hset::format::chunk::HDAT)
        .unwrap();
    let entry = 40 + 12 + hdat_pos * 12;
    b[entry..entry + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Hashset::load(&b).is_err());
    // Chunk length overflow.
    let (hdat_off, _) = toc[hdat_pos];
    let mut b = bytes.clone();
    let off = hdat_off as usize + 4;
    b[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Hashset::load(&b).is_err());
}
