//! Corrupted and truncated input must never panic: it either loads (and then
//! every query and `verify` must be safe) or returns an error.

use hset::synth::SplitMix64;
use hset::{BuildOptions, Builder, HashType, Hashset, HintSpec};

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

fn exercise(bytes: &[u8]) {
    if let Ok(hs) = Hashset::load(bytes) {
        let _ = hs.verify();
        for i in 0..hs.section_count() {
            let s = hs.section(i);
            let hl = s.hash_length();
            let probe = vec![0x5au8; hl];
            let _ = hs.contains(i, &probe);
            let _ = hs.find(i, &probe);
            let _ = hs.records_for(i, &probe);
            if !s.is_empty() {
                let h = s.hash(s.len() / 2).to_vec();
                let _ = hs.records_for(i, &h);
            }
            let mut out = vec![false; 5];
            hs.contains_batch(i, &vec![0xa5u8; hl * 5], &mut out);
        }
        for r in hs.records().take(10) {
            let _ = hs.record_fields(r);
        }
    }
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
        if Hashset::load(b).is_ok() {
            ok += 1;
        }
        exercise(b);
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
        exercise(&b);
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
