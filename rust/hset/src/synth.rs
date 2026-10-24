//! Deterministic synthetic data for tests and benchmarks.

/// SplitMix64 generator; the same recurrence as the reference C++ harness.
#[derive(Debug, Clone)]
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, bound)`.
    #[inline]
    pub fn below(&mut self, bound: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(bound)) >> 64) as u64
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let (chunks, rest) = buf.as_chunks_mut::<8>();
        for c in chunks {
            *c = self.next_u64().to_le_bytes();
        }
        if !rest.is_empty() {
            let v = self.next_u64().to_le_bytes();
            rest.copy_from_slice(&v[..rest.len()]);
        }
    }
}

/// Sort fixed-width rows lexicographically and drop duplicates.
pub fn sort_unique_rows(data: &mut Vec<u8>, width: usize) {
    let sorted = crate::builder::sorted_rows(data, width, true);
    *data = sorted;
}

/// `count` uniformly random `hlen`-byte hashes, sorted and de-duplicated
/// (so the result may be marginally shorter than `count`).
pub fn sorted_unique_hashes(count: usize, hlen: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    let mut data = vec![0u8; count * hlen];
    rng.fill(&mut data);
    sort_unique_rows(&mut data, hlen);
    data
}

/// Clustered, skewed hashes: leading bytes drawn from a handful of values so
/// blocks are wildly unequal and position prediction is poor. Correctness
/// must hold; only speed may degrade.
pub fn adversarial_hashes(count: usize, hlen: usize, seed: u64) -> Vec<u8> {
    const LEAD: [u8; 6] = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF];
    let mut rng = SplitMix64::new(if seed == 0 { 0xABC } else { seed });
    let mut data = vec![0u8; count * hlen];
    for row in data.chunks_exact_mut(hlen) {
        row[0] = LEAD[(rng.next_u64() % LEAD.len() as u64) as usize];
        for b in &mut row[1..] {
            *b = rng.next_u64() as u8;
        }
    }
    sort_unique_rows(&mut data, hlen);
    data
}

/// Build `m` query hashes of which about `hit_fraction` are drawn from `data`
/// and the rest are random (almost surely absent), shuffled together.
pub fn queries(data: &[u8], hlen: usize, m: usize, hit_fraction: f64, seed: u64) -> Vec<u8> {
    let n = data.len() / hlen;
    let mut rng = SplitMix64::new(seed);
    let mut out = vec![0u8; m * hlen];
    for row in out.chunks_exact_mut(hlen) {
        let hit = n > 0 && ((rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)) < hit_fraction;
        if hit {
            let i = rng.below(n as u64) as usize;
            row.copy_from_slice(&data[i * hlen..(i + 1) * hlen]);
        } else {
            rng.fill(row);
        }
    }
    out
}

/// Queries that are one bit away from a stored hash: the hardest misses.
pub fn near_misses(data: &[u8], hlen: usize, m: usize, seed: u64) -> Vec<u8> {
    let n = data.len() / hlen;
    let mut rng = SplitMix64::new(seed);
    let mut out = vec![0u8; m * hlen];
    if n == 0 {
        return out;
    }
    for row in out.chunks_exact_mut(hlen) {
        let i = rng.below(n as u64) as usize;
        row.copy_from_slice(&data[i * hlen..(i + 1) * hlen]);
        let bit = rng.below(8 * hlen as u64) as usize;
        row[bit / 8] ^= 1 << (bit % 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_sorted_and_unique() {
        for (n, l) in [(1000usize, 20usize), (500, 4), (77, 8)] {
            let d = sorted_unique_hashes(n, l, 1);
            let rows: Vec<&[u8]> = d.chunks_exact(l).collect();
            assert!(rows.windows(2).all(|w| w[0] < w[1]));
            assert!(rows.len() <= n && rows.len() >= n * 9 / 10);
        }
        let hl = 20;
        let d = adversarial_hashes(2000, hl, 5);
        let rows: Vec<&[u8]> = d.chunks_exact(hl).collect();
        assert!(rows.windows(2).all(|w| w[0] < w[1]));
        assert!(
            rows.iter()
                .all(|r| [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF].contains(&r[0]))
        );
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(
            sorted_unique_hashes(100, 16, 9),
            sorted_unique_hashes(100, 16, 9)
        );
        assert_ne!(
            sorted_unique_hashes(100, 16, 9),
            sorted_unique_hashes(100, 16, 10)
        );
    }

    #[test]
    fn query_mix_roughly_matches_fraction() {
        let hl = 20;
        let d = sorted_unique_hashes(1000, hl, 2);
        let q = queries(&d, hl, 2000, 0.5, 3);
        let rows: Vec<&[u8]> = d.chunks_exact(hl).collect();
        let hits = q
            .chunks_exact(hl)
            .filter(|h| rows.binary_search(h).is_ok())
            .count();
        assert!((800..1200).contains(&hits), "hits = {hits}");
        let nm = near_misses(&d, hl, 500, 4);
        assert!(nm.chunks_exact(hl).all(|h| rows.binary_search(&h).is_err()));
    }

    /// The published SplitMix64 test vector (Vigna's `splitmix64.c`, seed
    /// 1234567) and the state-0 output `SplitMix64::new` substitutes for.
    #[test]
    fn next_u64_matches_the_reference_outputs() {
        let mut r = SplitMix64::new(1_234_567);
        let got: Vec<u64> = (0..5).map(|_| r.next_u64()).collect();
        assert_eq!(
            got,
            [
                6_457_827_717_110_365_317,
                3_203_168_211_198_807_973,
                9_817_491_932_198_370_423,
                4_593_380_528_125_082_431,
                16_408_922_859_458_223_821,
            ]
        );
        // Seed 0 starts from the golden-ratio increment, i.e. the
        // reference generator's second output from state 0.
        let mut z = SplitMix64::new(0);
        assert_eq!(z.next_u64(), 0x6e78_9e6a_a1b9_65f4);
    }

    /// `below` is the high half of `next_u64() * bound` (Lemire's
    /// multiply-shift); with seed 1 the first draws scaled to 10 are
    /// these, and a bound of 2^63 halves the raw outputs.
    #[test]
    fn below_takes_the_high_half_of_the_product() {
        let mut r = SplitMix64::new(1);
        let got: Vec<u64> = (0..8).map(|_| r.below(10)).collect();
        assert_eq!(got, [5, 7, 9, 4, 4, 7, 8, 5]);
        assert_eq!(r.below(1 << 63), 2_633_352_815_946_178_260);
        assert_eq!(r.below(1 << 63), 7_323_326_090_023_318_475);
    }

    /// `fill` writes whole outputs little-endian and the first bytes of one
    /// more for a ragged tail; a whole buffer draws no extra output.
    #[test]
    fn fill_writes_outputs_little_endian() {
        let mut r = SplitMix64::new(1);
        let mut buf = [0u8; 11];
        r.fill(&mut buf);
        assert_eq!(crate::hex::encode(&buf), "c15c0289ec2d0a9167ec8e");
        let mut whole = [0u8; 8];
        let mut r = SplitMix64::new(1);
        r.fill(&mut whole);
        let mut next = [0u8; 3];
        r.fill(&mut next);
        assert_eq!(crate::hex::encode(&next), "67ec8e");
    }

    /// Hand-traced outputs of the generators over a three-row table
    /// (expected bytes from a straight transcription of each function
    /// over the SplitMix64 reference recurrence).
    #[test]
    fn generators_produce_the_traced_outputs() {
        let data = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let hex = |v: &[u8]| crate::hex::encode(v);
        // Leading bytes from the clustered set; seed 0 means seed 0xABC.
        assert_eq!(
            hex(&adversarial_hashes(4, 3, 7)),
            "801c0280da11fefe61ffeb2c"
        );
        assert_eq!(hex(&adversarial_hashes(2, 2, 0)), "7f97ff31");
        assert_eq!(hex(&adversarial_hashes(2, 2, 0xABC)), "7f97ff31");
        // Hits copy a stored row, misses are fresh random bytes.
        assert_eq!(
            hex(&queries(&data, 2, 6, 0.5, 3)),
            "5060cfc93040506050607f48"
        );
        // An empty table can only miss, whatever the hit fraction.
        assert_eq!(hex(&queries(&[], 2, 2, 1.0, 3)), "ed8f89a9");
        // A draw equal to the hit fraction is a miss (the test is `<`).
        let u = (SplitMix64::new(3).next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        assert_eq!(hex(&queries(&data, 2, 1, u, 3)), "89a9");
        // Each near miss is a stored row with exactly one bit flipped.
        assert_eq!(hex(&near_misses(&data, 2, 4, 3)), "1028324010241060");
        assert_eq!(near_misses(&[], 2, 2, 3), [0u8; 4]);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // The Kani version (a symbolic 128-bit product) did not converge in 15 minutes.
        #[test]
        fn below_is_below(seed in any::<u64>(), b in 1u64..) {
            prop_assert!(SplitMix64::new(seed).below(b) < b);
        }
    }
}
