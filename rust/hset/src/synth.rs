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
