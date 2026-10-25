//! The 64-bit Mersenne Twister (`std::mt19937_64`) that the BISECT build
//! draws from, ported bit for bit so builds match the C++ library.
//!
//! The C++ standard fixes the engine's whole output sequence
//! (`[rand.predef]`: the 10000th output for the default seed 5489 is
//! 9981545732273789042), unlike its distributions, so the C++ build draws
//! `rng() % n` straight from the engine (`src/lib/hashset/tlsh_ivf.cpp`)
//! and so do the Rust callers, with [`Mt19937_64::next_u64`].
//!
//! Parameters (`std::mersenne_twister_engine`): word size 64, state size
//! n = 312, shift m = 156, mask bits r = 31, twist matrix
//! a = `0xB5026F5AA96619E9`, tempering u = 29, d = `0x5555555555555555`,
//! s = 17, b = `0x71D67FFFEDA60000`, t = 37, c = `0xFFF7EEE000000000`,
//! l = 43, initialization multiplier f = 6364136223846793005.

const N: usize = 312;
const M: usize = 156;
const MATRIX_A: u64 = 0xB502_6F5A_A966_19E9;
/// The top 33 bits (`w - r`).
const UPPER_MASK: u64 = !0 << 31;
/// The low 31 bits (`r`).
const LOWER_MASK: u64 = !UPPER_MASK;
const INIT_MULTIPLIER: u64 = 6_364_136_223_846_793_005;

/// `std::mt19937_64`: [`Mt19937_64::new`] is `std::mt19937_64(seed)` and
/// [`Mt19937_64::next_u64`] is `rng()`.
#[derive(Clone, Debug)]
pub struct Mt19937_64 {
    state: [u64; N],
    /// Index of the next state word to temper; `N` forces a regeneration.
    index: usize,
}

impl Mt19937_64 {
    /// The engine seeded as `std::mt19937_64(seed)`:
    /// `x[0] = seed`, `x[i] = f * (x[i-1] ^ (x[i-1] >> 62)) + i`.
    pub fn new(seed: u64) -> Self {
        let mut state = [0; N];
        state[0] = seed;
        for i in 1..N {
            let prev = state[i - 1];
            state[i] = INIT_MULTIPLIER
                .wrapping_mul(prev ^ (prev >> 62))
                .wrapping_add(i as u64);
        }
        Self { state, index: N }
    }

    /// The next output, `rng()`.
    pub fn next_u64(&mut self) -> u64 {
        if self.index >= N {
            self.twist();
        }
        let mut z = self.state[self.index];
        self.index += 1;
        z ^= (z >> 29) & 0x5555_5555_5555_5555;
        z ^= (z << 17) & 0x71D6_7FFF_EDA6_0000;
        z ^= (z << 37) & 0xFFF7_EEE0_0000_0000;
        z ^ (z >> 43)
    }

    /// Regenerate all `N` state words.
    fn twist(&mut self) {
        for i in 0..N {
            let y = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
            let mag = if y & 1 == 0 { 0 } else { MATRIX_A };
            self.state[i] = self.state[(i + M) % N] ^ (y >> 1) ^ mag;
        }
        self.index = 0;
    }
}
