//! `hset::tlsh::mt64` against `std::mt19937_64`: the C++ standard's
//! required 10000th output for the default seed, and outputs of libstdc++'s
//! engine (printed by a small C++ program) for the BISECT build's default
//! seed, including both sides of the 312-word state regeneration.

use hset::tlsh::mt64::Mt19937_64;

/// Outputs `1..=n` of the engine seeded with `seed`, one-based like the
/// standard's wording ("the 10000th consecutive invocation").
fn outputs(seed: u64, n: usize) -> Vec<u64> {
    let mut g = Mt19937_64::new(seed);
    (0..n).map(|_| g.next_u64()).collect()
}

#[test]
fn default_seed_first_output() {
    assert_eq!(outputs(5489, 1)[0], 14514284786278117030);
}
