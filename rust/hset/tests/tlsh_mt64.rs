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

#[test]
fn default_seed_ten_thousandth_output_is_the_standards() {
    // [rand.predef]: "the 10000th consecutive invocation of a default-
    // constructed object of type mt19937_64 produces 9981545732273789042"
    assert_eq!(outputs(5489, 10000)[9999], 9981545732273789042);
}

#[test]
fn bisect_default_seed_across_the_state_regenerations() {
    // libstdc++ std::mt19937_64(0x7175657279), outputs 1, 2, 3, 312, 313,
    // 624, 625, 10000: the first state, both sides of the second and third.
    let v = outputs(0x7175657279, 10000);
    assert_eq!(v[0], 16184147992570536421);
    assert_eq!(v[1], 442677497207468626);
    assert_eq!(v[2], 9152176512386318889);
    assert_eq!(v[311], 10717209905997423585);
    assert_eq!(v[312], 156008643312855756);
    assert_eq!(v[623], 3791424765275033286);
    assert_eq!(v[624], 3354402863138750041);
    assert_eq!(v[9999], 4787406912471946911);
}

#[test]
fn extreme_seeds() {
    // libstdc++: (seed, first output, 10000th output)
    for (seed, first, ten_thousandth) in [
        (0, 2947667278772165694, 16335088777103562557),
        (u64::MAX, 478026398904862820, 898929940823410802),
    ] {
        let v = outputs(seed, 10000);
        assert_eq!((v[0], v[9999]), (first, ten_thousandth), "seed {seed:#x}");
    }
}

#[test]
fn a_clone_continues_the_same_sequence() {
    let mut a = Mt19937_64::new(42);
    for _ in 0..400 {
        a.next_u64();
    }
    let mut b = a.clone();
    for _ in 0..700 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}
