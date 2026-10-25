//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and validation.

pub mod bisect;
pub mod merge;
pub mod search;

use super::CELL_COUNT;
use super::digest::DIGEST_LENGTH;

/// Length of the fixed TIVF header.
pub const TIVF_HEADER_LENGTH: usize = 32;

/// Length in bytes of a TIVF payload with `lists` lists over `n` rows:
/// `32 + 4 * 65537 + 48 * lists + 8 + 4 * n` (C++ `length_tivf_data`).
/// Saturates at `u64::MAX`, so a header from a corrupt file never yields a
/// length that wrapped around to a plausible value.
pub const fn tivf_len(lists: u32, n: u64) -> u64 {
    const FIXED: u64 = (TIVF_HEADER_LENGTH + (CELL_COUNT + 1) * 4 + 8) as u64;
    const PER_LIST: u64 = (DIGEST_LENGTH + 4 + 8) as u64;
    FIXED
        .saturating_add(PER_LIST * lists as u64)
        .saturating_add(n.saturating_mul(4))
}
