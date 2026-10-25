//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and validation.

pub mod bisect;
pub mod merge;
pub mod search;

use super::CELL_COUNT;
use super::digest::{DIGEST_LENGTH, TlshDigest};

/// Length of the fixed TIVF header.
pub const TIVF_HEADER_LENGTH: usize = 32;

/// TIVF payload version written and accepted.
pub const TIVF_VERSION: u16 = 3;

/// Embedding dimensions recorded in the header: the 256-dimensional body
/// embedding.
pub const TIVF_DIMS: u32 = 256;

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

/// An owned TIVF index (C++ `TlshIvf`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlshIvf {
    /// Rows indexed.
    pub n: u64,
    /// `CELL_COUNT + 1` entries.
    pub cell_lists: Vec<u32>,
    /// One per list.
    pub medoids: Vec<TlshDigest>,
    /// One per list.
    pub radius2: Vec<u32>,
    /// Lists + 1 entries.
    pub list_start: Vec<u64>,
    /// `n` row indexes.
    pub ids: Vec<u32>,
}

impl TlshIvf {
    /// The index of no rows.
    pub fn empty() -> Self {
        Self {
            n: 0,
            cell_lists: vec![0; CELL_COUNT + 1],
            medoids: Vec::new(),
            radius2: Vec::new(),
            list_start: vec![0],
            ids: Vec::new(),
        }
    }

    /// Number of lists.
    pub fn lists(&self) -> usize {
        self.radius2.len()
    }

    /// Panic unless the arrays have the lengths the payload layout implies.
    fn assert_shape(&self) {
        let lists = self.lists();
        assert!(
            u32::try_from(lists).is_ok(),
            "TIVF index has {lists} lists, more than a u32 counts"
        );
        assert_eq!(
            self.cell_lists.len(),
            CELL_COUNT + 1,
            "TIVF cell_lists must have CELL_COUNT + 1 entries"
        );
        assert_eq!(self.medoids.len(), lists, "TIVF medoids must match radius2");
        assert_eq!(
            self.list_start.len(),
            lists + 1,
            "TIVF list_start must have lists + 1 entries"
        );
        assert_eq!(self.ids.len() as u64, self.n, "TIVF ids must have n entries");
    }

    /// The TIVF payload (C++ `write_tivf_data`).
    ///
    /// # Panics
    ///
    /// If the arrays disagree in length with each other or with `n` (see
    /// the field docs).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.assert_shape();
        let lists = self.lists() as u32;
        let mut out = Vec::with_capacity(tivf_len(lists, self.n) as usize);
        out.extend_from_slice(&TIVF_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&TIVF_DIMS.to_le_bytes());
        out.extend_from_slice(&lists.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        out.extend_from_slice(&self.n.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // reserved
        for c in &self.cell_lists {
            out.extend_from_slice(&c.to_le_bytes());
        }
        for m in &self.medoids {
            out.extend_from_slice(&m.0);
        }
        for r in &self.radius2 {
            out.extend_from_slice(&r.to_le_bytes());
        }
        for s in &self.list_start {
            out.extend_from_slice(&s.to_le_bytes());
        }
        for id in &self.ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }
}
