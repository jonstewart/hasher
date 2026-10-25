//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and validation.

pub mod bisect;
pub mod merge;
pub mod search;

use std::fmt;

use super::CELL_COUNT;
use super::digest::{DIGEST_LENGTH, TlshDigest};
use crate::error::{Error, Result};

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

    /// An owned copy of any index.
    pub fn from_index<I: IvfIndex + ?Sized>(index: &I) -> Self {
        let lists = index.lists();
        Self {
            n: index.n(),
            cell_lists: (0..=CELL_COUNT).map(|c| index.cell_lists(c)).collect(),
            medoids: (0..lists).map(|l| index.medoid(l)).collect(),
            radius2: (0..lists).map(|l| index.radius2(l)).collect(),
            list_start: (0..=lists).map(|l| index.list_start(l)).collect(),
            ids: (0..index.n() as usize).map(|i| index.id(i)).collect(),
        }
    }
}

/// Read access to a TIVF index, owned ([`TlshIvf`]) or borrowed from a
/// payload ([`TivfView`]).
pub trait IvfIndex {
    /// Rows indexed.
    fn n(&self) -> u64;
    /// Number of lists.
    fn lists(&self) -> usize;
    /// Entry `c` of `cell_lists`.
    fn cell_lists(&self, c: usize) -> u32;
    /// Medoid of list `l`.
    fn medoid(&self, l: usize) -> TlshDigest;
    /// Squared radius of list `l`.
    fn radius2(&self, l: usize) -> u32;
    /// Entry `l` of `list_start`.
    fn list_start(&self, l: usize) -> u64;
    /// Entry `i` of `ids`.
    fn id(&self, i: usize) -> u32;
}

impl IvfIndex for TlshIvf {
    fn n(&self) -> u64 {
        self.n
    }
    fn lists(&self) -> usize {
        self.radius2.len()
    }
    fn cell_lists(&self, c: usize) -> u32 {
        self.cell_lists[c]
    }
    fn medoid(&self, l: usize) -> TlshDigest {
        self.medoids[l]
    }
    fn radius2(&self, l: usize) -> u32 {
        self.radius2[l]
    }
    fn list_start(&self, l: usize) -> u64 {
        self.list_start[l]
    }
    fn id(&self, i: usize) -> u32 {
        self.ids[i]
    }
}

/// A TIVF index borrowed from its payload.
#[derive(Clone, Copy)]
pub struct TivfView<'a> {
    n: u64,
    cell_lists: &'a [[u8; 4]],
    medoids: &'a [[u8; DIGEST_LENGTH]],
    radius2: &'a [[u8; 4]],
    list_start: &'a [[u8; 8]],
    ids: &'a [[u8; 4]],
}

impl<'a> TivfView<'a> {
    /// Parse a payload.
    pub fn parse(payload: &'a [u8], expected_n: u64) -> Result<Self> {
        let Some((header, body)) = payload.split_first_chunk::<TIVF_HEADER_LENGTH>() else {
            return Err(Error::format(format!(
                "TIVF payload is {} bytes, shorter than its {TIVF_HEADER_LENGTH}-byte header",
                payload.len()
            )));
        };
        let (version, rest) = header.split_first_chunk::<2>().expect("32 bytes");
        let (flags, rest) = rest.split_first_chunk::<2>().expect("30 bytes");
        let (dims, rest) = rest.split_first_chunk::<4>().expect("28 bytes");
        let (lists, rest) = rest.split_first_chunk::<4>().expect("24 bytes");
        let (reserved32, rest) = rest.split_first_chunk::<4>().expect("20 bytes");
        let (n, rest) = rest.split_first_chunk::<8>().expect("16 bytes");
        let (reserved64, _) = rest.split_first_chunk::<8>().expect("8 bytes");

        let version = u16::from_le_bytes(*version);
        if version != TIVF_VERSION {
            return Err(Error::format(format!("unsupported TIVF version {version}")));
        }
        let flags = u16::from_le_bytes(*flags);
        if flags != 0 {
            return Err(Error::format(format!(
                "unsupported TIVF flags 0x{flags:04x}"
            )));
        }
        let dims = u32::from_le_bytes(*dims);
        if dims != TIVF_DIMS {
            return Err(Error::format(format!("unsupported TIVF dims {dims}")));
        }
        if *reserved32 != [0; 4] || *reserved64 != [0; 8] {
            return Err(Error::format("TIVF reserved header fields are not zero"));
        }
        let lists = u32::from_le_bytes(*lists);
        let n = u64::from_le_bytes(*n);
        let want = tivf_len(lists, n);
        if payload.len() as u64 != want {
            return Err(Error::format(format!(
                "TIVF payload is {} bytes, expected {want} for {lists} lists over {n} rows",
                payload.len()
            )));
        }
        // The length matched, so every count below fits in memory.
        let lists = lists as usize;
        let (cell_lists, body) = body.split_at(4 * (CELL_COUNT + 1));
        let (medoids, body) = body.split_at(DIGEST_LENGTH * lists);
        let (radius2, body) = body.split_at(4 * lists);
        let (list_start, ids) = body.split_at(8 * (lists + 1));
        let v = Self {
            n,
            cell_lists: cell_lists.as_chunks().0,
            medoids: medoids.as_chunks().0,
            radius2: radius2.as_chunks().0,
            list_start: list_start.as_chunks().0,
            ids: ids.as_chunks().0,
        };

        if n != expected_n {
            return Err(Error::format(format!(
                "TIVF has {n} rows, expected {expected_n}"
            )));
        }
        if v.cell_lists(0) != 0 || v.cell_lists(CELL_COUNT) as usize != lists {
            return Err(Error::format(format!(
                "bad TIVF cell_lists: [0] = {}, [{CELL_COUNT}] = {}, expected 0 and {lists}",
                v.cell_lists(0),
                v.cell_lists(CELL_COUNT)
            )));
        }
        if v.list_start(0) != 0 || v.list_start(lists) != n {
            return Err(Error::format("TIVF list offsets do not cover the rows"));
        }
        if v.list_start.windows(2).any(|w| {
            u64::from_le_bytes(w[0]) > u64::from_le_bytes(w[1])
        }) {
            return Err(Error::format("TIVF list offsets are not nondecreasing"));
        }
        Ok(v)
    }
}

impl fmt::Debug for TivfView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TivfView")
            .field("n", &self.n)
            .field("lists", &self.radius2.len())
            .finish_non_exhaustive()
    }
}

impl IvfIndex for TivfView<'_> {
    fn n(&self) -> u64 {
        self.n
    }
    fn lists(&self) -> usize {
        self.radius2.len()
    }
    fn cell_lists(&self, c: usize) -> u32 {
        u32::from_le_bytes(self.cell_lists[c])
    }
    fn medoid(&self, l: usize) -> TlshDigest {
        TlshDigest(self.medoids[l])
    }
    fn radius2(&self, l: usize) -> u32 {
        u32::from_le_bytes(self.radius2[l])
    }
    fn list_start(&self, l: usize) -> u64 {
        u64::from_le_bytes(self.list_start[l])
    }
    fn id(&self, i: usize) -> u32 {
        u32::from_le_bytes(self.ids[i])
    }
}
