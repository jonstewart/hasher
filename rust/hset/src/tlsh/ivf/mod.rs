//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and validation.

pub mod bisect;
pub mod merge;
pub mod search;

use std::fmt;
use std::ops::Range;

use super::CELL_COUNT;
use super::digest::{DIGEST_LENGTH, TlshDigest};
use super::distance::BodyQuery;
use crate::error::{Error, Result};

/// Lists hold about this many rows each: the clustering target `T` of the
/// BISECT build (C++ `TLSH_IVF_TARGET_LIST_SIZE`).
pub const TARGET_LIST_SIZE: usize = 32;

/// Default seed of the BISECT build's random draws, ASCII `"query"`
/// (C++ `TLSH_IVF_DEFAULT_SEED`).
pub const DEFAULT_SEED: u64 = 0x71_7565_7279;

/// Default coalescing threshold `C` of a merge, `2 * TARGET_LIST_SIZE`:
/// two lists of a cell are coalesced while both have fewer than `C / 2`
/// members (C++ `TLSH_IVF_DEFAULT_COALESCE`). See [`check_invariant`].
pub const DEFAULT_COALESCE: u32 = 2 * TARGET_LIST_SIZE as u32;

/// BISECT splits a node in two only while it has more than this many rows;
/// smaller nodes are clustered flat by integer k-means into at most
/// `ceil(s / T)` lists. A quality and build-cost knob only
/// (C++ `TLSH_IVF_BISECT_FLAT_MAX`).
pub const FLAT_MAX: usize = 4096;

/// The output row of an input row that a merge drops, in merge row maps
/// (C++ `TLSH_IVF_DROPPED`).
pub const DROPPED: u32 = u32::MAX;

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

    /// What is wrong with the array lengths, if anything: they must be
    /// those the payload layout implies for `lists()` lists over `n` rows.
    fn layout_error(&self) -> Option<String> {
        let lists = self.lists();
        if u32::try_from(lists).is_err() {
            return Some(format!(
                "TIVF index has {lists} lists, more than a u32 counts"
            ));
        }
        let lens = [
            ("cell_lists", self.cell_lists.len(), CELL_COUNT + 1),
            ("medoids", self.medoids.len(), lists),
            ("list_start", self.list_start.len(), lists + 1),
        ];
        for (name, len, want) in lens {
            if len != want {
                return Some(format!(
                    "TIVF {name} has {len} entries, expected {want} for {lists} lists"
                ));
            }
        }
        if self.ids.len() as u64 != self.n {
            return Some(format!(
                "TIVF ids has {} entries, expected n = {}",
                self.ids.len(),
                self.n
            ));
        }
        None
    }

    /// The TIVF payload (C++ `write_tivf_data`).
    ///
    /// # Panics
    ///
    /// If the arrays disagree in length with each other or with `n` (see
    /// the field docs).
    pub fn to_bytes(&self) -> Vec<u8> {
        if let Some(e) = self.layout_error() {
            panic!("{e}");
        }
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
    /// The arrays have the lengths the layout implies.
    fn check_layout(&self) -> Result<()>;

    /// The lists of cell `c`.
    fn cell_range(&self, c: usize) -> Range<usize> {
        let end = (self.cell_lists(c + 1) as usize).min(self.lists());
        (self.cell_lists(c) as usize).min(end)..end
    }

    /// The positions in `ids` of list `l`.
    fn list_range(&self, l: usize) -> Range<usize> {
        let end = self.list_start(l + 1).min(self.n()) as usize;
        (self.list_start(l) as usize).min(end)..end
    }

    /// Members of list `l`.
    fn list_len(&self, l: usize) -> u64 {
        self.list_start(l + 1).saturating_sub(self.list_start(l))
    }

    /// The row indexes of list `l`.
    fn list_ids(&self, l: usize) -> impl Iterator<Item = u32> + '_ {
        self.list_range(l).map(move |i| self.id(i))
    }

    /// Validate against the rows.
    fn validate(self, rows: &[[u8; DIGEST_LENGTH]]) -> Result<ValidIvf<'_, Self>>
    where
        Self: Sized,
    {
        check_valid(&self, rows)?;
        Ok(ValidIvf { index: self, rows })
    }
}

/// The checks of [`IvfIndex::validate`].
fn check_valid<I: IvfIndex + ?Sized>(ivf: &I, rows: &[[u8; DIGEST_LENGTH]]) -> Result<()> {
    ivf.check_layout()?;
    let n = ivf.n();
    if rows.len() as u64 != n {
        return Err(Error::format(format!(
            "TIVF indexes {n} rows, the section has {}",
            rows.len()
        )));
    }
    if let Some(i) = rows.windows(2).position(|w| cell_of(&w[0]) > cell_of(&w[1])) {
        return Err(Error::format(format!(
            "TIVF rows are not sorted by cell: row {} of cell 0x{:04x} follows cell 0x{:04x}",
            i + 1,
            cell_of(&rows[i + 1]),
            cell_of(&rows[i])
        )));
    }
    check_offsets(ivf)?;
    for c in 0..CELL_COUNT {
        let (first, end) = (ivf.cell_lists(c), ivf.cell_lists(c + 1));
        if first > end {
            return Err(Error::format(format!(
                "TIVF cell_lists decreases from {first} to {end} after cell 0x{c:04x}"
            )));
        }
    }

    // From here every cell_range lies in 0..lists and every list_range in
    // 0..n. n distinct ids below n: every row exactly once.
    let mut seen = vec![0u64; rows.len().div_ceil(64)];
    for c in 0..CELL_COUNT {
        for l in ivf.cell_range(c) {
            if ivf.list_len(l) == 0 {
                return Err(Error::format(format!("TIVF list {l} is empty")));
            }
            let medoid = BodyQuery::new(&ivf.medoid(l));
            let radius2 = ivf.radius2(l);
            let mut prev = None;
            for i in ivf.list_range(l) {
                let id = ivf.id(i);
                let Some(row) = rows.get(id as usize) else {
                    return Err(Error::format(format!(
                        "TIVF list {l} has id {id} out of range for {n} rows"
                    )));
                };
                if prev.is_some_and(|p| p >= id) {
                    return Err(Error::format(format!(
                        "TIVF list {l} ids are not ascending at id {id}"
                    )));
                }
                prev = Some(id);
                let row_cell = cell_of(row);
                if usize::from(row_cell) != c {
                    return Err(Error::format(format!(
                        "TIVF row {id} of cell 0x{row_cell:04x} is in a list of cell 0x{c:04x}"
                    )));
                }
                let (word, bit) = (id as usize / 64, 1u64 << (id % 64));
                if seen[word] & bit != 0 {
                    return Err(Error::format(format!("TIVF row {id} is in two lists")));
                }
                seen[word] |= bit;
                let d2 = medoid.emb_body(row);
                if d2 > radius2 {
                    return Err(Error::format(format!(
                        "TIVF row {id} is {d2} from the medoid of list {l}, beyond radius2 {radius2}"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// The checks `parse` makes beyond the header, which also bound every
/// `list_range`: `cell_lists` runs from 0 to the list count and
/// `list_start` from 0 to n without decreasing (C++ `parse_tivf_data` and
/// `handle_tivf`).
fn check_offsets<I: IvfIndex + ?Sized>(ivf: &I) -> Result<()> {
    let (n, lists) = (ivf.n(), ivf.lists());
    if ivf.cell_lists(0) != 0 || ivf.cell_lists(CELL_COUNT) as usize != lists {
        return Err(Error::format(format!(
            "bad TIVF cell_lists: [0] = {}, [{CELL_COUNT}] = {}, expected 0 and {lists}",
            ivf.cell_lists(0),
            ivf.cell_lists(CELL_COUNT)
        )));
    }
    if ivf.list_start(0) != 0 || ivf.list_start(lists) != n {
        return Err(Error::format("TIVF list offsets do not cover the rows"));
    }
    if (0..lists).any(|l| ivf.list_start(l) > ivf.list_start(l + 1)) {
        return Err(Error::format("TIVF list offsets are not nondecreasing"));
    }
    Ok(())
}

/// The coalescing invariant.
pub fn check_invariant<I: IvfIndex + ?Sized>(ivf: &I, coalesce_threshold: u32) -> bool {
    let half = u64::from(coalesce_threshold / 2);
    if half == 0 {
        return true;
    }
    (0..CELL_COUNT).all(|c| {
        ivf.cell_range(c)
            .filter(|&l| ivf.list_len(l) < half)
            .nth(1)
            .is_none()
    })
}

/// The cell of a raw row.
fn cell_of(row: &[u8; DIGEST_LENGTH]) -> u16 {
    TlshDigest(*row).cell()
}

/// A validated index.
#[derive(Clone, Copy, Debug)]
pub struct ValidIvf<'r, I> {
    index: I,
    rows: &'r [[u8; DIGEST_LENGTH]],
}

impl<'r, I: IvfIndex> ValidIvf<'r, I> {
    /// The index.
    pub fn index(&self) -> &I {
        &self.index
    }

    /// The rows it was validated against.
    pub fn rows(&self) -> &'r [[u8; DIGEST_LENGTH]] {
        self.rows
    }

    /// The index, giving up the guarantee.
    pub fn into_inner(self) -> I {
        self.index
    }
}

impl<I: IvfIndex + ?Sized> IvfIndex for &I {
    fn n(&self) -> u64 {
        (**self).n()
    }
    fn lists(&self) -> usize {
        (**self).lists()
    }
    fn cell_lists(&self, c: usize) -> u32 {
        (**self).cell_lists(c)
    }
    fn medoid(&self, l: usize) -> TlshDigest {
        (**self).medoid(l)
    }
    fn radius2(&self, l: usize) -> u32 {
        (**self).radius2(l)
    }
    fn list_start(&self, l: usize) -> u64 {
        (**self).list_start(l)
    }
    fn id(&self, i: usize) -> u32 {
        (**self).id(i)
    }
    fn check_layout(&self) -> Result<()> {
        (**self).check_layout()
    }
}

impl<I: IvfIndex> IvfIndex for ValidIvf<'_, I> {
    fn n(&self) -> u64 {
        self.index.n()
    }
    fn lists(&self) -> usize {
        self.index.lists()
    }
    fn cell_lists(&self, c: usize) -> u32 {
        self.index.cell_lists(c)
    }
    fn medoid(&self, l: usize) -> TlshDigest {
        self.index.medoid(l)
    }
    fn radius2(&self, l: usize) -> u32 {
        self.index.radius2(l)
    }
    fn list_start(&self, l: usize) -> u64 {
        self.index.list_start(l)
    }
    fn id(&self, i: usize) -> u32 {
        self.index.id(i)
    }
    fn check_layout(&self) -> Result<()> {
        self.index.check_layout()
    }
}

impl IvfIndex for TlshIvf {
    fn check_layout(&self) -> Result<()> {
        match self.layout_error() {
            Some(e) => Err(Error::format(e)),
            None => Ok(()),
        }
    }
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
        check_offsets(&v)?;
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
    fn check_layout(&self) -> Result<()> {
        // parse split the payload into arrays of these lengths
        Ok(())
    }
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
