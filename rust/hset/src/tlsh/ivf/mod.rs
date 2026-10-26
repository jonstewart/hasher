//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and its structural check. C++: `include/hashset/
//! tlsh_ivf.h`, `src/lib/hashset/tlsh_ivf.cpp`; docs/TLSH_EMBEDDING.md
//! section 3.
//!
//! # Model
//!
//! The rows of a TLSH hash set (sorted 36-byte digests, `HDAT`) are grouped
//! by cell, `(L << 8) | Q`, which is contiguous in sorted order, and each
//! cell's rows are split into lists. Each list keeps a medoid (a digest
//! central to the list; after a merge not necessarily a member) and
//! `radius2`, an upper bound on the squared body-embedding distance
//! ([`emb_body_dist2`](super::emb_body_dist2)) from the medoid to every
//! member. The header part of the TLSH distance is exact per cell, and
//! `radius2` with the triangle inequality bounds the body part per list,
//! which is what the search ([`search`]) prunes with.
//!
//! With `C` lists over `n` rows the index is five arrays:
//!
//! ```text
//! cell_lists[65537]  u32  lists of cell c are cell_lists[c]..cell_lists[c + 1]
//! medoids[C]         36-byte digest
//! radius2[C]         u32
//! list_start[C + 1]  u64  members of list l are ids[list_start[l]..list_start[l + 1]]
//! ids[n]             u32  row indexes into HDAT, ascending within a list
//! ```
//!
//! # Payload
//!
//! The `TIVF` chunk payload (HASHSET_FORMAT; C++ `write_tivf_data`,
//! `parse_tivf_data`) is a 32-byte little-endian header, then the arrays in
//! the order above, little-endian, with no padding:
//!
//! ```text
//! offset  0  u16 version   3
//! offset  2  u16 flags     0
//! offset  4  u32 dims      256
//! offset  8  u32 lists     C
//! offset 12  u32 reserved  0
//! offset 16  u64 n
//! offset 24  u64 reserved  0
//! ```
//!
//! Its length is [`tivf_len`]. The chunk is only 4-byte aligned in a file
//! (so `list_start` may be misaligned for `u64`), and [`TivfView`] assumes
//! no alignment at all: it reads every entry with `from_le_bytes`.
//!
//! # Owned and borrowed
//!
//! [`TlshIvf`] owns the arrays; the BISECT build ([`bisect`]) and merge
//! ([`merge`]) produce one and [`TlshIvf::to_bytes`] writes its payload.
//! [`TivfView`] borrows them from a payload, as mapped from a file. Both
//! implement [`IvfIndex`], the read interface the search and the merge take.
//!
//! # Checks
//!
//! An index is never validated as a step before use. [`TivfView::parse`]
//! checks what C++ checks at load (header values, length, row count, the
//! ends of `cell_lists` and `list_start`), in O(1). The search
//! ([`knn_ivf`]) and the merge ([`merge_tlsh_ivf`]) read the index as C++
//! does and bounds-check each read with [`IvfIndex::cell_range`],
//! [`IvfIndex::list_range`] and checked row access: an index out of
//! bounds where they read it is an [`Error::Format`], one corrupt within
//! bounds an inexact answer (as in C++), never a panic. [`check_index`] is
//! the full structural check against the rows, O(n), run only on request
//! (`Hashset::verify`, `hset verify`). [`check_invariant`] is the merge's
//! coalescing invariant, a property of good indexes rather than a validity
//! condition.
//!
//! # Differences from the C++ library
//!
//! * `handle_tivf` also checks at load that `list_start` never
//!   decreases, an O(lists) loop; `parse` does not (no pass over the
//!   index at load). The search and the merge find an inverted list range
//!   where they read it.
//! * C++ reads a loaded index unchecked; Rust bounds-checks the reads, so
//!   an index out of bounds is a format error instead of undefined
//!   behaviour.
//! * A hash set without an index has no `TivfView` (C++ uses an empty
//!   `TlshIvfView`); [`TlshIvf::empty`] is the index of no rows.

pub mod bisect;
pub mod merge;
pub mod search;

pub use bisect::{IvfBuildOptions, build_tlsh_ivf, nearer};
pub use merge::merge_tlsh_ivf;
pub use search::{MIN_BOUNDED_LIST, knn_ivf, list_bound};

use std::fmt;
use std::ops::Range;

use super::CELL_COUNT;
use super::digest::{DIGEST_LENGTH, TlshDigest};
use super::distance::{BodyQuery, popcount};
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

/// Length of the fixed TIVF payload header.
pub const TIVF_HEADER_LENGTH: usize = 32;

/// TIVF payload version written and accepted (C++ `TIVF_VERSION`).
pub const TIVF_VERSION: u16 = 3;

/// Embedding dimensions recorded in the header: the 256 dimensions of the
/// body embedding (C++ `TLSH_EMBED_BODY_DIMS`).
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

/// An owned TIVF index (C++ `TlshIvf`); see the [module docs](self).
///
/// The fields are public so builders can fill them; the list count is
/// `radius2.len()`. Nothing is checked on construction: the search and the
/// merge check the lengths ([`IvfIndex::check_layout`]) and bounds-check
/// what they read, [`check_index`] checks an index fully against its rows,
/// and [`TlshIvf::to_bytes`] panics on arrays of inconsistent lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlshIvf {
    /// Rows indexed: the `HDAT` row count.
    pub n: u64,
    /// `CELL_COUNT + 1` entries, nondecreasing from 0 to the list count:
    /// the lists of cell `c` are `cell_lists[c]..cell_lists[c + 1]`.
    pub cell_lists: Vec<u32>,
    /// One per list: the digest the list's `radius2` is measured from.
    pub medoids: Vec<TlshDigest>,
    /// One per list: at least the largest squared body-embedding distance
    /// from the medoid to a member (exact as built and merged).
    pub radius2: Vec<u32>,
    /// Lists + 1 entries, nondecreasing from 0 to `n`: the members of list
    /// `l` are `ids[list_start[l]..list_start[l + 1]]`.
    pub list_start: Vec<u64>,
    /// `n` row indexes into `HDAT`, ascending within a list; every row
    /// once.
    pub ids: Vec<u32>,
}

impl TlshIvf {
    /// The index of no rows: no lists, all offsets 0. It is valid over an
    /// empty row set and is the index of a merge side with no rows.
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

    /// Number of lists, `radius2.len()` (C++ `TlshIvf::lists`).
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

    /// The TIVF payload (C++ `write_tivf_data`), [`tivf_len`] bytes. The
    /// contents are written as they are; only the lengths are checked.
    ///
    /// # Panics
    ///
    /// If the arrays disagree in length with each other or with `n` (see
    /// the field docs), or there are more than `u32::MAX` lists.
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

    /// An owned copy of any index, entry by entry (for a view, the arrays
    /// its payload holds).
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
/// payload ([`TivfView`]), entry by entry; the arrays are those of the
/// [module docs](self). The search, the merge and [`check_index`] are
/// written against this trait, so they take either kind or a reference to
/// one.
///
/// The accessors take indexes into the arrays: `c` in `0..=CELL_COUNT`,
/// `l` in `0..lists()` (`0..=lists()` for [`list_start`](Self::list_start)),
/// `i` in `0..n`. They panic outside those bounds, and are cheap (an array
/// read and, for a view, a `from_le_bytes`). What the entries promise
/// depends on the index:
///
/// * after [`TivfView::parse`]: the array lengths, `cell_lists[0] == 0`,
///   `cell_lists[CELL_COUNT] == lists()`, `list_start[0] == 0` and
///   `list_start[lists()] == n`. Nothing about the inner entries or the
///   ids.
/// * a [`TlshIvf`] promises nothing; [`check_layout`](Self::check_layout)
///   checks its array lengths in O(1).
/// * after [`check_index`] over the rows: everything it lists.
///
/// The provided range helpers ([`cell_range`](Self::cell_range),
/// [`list_range`](Self::list_range), [`list_ids`](Self::list_ids)) check
/// the range they read and return a format error when it is inverted or
/// runs past the arrays, so on an index whose layout is right (always,
/// for a view) walking cells and lists through them never panics.
///
/// Implementors provide the seven accessors and
/// [`check_layout`](Self::check_layout); the rest is provided.
pub trait IvfIndex {
    /// Rows indexed (the header's `n`).
    fn n(&self) -> u64;
    /// Number of lists, `C`.
    fn lists(&self) -> usize;
    /// Entry `c` of `cell_lists`, `c <= CELL_COUNT`.
    fn cell_lists(&self, c: usize) -> u32;
    /// Medoid of list `l`.
    fn medoid(&self, l: usize) -> TlshDigest;
    /// `radius2` of list `l`: a bound on the squared body-embedding
    /// distance from the medoid to each member.
    fn radius2(&self, l: usize) -> u32;
    /// Entry `l` of `list_start`, `l <= lists()`.
    fn list_start(&self, l: usize) -> u64;
    /// Entry `i` of `ids`: an `HDAT` row index.
    fn id(&self, i: usize) -> u32;
    /// `Ok` when the arrays have the lengths the layout implies for
    /// `lists()` lists over `n()` rows (always, for a parsed view); a
    /// format error naming the first array that does not.
    fn check_layout(&self) -> Result<()>;

    /// The lists of cell `c` (`c < CELL_COUNT`):
    /// `cell_lists[c]..cell_lists[c + 1]`, or a format error when that
    /// range is inverted or runs past `lists()`. Two comparisons, no walk.
    fn cell_range(&self, c: usize) -> Result<Range<usize>> {
        let (start, end) = (self.cell_lists(c) as usize, self.cell_lists(c + 1) as usize);
        if start > end {
            return Err(Error::format(format!(
                "TIVF cell_lists decreases from {start} to {end} after cell 0x{c:04x}"
            )));
        }
        if end > self.lists() {
            return Err(Error::format(format!(
                "TIVF lists of cell 0x{c:04x} end at {end}, past the {} lists",
                self.lists()
            )));
        }
        Ok(start..end)
    }

    /// The positions in `ids` of list `l`'s members (`l < lists()`):
    /// `list_start[l]..list_start[l + 1]`, or a format error when that
    /// range is inverted or runs past `n`. Two comparisons, no walk.
    fn list_range(&self, l: usize) -> Result<Range<usize>> {
        let (start, end) = (self.list_start(l), self.list_start(l + 1));
        if start > end {
            return Err(Error::format(format!(
                "TIVF list {l} starts at {start}, after its end {end}"
            )));
        }
        if end > self.n() {
            return Err(Error::format(format!(
                "TIVF list {l} ends at {end}, past the {} ids",
                self.n()
            )));
        }
        // end <= n, and n ids are in memory (check_layout)
        Ok(start as usize..end as usize)
    }

    /// Number of members of list `l`, `list_start[l + 1] - list_start[l]`
    /// (0 if that would be negative).
    fn list_len(&self, l: usize) -> u64 {
        self.list_start(l + 1).saturating_sub(self.list_start(l))
    }

    /// The row indexes of list `l`'s members, in `ids` order (ascending on
    /// a valid index), or the error of [`list_range`](Self::list_range).
    fn list_ids(&self, l: usize) -> Result<impl Iterator<Item = u32> + '_> {
        Ok(self.list_range(l)?.map(move |i| self.id(i)))
    }
}

/// Check the index against the `HDAT` rows it indexes, or return the
/// first problem as [`Error::Format`]. Nothing requires this: the search
/// and the merge bounds-check what they read and never panic on any
/// index. It is the full structural check that [`Hashset::verify`]
/// (`hset verify`) makes, in O(n + lists + CELL_COUNT):
///
/// * [`check_layout`](IvfIndex::check_layout), `rows.len() == n`, and the
///   end checks of [`TivfView::parse`] (repeated, for owned indexes);
/// * the rows are sorted by cell, so each cell's rows are contiguous;
/// * `list_start` and `cell_lists` never decrease;
/// * no list is empty;
/// * every id is below `n`, ids ascend strictly within a list, and
///   every row is in exactly one list;
/// * every member lies in its list's cell, so the lists of cell `c`
///   hold exactly the rows of cell `c`;
/// * every member is within its list's `radius2` of the medoid
///   ([`BodyQuery::emb_body`]). The medoid need not be a member.
///
/// An index that passes is searched exactly ([`knn_ivf`] equals
/// [`knn_brute`](crate::tlsh::knn_brute)) and merges into one that passes.
/// The coalescing invariant ([`check_invariant`]) is not required.
///
/// [`Hashset::verify`]: crate::Hashset::verify
pub fn check_index<I: IvfIndex + ?Sized>(ivf: &I, rows: &[[u8; DIGEST_LENGTH]]) -> Result<()> {
    popcount().scan(
        #[inline(always)]
        || check_valid(ivf, rows),
    )
}

/// The checks of [`check_index`].
#[inline(always)]
fn check_valid<I: IvfIndex + ?Sized>(ivf: &I, rows: &[[u8; DIGEST_LENGTH]]) -> Result<()> {
    ivf.check_layout()?;
    let n = ivf.n();
    if rows.len() as u64 != n {
        return Err(Error::format(format!(
            "TIVF indexes {n} rows, the section has {}",
            rows.len()
        )));
    }
    if let Some(i) = rows
        .windows(2)
        .position(|w| cell_of(&w[0]) > cell_of(&w[1]))
    {
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

    // n distinct ids below n: every row exactly once.
    let mut seen = vec![0u64; rows.len().div_ceil(64)];
    for c in 0..CELL_COUNT {
        for l in ivf.cell_range(c)? {
            if ivf.list_len(l) == 0 {
                return Err(Error::format(format!("TIVF list {l} is empty")));
            }
            let medoid = BodyQuery::new(&ivf.medoid(l));
            let radius2 = ivf.radius2(l);
            let mut prev = None;
            for i in ivf.list_range(l)? {
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

/// The checks `parse` makes beyond the header, O(1): `cell_lists` runs
/// from 0 to the list count and `list_start` from 0 to n (C++
/// `parse_tivf_data` and `handle_tivf`).
fn check_ends<I: IvfIndex + ?Sized>(ivf: &I) -> Result<()> {
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
    Ok(())
}

/// [`check_ends`], and that `list_start` never decreases.
fn check_offsets<I: IvfIndex + ?Sized>(ivf: &I) -> Result<()> {
    check_ends(ivf)?;
    let lists = ivf.lists();
    if (0..lists).any(|l| ivf.list_start(l) > ivf.list_start(l + 1)) {
        return Err(Error::format("TIVF list offsets are not nondecreasing"));
    }
    Ok(())
}

/// The coalescing invariant of a merge (C++ `tlsh_ivf_check_invariant`):
/// at most one list per cell has fewer than `coalesce_threshold / 2`
/// members. True when `coalesce_threshold / 2 == 0` (coalescing disabled)
/// and for an index with no lists. A merge with threshold `C` leaves it
/// true; a fresh BISECT build need not satisfy it.
///
/// False when the arrays have the wrong lengths
/// ([`IvfIndex::check_layout`]) or a cell's range of lists is out of
/// bounds ([`IvfIndex::cell_range`]); never panics.
pub fn check_invariant<I: IvfIndex + ?Sized>(ivf: &I, coalesce_threshold: u32) -> bool {
    let half = u64::from(coalesce_threshold / 2);
    if half == 0 {
        return true;
    }
    ivf.check_layout().is_ok()
        && (0..CELL_COUNT).all(|c| {
            ivf.cell_range(c)
                .is_ok_and(|lists| lists.filter(|&l| ivf.list_len(l) < half).nth(1).is_none())
        })
}

/// The cell of a raw row.
fn cell_of(row: &[u8; DIGEST_LENGTH]) -> u16 {
    TlshDigest(*row).cell()
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

/// A TIVF index borrowed from its payload (C++ `TlshIvfView`), e.g. a
/// `TIVF` chunk of a mapped file. Zero-copy: the arrays are slices of the
/// payload, read with `from_le_bytes`, so any alignment works.
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
    /// Parse a `TIVF` payload over a section of `expected_n` rows (C++
    /// `parse_tivf_data` and the checks of `handle_tivf`), in O(1): no
    /// array is walked. Errors are [`Error::Format`]:
    ///
    /// * fewer than 32 bytes, version other than 3, dims other than 256;
    /// * a length other than [`tivf_len`]`(lists, n)`;
    /// * `n != expected_n`;
    /// * `cell_lists[0] != 0` or `cell_lists[CELL_COUNT] != lists`;
    /// * `list_start[0] != 0` or `list_start[lists] != n`.
    ///
    /// The flags and reserved header fields are ignored, as C++ does.
    ///
    /// The inner `cell_lists` and `list_start` entries and the ids are not
    /// looked at: the search and the merge bounds-check them as they read
    /// them, and [`check_index`] checks them fully.
    pub fn parse(payload: &'a [u8], expected_n: u64) -> Result<Self> {
        let Some((header, body)) = payload.split_first_chunk::<TIVF_HEADER_LENGTH>() else {
            return Err(Error::format(format!(
                "TIVF payload is {} bytes, shorter than its {TIVF_HEADER_LENGTH}-byte header",
                payload.len()
            )));
        };
        // flags (offset 2) and the reserved fields (12, 24) are ignored
        let (version, rest) = header.split_first_chunk::<2>().expect("32 bytes");
        let (dims, rest) = rest[2..].split_first_chunk::<4>().expect("28 bytes");
        let (lists, rest) = rest.split_first_chunk::<4>().expect("24 bytes");
        let (n, _) = rest[4..].split_first_chunk::<8>().expect("16 bytes");

        let version = u16::from_le_bytes(*version);
        if version != TIVF_VERSION {
            return Err(Error::format(format!("unsupported TIVF version {version}")));
        }
        let dims = u32::from_le_bytes(*dims);
        if dims != TIVF_DIMS {
            return Err(Error::format(format!("unsupported TIVF dims {dims}")));
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
        check_ends(&v)?;
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

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `tivf_len` is the exact `32 + 4 * 65537 + 48 * lists + 8 + 4 * n`
    /// whenever that fits in a `u64`, and `u64::MAX` otherwise; in
    /// particular it is never below the 262,188 bytes of the fixed part.
    /// So no header passes [`TivfView::parse`]'s length check on a payload
    /// shorter than that, and a payload that passes holds every array its
    /// header names. Rules out a wrapping length: with one,
    /// `lists = 0, n = 2^62 - 65537` gives `262188 + 4 n = 2^64 + 40`, a
    /// 40-byte payload passes, and the split into arrays indexes out of
    /// bounds. (A harness over `parse` itself on short payloads ran out of
    /// its 4 GB in the error messages' formatting of symbolic values; the
    /// `tivf` fuzz target covers `parse`.)
    #[kani::proof]
    #[kani::unwind(1)]
    fn tivf_len_is_exact_or_saturated() {
        let lists: u32 = kani::any();
        let n: u64 = kani::any();
        let exact = (32 + 4 * 65537 + 8) + 48 * u128::from(lists) + 4 * u128::from(n);
        let want = u64::try_from(exact).unwrap_or(u64::MAX);
        let len = tivf_len(lists, n);
        assert!(len == want);
        assert!(len >= 262_188);
    }
}
