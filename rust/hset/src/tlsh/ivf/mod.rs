//! The TIVF inverted-file index over a TLSH hash set: its in-memory model,
//! the on-disk chunk payload, and validation. C++: `include/hashset/
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
//! # Validation
//!
//! [`TivfView::parse`] checks what C++ checks at load (header values,
//! length, row count, the ends of `cell_lists` and `list_start`, and that
//! `list_start` never decreases), which is O(lists). [`IvfIndex::validate`]
//! checks the rest against the rows, O(n), and returns a [`ValidIvf`]; the
//! hash set runs it lazily on first indexed use (controller ruling 5).
//! [`check_invariant`] is the merge's coalescing invariant, a property of
//! good indexes rather than a validity condition.
//!
//! # Differences from the C++ library
//!
//! * `parse` rejects non-zero flags and reserved header fields, which
//!   `parse_tivf_data` ignores.
//! * C++ never checks the ids, `cell_lists` monotonicity, cells or radii of
//!   a loaded index; Rust's `validate` does, so an inconsistent index is a
//!   format error instead of a wrong (or out-of-bounds) search.
//! * A hash set without an index has no `TivfView` (C++ uses an empty
//!   `TlshIvfView`); [`TlshIvf::empty`] is the index of no rows.

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
/// `radius2.len()`. Nothing is checked on construction:
/// [`IvfIndex::validate`] checks an index against its rows, and
/// [`TlshIvf::to_bytes`] panics on arrays of inconsistent lengths.
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
/// [module docs](self). The search, the merge and validation are written
/// against this trait, so they take either kind, a reference to one, or a
/// [`ValidIvf`].
///
/// The accessors take indexes into the arrays: `c` in `0..=CELL_COUNT`,
/// `l` in `0..lists()` (`0..=lists()` for [`list_start`](Self::list_start)),
/// `i` in `0..n`. They panic outside those bounds, and are cheap (an array
/// read and, for a view, a `from_le_bytes`). What the entries promise
/// depends on the index:
///
/// * after [`TivfView::parse`]: the array lengths, `cell_lists[0] == 0`,
///   `cell_lists[CELL_COUNT] == lists()`, `list_start[0] == 0`,
///   `list_start[lists()] == n` and `list_start` nondecreasing. Nothing
///   about the ids, and inner `cell_lists` entries may exceed `lists()`.
/// * through a [`ValidIvf`]: everything [`IvfIndex::validate`] lists.
/// * a [`TlshIvf`] promises nothing until validated.
///
/// The provided range helpers ([`cell_range`](Self::cell_range),
/// [`list_range`](Self::list_range)) clamp to the arrays, so walking a
/// parsed but unvalidated view through them never panics; on a valid
/// index they are the exact ranges.
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
    /// `cell_lists[c]..cell_lists[c + 1]`, clamped into `0..lists()`.
    fn cell_range(&self, c: usize) -> Range<usize> {
        let end = (self.cell_lists(c + 1) as usize).min(self.lists());
        (self.cell_lists(c) as usize).min(end)..end
    }

    /// The positions in `ids` of list `l`'s members:
    /// `list_start[l]..list_start[l + 1]`, clamped into `0..n`.
    fn list_range(&self, l: usize) -> Range<usize> {
        let end = self.list_start(l + 1).min(self.n()) as usize;
        (self.list_start(l) as usize).min(end)..end
    }

    /// Number of members of list `l`, `list_start[l + 1] - list_start[l]`
    /// (0 if that would be negative).
    fn list_len(&self, l: usize) -> u64 {
        self.list_start(l + 1).saturating_sub(self.list_start(l))
    }

    /// The row indexes of list `l`'s members, in `ids` order (ascending on
    /// a valid index).
    fn list_ids(&self, l: usize) -> impl Iterator<Item = u32> + '_ {
        self.list_range(l).map(move |i| self.id(i))
    }

    /// Check the index against the `HDAT` rows it indexes and wrap it as a
    /// [`ValidIvf`], or return the first problem as [`Error::Format`]
    /// (controller ruling 5). Checks, in O(n + lists + CELL_COUNT):
    ///
    /// * [`check_layout`](Self::check_layout), `rows.len() == n`, and the
    ///   offset checks of [`TivfView::parse`] (repeated, for owned indexes);
    /// * the rows are sorted by cell, so each cell's rows are contiguous;
    /// * `cell_lists` never decreases;
    /// * no list is empty;
    /// * every id is below `n`, ids ascend strictly within a list, and
    ///   every row is in exactly one list;
    /// * every member lies in its list's cell, so the lists of cell `c`
    ///   hold exactly the rows of cell `c`;
    /// * every member is within its list's `radius2` of the medoid
    ///   ([`BodyQuery::emb_body`]). The medoid need not be a member.
    ///
    /// The coalescing invariant ([`check_invariant`]) is not required.
    ///
    /// Takes the index by value; pass `&index` to keep it.
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

/// The coalescing invariant of a merge (C++ `tlsh_ivf_check_invariant`):
/// at most one list per cell has fewer than `coalesce_threshold / 2`
/// members. True when `coalesce_threshold / 2 == 0` (coalescing disabled)
/// and for an index with no lists. A merge with threshold `C` leaves it
/// true; a fresh BISECT build need not satisfy it.
///
/// Never panics on a parsed view, validated or not (the walk uses the
/// clamped [`IvfIndex::cell_range`]).
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

/// An index that passed [`IvfIndex::validate`] against `rows()`, made only
/// by `validate`. It implements [`IvfIndex`] by forwarding, and code taking
/// one may rely on every check `validate` lists, in particular:
///
/// * `rows()` are the indexed rows, sorted by cell, `rows().len() == n`;
/// * the members of the lists of cell `c` are exactly the rows of cell
///   `c`, a contiguous range of `rows()`, so a cell with a single list
///   holds the rows `ids[list_start[l]]..` in order;
/// * every list is nonempty, ascending, and within `radius2` of its medoid;
/// * all ranges are in bounds, so no accessor panics on them.
#[derive(Clone, Copy, Debug)]
pub struct ValidIvf<'r, I> {
    index: I,
    rows: &'r [[u8; DIGEST_LENGTH]],
}

impl<'r, I: IvfIndex> ValidIvf<'r, I> {
    /// The validated index.
    pub fn index(&self) -> &I {
        &self.index
    }

    /// The rows it was validated against.
    pub fn rows(&self) -> &'r [[u8; DIGEST_LENGTH]] {
        self.rows
    }

    /// The index, without the guarantee.
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
    /// `parse_tivf_data` and the checks of `handle_tivf`), in O(lists).
    /// Errors are [`Error::Format`]:
    ///
    /// * fewer than 32 bytes, version other than 3, dims other than 256,
    ///   non-zero flags or reserved fields;
    /// * a length other than [`tivf_len`]`(lists, n)`;
    /// * `n != expected_n`;
    /// * `cell_lists[0] != 0` or `cell_lists[CELL_COUNT] != lists`;
    /// * `list_start[0] != 0`, `list_start[lists] != n`, or a decreasing
    ///   `list_start`.
    ///
    /// The ids and inner `cell_lists` entries are not looked at: call
    /// [`IvfIndex::validate`] before relying on them.
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
