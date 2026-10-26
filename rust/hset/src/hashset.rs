//! A loaded `.hset`: decoded structure plus lookup strategies.
//!
//! # TLSH similarity search
//!
//! A TLSH section (36-byte canonical digests, [`HashType::Tlsh`]) answers
//! k-nearest-neighbour queries by TLSH distance as well as exact lookups
//! (C `sfhash_hashset_tlsh_knn*`, `src/lib/hashset/tlsh_search.cpp`):
//!
//! * [`Hashset::tlsh_rows`]: the section's sorted rows; match indexes
//!   are positions in them.
//! * [`Hashset::tlsh_index`]: its `TIVF` index, for searching
//!   ([`crate::tlsh::knn_ivf`]) or merging ([`crate::tlsh::merge_tlsh_ivf`]).
//! * [`Hashset::tlsh_knn_strategies`], [`Hashset::tlsh_knn`] (the index
//!   when there is one, else brute force) and [`Hashset::tlsh_knn_with`]
//!   (a chosen [`KnnStrategy`], optionally counting [`KnnStats`]).
//!
//! Every strategy returns the same matches: at most k rows within the
//! distance bound, ordered by (distance, row index).
//!
//! The `TIVF` header is checked by [`Hashset::load`] in O(1), as C++
//! checks it, so a file with a bad version, dims, row count, length or
//! list-offset ends does not load. Nothing else about the index (ids,
//! cells, radii, inner offsets) is checked at load or on first use: the
//! index search bounds-checks each access it makes, so an index that is
//! out of bounds where a search reads it makes that search an
//! [`Error::Format`], and one that is corrupt but in bounds gives the
//! answer C++ gives (possibly inexact). [`Hashset::verify`] runs the full
//! structural check ([`check_index`]); brute force always works.
//!
//! ## Differences from the C API
//!
//! * A section that is not TLSH, or does not exist, is an
//!   [`Error::Input`]; C returns 0 matches (or strategies).
//! * Asking for the index of a file without one is an [`Error::Input`];
//!   C returns 0 matches.
//! * C trusts a loaded index and reads it unchecked; Rust bounds-checks
//!   the reads, so a corrupt index is an error or an inexact answer, never
//!   undefined behaviour.

use std::ops::Range;

use crate::error::{Error, Result};
use crate::format::{self, FieldDescriptor, Hint, HsetFile, RecordHeader, Section};
use crate::hash_type::HashType;
use crate::lookup::{self, Lookup, SearchConfig};
use crate::tlsh::cells::{cell_index, cell_table};
use crate::tlsh::{
    DIGEST_LENGTH, IvfIndex, KnnStats, TivfView, TlshDigest, TlshMatch, check_index, knn_brute,
    knn_ivf,
};

/// A kNN search strategy over a TLSH section (C `SFHASH_TLSH_KNN_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KnnStrategy {
    /// Every row's distance ([`crate::tlsh::knn_brute`]); always available.
    Brute,
    /// The section's `TIVF` index ([`crate::tlsh::knn_ivf`]); available when
    /// the file has one.
    Index,
}

/// The kNN strategies a TLSH section supports
/// ([`Hashset::tlsh_knn_strategies`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct KnnStrategies {
    /// [`KnnStrategy::Brute`]: true for every TLSH section.
    pub brute: bool,
    /// [`KnnStrategy::Index`]: the section has a `TIVF` index.
    pub index: bool,
}

impl KnnStrategies {
    /// Whether `strategy` is among these.
    pub fn contains(&self, strategy: KnnStrategy) -> bool {
        match strategy {
            KnnStrategy::Brute => self.brute,
            KnnStrategy::Index => self.index,
        }
    }
}

/// A decoded hash set file ready for queries. Borrows the file bytes.
pub struct Hashset<'a> {
    raw: &'a [u8],
    file: HsetFile<'a>,
    lookups: Vec<Box<dyn Lookup + 'a>>,
    /// Per section: its kNN part if it is a TLSH section of 36-byte rows.
    tlsh: Vec<Option<TlshPart<'a>>>,
}

/// What a TLSH section holds for kNN search.
#[derive(Debug)]
struct TlshPart<'a> {
    /// The sorted rows (`HDAT`).
    rows: &'a [[u8; DIGEST_LENGTH]],
    /// The `TIVF` index, its header checked at load.
    tivf: Option<TivfView<'a>>,
}

impl<'a> TlshPart<'a> {
    /// The kNN part of `s`, if it is a TLSH section of 36-byte rows. A
    /// `TIVF` (which the decoder allows only on a TLSH section) is parsed
    /// here, so a bad header fails the load.
    fn of(s: &Section<'a>) -> Result<Option<Self>> {
        if s.header.htype != HashType::Tlsh || s.hash_length() != DIGEST_LENGTH {
            if s.tivf.is_some() {
                return Err(Error::Format(format!(
                    "TIVF index in hash set '{}' of {}-byte hashes, not 36-byte TLSH digests",
                    s.header.name,
                    s.hash_length()
                )));
            }
            return Ok(None);
        }
        // the decoder checked that HDAT is hash_count rows
        let (rows, _) = s.data.as_chunks::<DIGEST_LENGTH>();
        let tivf = s
            .tivf
            .map(|payload| {
                TivfView::parse(payload, rows.len() as u64)
                    .map_err(|e| Error::Format(format!("hash set '{}': {e}", s.header.name)))
            })
            .transpose()?;
        Ok(Some(TlshPart { rows, tivf }))
    }
}

impl std::fmt::Debug for Hashset<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hashset")
            .field("name", &self.file.fhdr.name)
            .field("sections", &self.file.sections.len())
            .field("records", &self.file.record_count())
            .finish()
    }
}

impl<'a> Hashset<'a> {
    /// Decode `buf` and install a lookup strategy per section.
    pub fn load(buf: &'a [u8]) -> Result<Self> {
        Self::load_with(buf, SearchConfig::default())
    }

    /// [`Hashset::load`] with explicit search tunables.
    pub fn load_with(buf: &'a [u8], cfg: SearchConfig) -> Result<Self> {
        let file = format::decode(buf)?;
        let mut lookups = Vec::with_capacity(file.sections.len());
        for s in &file.sections {
            lookups.push(lookup::make_lookup_with(
                s.hash_length(),
                s.data,
                s.hint.as_ref(),
                cfg,
            )?);
        }
        let tlsh = file
            .sections
            .iter()
            .map(TlshPart::of)
            .collect::<Result<_>>()?;
        Ok(Hashset {
            raw: buf,
            file,
            lookups,
            tlsh,
        })
    }

    pub fn file(&self) -> &HsetFile<'a> {
        &self.file
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn name(&self) -> &str {
        &self.file.fhdr.name
    }

    pub fn description(&self) -> &str {
        &self.file.fhdr.desc
    }

    pub fn timestamp(&self) -> &str {
        &self.file.fhdr.time
    }

    pub fn version(&self) -> u64 {
        self.file.fhdr.version
    }

    /// The SHA-256 stored in the header (over bytes 40..end).
    pub fn sha2_256(&self) -> &[u8; 32] {
        &self.file.fhdr.sha2_256
    }

    /// Recompute the digest and compare with the header.
    pub fn verify_digest(&self) -> bool {
        format::encode::file_digest(self.raw).is_some_and(|d| d == self.file.fhdr.sha2_256)
    }

    pub fn section_count(&self) -> usize {
        self.file.sections.len()
    }

    pub fn section(&self, idx: usize) -> &Section<'a> {
        &self.file.sections[idx]
    }

    pub fn sections(&self) -> &[Section<'a>] {
        &self.file.sections
    }

    pub fn lookup(&self, idx: usize) -> &dyn Lookup {
        self.lookups[idx].as_ref()
    }

    /// Section index for hashes of type `t`.
    pub fn index_for_type(&self, t: HashType) -> Option<usize> {
        self.file.section_for(t)
    }

    /// Number of hashes in section `idx`.
    pub fn count(&self, idx: usize) -> usize {
        self.file.sections[idx].len()
    }

    /// Is `hash` in section `idx`? `hash` must be at least the section's hash length.
    pub fn contains(&self, idx: usize, hash: &[u8]) -> bool {
        self.lookups[idx].contains(hash)
    }

    /// Batch membership for `out.len()` contiguous hashes.
    pub fn contains_batch(&self, idx: usize, hashes: &[u8], out: &mut [bool]) {
        self.lookups[idx].contains_batch(hashes, out)
    }

    /// Index of the first hash equal to `hash` in section `idx`.
    pub fn find(&self, idx: usize, hash: &[u8]) -> Option<usize> {
        self.lookups[idx].find(hash)
    }

    /// Indices of all hashes equal to `hash` in section `idx`.
    pub fn equal_range(&self, idx: usize, hash: &[u8]) -> Range<usize> {
        self.lookups[idx].equal_range(hash)
    }

    pub fn record_header(&self) -> Option<&RecordHeader> {
        self.file.rhdr.as_ref()
    }

    pub fn record_count(&self) -> usize {
        self.file.record_count()
    }

    /// The `i`th record (raw layout), if records are present.
    pub fn record(&self, i: usize) -> Option<&'a [u8]> {
        self.file.record(i)
    }

    /// Iterate over all records.
    pub fn records(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        (0..self.record_count()).filter_map(move |i| self.record(i))
    }

    /// Records whose section-`idx` hash equals `hash`.
    pub fn records_for(&self, idx: usize, hash: &[u8]) -> Vec<&'a [u8]> {
        let s = &self.file.sections[idx];
        self.equal_range(idx, hash)
            .filter_map(|i| s.record_index(i))
            .filter_map(|r| self.record(r as usize))
            .collect()
    }

    /// Value of field `t` in record `rec`, if the record has the field and it is present.
    pub fn field_value<'r>(&self, rec: &'r [u8], t: HashType) -> Option<&'r [u8]> {
        let rhdr = self.file.rhdr.as_ref()?;
        let off = rhdr.field_offset(t)?;
        let f = rhdr.fields.iter().find(|f| f.htype == t)?;
        (rec.get(off)? == &1).then(|| &rec[off + 1..off + 1 + f.length as usize])
    }

    /// Split a record into `(field, Some(value))` or `(field, None)` per field.
    pub fn record_fields<'r>(&self, rec: &'r [u8]) -> Vec<(&FieldDescriptor, Option<&'r [u8]>)> {
        let Some(rhdr) = self.file.rhdr.as_ref() else {
            return Vec::new();
        };
        let mut off = 0usize;
        rhdr.fields
            .iter()
            .map(|f| {
                let present = rec.get(off) == Some(&1);
                let v = present.then(|| &rec[off + 1..off + 1 + f.length as usize]);
                off += f.stride();
                (f, v)
            })
            .collect()
    }

    /// The part of section `idx` that kNN works on, or an input error
    /// naming why there is none.
    fn tlsh_part(&self, idx: usize) -> Result<&TlshPart<'a>> {
        match self.tlsh.get(idx) {
            None => Err(Error::input(format!(
                "no hash set {idx}: the file has {}",
                self.tlsh.len()
            ))),
            Some(None) => {
                let s = &self.file.sections[idx];
                Err(Error::input(format!(
                    "hash set {idx} ('{}', {}, {}-byte hashes) is not a TLSH hash set",
                    s.header.name,
                    s.header.htype,
                    s.hash_length()
                )))
            }
            Some(Some(p)) => Ok(p),
        }
    }

    /// The rows of TLSH section `idx`: its sorted 36-byte canonical
    /// digests (`HDAT`), duplicates included in a records file. Row
    /// indexes in a [`TlshMatch`] and in the `TIVF` index are positions in
    /// this slice, and [`Section::record_index`] maps them to records.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] when `idx` is not a section, or not a TLSH
    /// section of 36-byte hashes (C `sfhash_hashset_tlsh_*` return 0
    /// there).
    pub fn tlsh_rows(&self, idx: usize) -> Result<&'a [[u8; DIGEST_LENGTH]]> {
        Ok(self.tlsh_part(idx)?.rows)
    }

    /// The `TIVF` index of TLSH section `idx`, or `None` when the file has
    /// none. Its rows are [`tlsh_rows`](Self::tlsh_rows).
    ///
    /// The header was checked when the file was loaded (a bad version,
    /// dims, row count, length or list-offset ends fail [`Hashset::load`]),
    /// in O(1); nothing else is, here or later. The view is what
    /// [`crate::tlsh::knn_ivf`] and [`crate::tlsh::merge_tlsh_ivf`] take;
    /// both bounds-check what they read, so a corrupt index is an error
    /// or an inexact answer, never a panic. [`verify`](Self::verify)
    /// checks it fully ([`check_index`]).
    ///
    /// # Errors
    ///
    /// [`Error::Input`] as for [`tlsh_rows`](Self::tlsh_rows).
    pub fn tlsh_index(&self, idx: usize) -> Result<Option<TivfView<'a>>> {
        Ok(self.tlsh_part(idx)?.tivf)
    }

    /// The kNN strategies TLSH section `idx` supports (C
    /// `sfhash_hashset_tlsh_knn_strategies`): brute force always, the
    /// index when the file has a `TIVF` for the section (its contents are
    /// not checked, see [`tlsh_index`](Self::tlsh_index)).
    ///
    /// # Errors
    ///
    /// [`Error::Input`] as for [`tlsh_rows`](Self::tlsh_rows) (C returns
    /// 0, no strategies).
    pub fn tlsh_knn_strategies(&self, idx: usize) -> Result<KnnStrategies> {
        let part = self.tlsh_part(idx)?;
        Ok(KnnStrategies {
            brute: true,
            index: part.tivf.is_some(),
        })
    }

    /// The `k` nearest rows of TLSH section `idx` to `q` within
    /// `max_distance` (inclusive), nearest first, ties by ascending row
    /// index (C `sfhash_hashset_tlsh_knn`). TLSH distance as
    /// [`crate::tlsh::diff`], with the length term when
    /// `include_length`. Searches with the index when the file has one,
    /// else by brute force; both return the same list.
    ///
    /// Empty when `k == 0` or `q` is null. Row indexes are into
    /// [`tlsh_rows`](Self::tlsh_rows).
    ///
    /// # Errors
    ///
    /// As [`tlsh_knn_with`](Self::tlsh_knn_with) with the strategy chosen:
    /// in particular an index search that reads out of bounds is an
    /// [`Error::Format`] here rather than a silent fallback to brute
    /// force; ask for [`KnnStrategy::Brute`] to search such a file.
    pub fn tlsh_knn(
        &self,
        idx: usize,
        q: &TlshDigest,
        k: usize,
        max_distance: u32,
        include_length: bool,
    ) -> Result<Vec<TlshMatch>> {
        let strategy = if self.tlsh_knn_strategies(idx)?.index {
            KnnStrategy::Index
        } else {
            KnnStrategy::Brute
        };
        self.tlsh_knn_with(idx, q, k, max_distance, include_length, strategy, None)
    }

    /// [`tlsh_knn`](Self::tlsh_knn) with an explicit strategy (C
    /// `sfhash_hashset_tlsh_knn_with`). [`KnnStrategy::Index`] adds its
    /// work to `stats` when given ([`crate::tlsh::knn_ivf`]: nonempty
    /// cells visited, lists bounded, rows scanned); brute force leaves
    /// `stats` unchanged.
    ///
    /// Empty when `k == 0` or `q` is null, once the section and strategy
    /// have been checked.
    ///
    /// # Errors
    ///
    /// * [`Error::Input`] when `idx` is not a TLSH section (as for
    ///   [`tlsh_rows`](Self::tlsh_rows)) or the strategy is
    ///   [`KnnStrategy::Index`] and the file has no index for it (C
    ///   returns 0 matches for both).
    /// * [`Error::Format`] for [`KnnStrategy::Index`] when the search
    ///   reads the index out of bounds ([`crate::tlsh::knn_ivf`]); brute
    ///   force still works on such a file. A corrupt index the search
    ///   reads within bounds is not detected (as in C++) and may give
    ///   inexact matches; [`verify`](Self::verify) reports it.
    // the C API's parameters, one for one
    #[allow(clippy::too_many_arguments)]
    pub fn tlsh_knn_with(
        &self,
        idx: usize,
        q: &TlshDigest,
        k: usize,
        max_distance: u32,
        include_length: bool,
        strategy: KnnStrategy,
        stats: Option<&mut KnnStats>,
    ) -> Result<Vec<TlshMatch>> {
        let rows = self.tlsh_rows(idx)?;
        match strategy {
            KnnStrategy::Brute => Ok(knn_brute(rows, q, k, max_distance, include_length)),
            KnnStrategy::Index => {
                let Some(ivf) = self.tlsh_index(idx)? else {
                    return Err(Error::input(format!(
                        "hash set {idx} ('{}') has no TIVF index to search; use brute force",
                        self.file.sections[idx].header.name
                    )));
                };
                knn_ivf(&ivf, rows, q, k, max_distance, include_length, stats).map_err(|e| {
                    Error::Format(format!(
                        "TIVF index of hash set {idx} ('{}'): {e}",
                        self.file.sections[idx].header.name
                    ))
                })
            }
        }
    }

    /// The TLSH checks of [`verify`](Self::verify) for section `idx`, its
    /// problems appended to `problems`; `None` for a section that is not
    /// TLSH.
    fn verify_tlsh(&self, idx: usize, problems: &mut Vec<String>) -> Option<TlshReport> {
        let part = self.tlsh[idx].as_ref()?;
        let s = &self.file.sections[idx];
        let cells_exact = match s.hint {
            // rows out of order have no cell index (and are reported as
            // unsorted already)
            Some(Hint::TlshCells { table }) => {
                Some(cell_index(part.rows).is_ok_and(|cells| cell_table(&cells) == table))
            }
            _ => None,
        };
        if cells_exact == Some(false) {
            problems.push(format!(
                "{}: TLSH cell hint is not the cell index of the rows",
                s.header.name
            ));
        }
        let index = part.tivf.map(|view| {
            let checked = check_index(&view, part.rows);
            if let Err(e) = &checked {
                problems.push(format!("{}: invalid TIVF index: {e}", s.header.name));
            }
            IndexReport {
                lists: view.lists(),
                valid: checked.is_ok(),
            }
        });
        Some(TlshReport { cells_exact, index })
    }

    /// Check structural invariants: digest, sortedness, hint soundness,
    /// and for TLSH sections that the cell hint is the cell index of the
    /// rows and the `TIVF` index is valid ([`TlshReport`]).
    pub fn verify(&self) -> VerifyReport {
        let mut report = VerifyReport {
            digest_ok: self.verify_digest(),
            problems: Vec::new(),
            sections: Vec::new(),
        };
        if !report.digest_ok {
            report
                .problems
                .push("SHA-256 digest does not match file contents".into());
        }
        if let (Some(rhdr), Some(rdat)) = (&self.file.rhdr, self.file.rdat) {
            let rl = rhdr.record_length as usize;
            let mut sorted = true;
            let mut dups = 0usize;
            for w in rdat.chunks_exact(rl).collect::<Vec<_>>().windows(2) {
                match w[0].cmp(w[1]) {
                    std::cmp::Ordering::Greater => sorted = false,
                    std::cmp::Ordering::Equal => dups += 1,
                    std::cmp::Ordering::Less => {}
                }
            }
            if !sorted {
                report.problems.push("records are not sorted".into());
            }
            if dups > 0 {
                report.problems.push(format!("{dups} duplicate records"));
            }
        }
        for (idx, s) in self.file.sections.iter().enumerate() {
            let lk = &self.lookups[idx];
            let hl = s.hash_length();
            let mut sr = SectionReport {
                htype: s.header.htype,
                name: s.header.name.clone(),
                count: s.len(),
                sorted: true,
                duplicates: 0,
                hint: s.hint.map(|h| h.describe()),
                hint_sound: true,
                max_window: 0,
                mean_window: 0.0,
                table_bytes: lk.table_bytes(),
                tlsh: None,
            };
            let mut total_window = 0u128;
            let mut bad_ridx = 0usize;
            for i in 0..s.len() {
                let h = s.hash(i);
                if i > 0 {
                    match s.hash(i - 1).cmp(h) {
                        std::cmp::Ordering::Greater => sr.sorted = false,
                        std::cmp::Ordering::Equal => sr.duplicates += 1,
                        std::cmp::Ordering::Less => {}
                    }
                }
                let w = lk.window(h);
                if !w.contains(&i) {
                    sr.hint_sound = false;
                }
                sr.max_window = sr.max_window.max(w.len());
                total_window += w.len() as u128;
                if let Some(r) = s.record_index(i) {
                    let ok = self
                        .record(r as usize)
                        .and_then(|rec| self.field_value(rec, s.header.htype))
                        .is_some_and(|v| v == &h[..hl]);
                    if !ok {
                        bad_ridx += 1;
                    }
                }
            }
            if bad_ridx > 0 {
                report.problems.push(format!(
                    "{}: {bad_ridx} record indices do not point at a matching record",
                    s.header.name
                ));
            }
            if !s.is_empty() {
                sr.mean_window = total_window as f64 / s.len() as f64;
            }
            if !sr.sorted {
                report
                    .problems
                    .push(format!("{}: hashes are not sorted", s.header.name));
            }
            if !sr.hint_sound {
                report.problems.push(format!(
                    "{}: hint window excludes a stored hash",
                    s.header.name
                ));
            }
            sr.tlsh = self.verify_tlsh(idx, &mut report.problems);
            report.sections.push(sr);
        }
        report
    }
}

/// Per-section findings of [`Hashset::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct SectionReport {
    pub htype: HashType,
    pub name: String,
    pub count: usize,
    pub sorted: bool,
    pub duplicates: usize,
    pub hint: Option<String>,
    /// Every stored hash lies inside the window its hint predicts.
    pub hint_sound: bool,
    pub max_window: usize,
    pub mean_window: f64,
    pub table_bytes: usize,
    /// The TLSH checks, for a TLSH section of 36-byte rows; `None` for
    /// any other section.
    pub tlsh: Option<TlshReport>,
}

/// The TLSH findings of [`Hashset::verify`] for one section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlshReport {
    /// The `0x7400` cell hint is exactly the cell index recomputed from
    /// the rows; `None` when the section has no cell hint.
    pub cells_exact: Option<bool>,
    /// The `TIVF` index, if the file has one for the section.
    pub index: Option<IndexReport>,
}

/// The `TIVF` index of a TLSH section, as [`Hashset::verify`] found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexReport {
    /// Number of lists (the header's count).
    pub lists: usize,
    /// It passed the full structural check ([`check_index`]), which only
    /// `verify` makes.
    pub valid: bool,
}

/// Result of [`Hashset::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    pub digest_ok: bool,
    /// Human-readable descriptions of every problem found (empty if sound).
    pub problems: Vec<String>,
    pub sections: Vec<SectionReport>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{BuildOptions, Builder};
    use crate::hex;

    fn sample() -> Vec<u8> {
        let mut b = Builder::new(&[HashType::Md5, HashType::Sha1, HashType::Size]).unwrap();
        b.add_text_line(
            "081d3d40b257d8bbc5858345ad186beb 0af8e028c7048ad772ddec2200ec7e0e4d58b0c3 10",
        )
        .unwrap();
        b.add_text_line(
            "19875d9651a319fdb8f7332b660c432d 1127ceb2c2d789c1d7615b12082ca30222f3c612 20",
        )
        .unwrap();
        b.add_text_line(
            "19875d9651a319fdb8f7332b660c432d 3e909896b309492e00444212bb2b270b5809a0cf ",
        )
        .unwrap();
        b.build(&BuildOptions::new("sample", "three records").timestamp("2024-01-01T00:00:00Z"))
            .unwrap()
    }

    #[test]
    fn load_query_and_records() {
        let bytes = sample();
        let hs = Hashset::load(&bytes).unwrap();
        assert_eq!(hs.name(), "sample");
        assert_eq!(hs.description(), "three records");
        assert_eq!(hs.timestamp(), "2024-01-01T00:00:00Z");
        assert!(hs.verify_digest());
        assert_eq!(hs.section_count(), 3);
        assert_eq!(hs.record_count(), 3);

        let md5 = hs.index_for_type(HashType::Md5).unwrap();
        let sha = hs.index_for_type(HashType::Sha1).unwrap();
        let size = hs.index_for_type(HashType::Size).unwrap();
        assert_eq!(hs.index_for_type(HashType::Blake3), None);
        assert_eq!(hs.count(md5), 3);
        assert_eq!(hs.count(sha), 3);
        assert_eq!(hs.count(size), 2);

        let dup = hex::decode("19875d9651a319fdb8f7332b660c432d").unwrap();
        assert!(hs.contains(md5, &dup));
        assert_eq!(hs.equal_range(md5, &dup).len(), 2);
        let recs = hs.records_for(md5, &dup);
        assert_eq!(recs.len(), 2);
        let shas: Vec<String> = recs
            .iter()
            .map(|r| hex::encode(hs.field_value(r, HashType::Sha1).unwrap()))
            .collect();
        assert!(shas.contains(&"1127ceb2c2d789c1d7615b12082ca30222f3c612".to_string()));
        assert!(shas.contains(&"3e909896b309492e00444212bb2b270b5809a0cf".to_string()));
        let sizes: Vec<Option<&[u8]>> = recs
            .iter()
            .map(|r| hs.field_value(r, HashType::Size))
            .collect();
        assert!(sizes.contains(&None));
        assert!(sizes.contains(&Some(&20u64.to_le_bytes()[..])));

        assert!(hs.contains(size, &10u64.to_le_bytes()));
        assert!(!hs.contains(size, &11u64.to_le_bytes()));

        let mut out = [false; 2];
        let mut q = Vec::new();
        q.extend_from_slice(&dup);
        q.extend_from_slice(&[0u8; 16]);
        hs.contains_batch(md5, &q, &mut out);
        assert_eq!(out, [true, false]);

        let fields = hs.record_fields(hs.record(0).unwrap());
        assert_eq!(fields.len(), 3);
        assert!(hs.records().count() == 3);

        let report = hs.verify();
        assert!(report.is_ok(), "{:?}", report.problems);
        assert!(report.sections.iter().all(|s| s.sorted && s.hint_sound));
        assert_eq!(report.sections[md5].duplicates, 1);
    }

    #[test]
    fn verify_detects_corruption() {
        let mut bytes = sample();
        let hs = Hashset::load(&bytes).unwrap();
        let toc = hs.file().toc.clone();
        drop(hs);
        // Corrupt the first byte of the sha1 HDAT (second HDAT chunk in the file).
        let hdat_offsets: Vec<u64> = toc
            .iter()
            .filter(|(_, t)| *t == format::chunk::HDAT)
            .map(|(o, _)| *o)
            .collect();
        let p = hdat_offsets[1] as usize + 12;
        bytes[p] = 0xff;
        let hs = Hashset::load(&bytes).unwrap();
        let r = hs.verify();
        assert!(!r.digest_ok);
        assert!(!r.is_ok());
        assert!(r.problems.iter().any(|p| p.contains("not sorted")));
    }

    #[test]
    fn accessors_expose_the_loaded_file() {
        let bytes = sample();
        let hs = Hashset::load(&bytes).unwrap();
        assert_eq!(hs.raw(), &bytes[..]);
        assert_eq!(hs.version(), format::FORMAT_VERSION);
        assert_eq!(hs.version(), 2);
        let types: Vec<HashType> = hs.sections().iter().map(|s| s.header.htype).collect();
        assert_eq!(types, [HashType::Md5, HashType::Sha1, HashType::Size]);
        assert_eq!(
            format!("{hs:?}"),
            r#"Hashset { name: "sample", sections: 3, records: 3 }"#
        );
    }

    #[test]
    fn verify_reports_mean_window_and_duplicate_records() {
        let mut bytes = sample();
        let hs = Hashset::load(&bytes).unwrap();
        let size = hs.index_for_type(HashType::Size).unwrap();
        // The size section has no hint, so each of its 2 hashes is
        // searched for over the whole section: a window of 2.
        let r = hs.verify();
        assert_eq!(r.sections[size].hint, None);
        assert_eq!(r.sections[size].max_window, 2);
        assert_eq!(r.sections[size].mean_window, 2.0);
        assert!(!r.problems.iter().any(|p| p.contains("duplicate")));

        // Copy record 0 over record 1: records stay sorted, one duplicate.
        let rl = hs.record_header().unwrap().record_length as usize;
        let rdat = hs
            .file()
            .toc
            .iter()
            .find(|(_, t)| *t == format::chunk::RDAT)
            .map(|(o, _)| *o as usize + format::chunk::CHUNK_HEADER_LEN)
            .unwrap();
        drop(hs);
        bytes.copy_within(rdat..rdat + rl, rdat + rl);
        let hs = Hashset::load(&bytes).unwrap();
        let r = hs.verify();
        assert!(
            r.problems.iter().any(|p| p == "1 duplicate records"),
            "{:?}",
            r.problems
        );
        assert!(!r.problems.iter().any(|p| p.contains("not sorted")));
    }
}
