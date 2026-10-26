//! Merge-based set operations on `.hset` files (C++ `hset_merge.cpp`,
//! HASHSET_FORMAT "Set operations").
//!
//! A set operation on two hash sets is a two-pointer merge of their sorted
//! sections. Each merge reports, for every input row (or record), the row it
//! becomes in the output, or [`DROPPED`] ([`RECORD_DROPPED`] for records).
//! The derived structures of a section (its `RIDX` record index, a TLSH
//! `TIVF` index) are carried through the merge by those maps.
//!
//! * [`merge`] writes the union, intersection or difference of two loaded
//!   files ([`MergeOptions`], [`TlshIndexPolicy`]), without re-sorting or
//!   re-clustering anything.
//! * [`merge_records`], [`merge_rows`] and [`RowMerge`] are its parts:
//!   the record merge, the row merge and the row maps' gathers.

use std::cmp::Ordering;

use crate::builder::{TLSH_OPTION_INDEX, TLSH_OPTION_INDEX_KMEANS, TLSH_OPTION_INHERIT, now_utc};
use crate::error::{Error, Result};
use crate::format::{
    self, Document, FORMAT_VERSION, FieldDescriptor, HashsetIn, HsetFile, RecordHeader, RecordsIn,
    Section,
};
use crate::hash_type::HashType;
use crate::hashset::Hashset;
use crate::lookup::{self, BitsPolicy, HintSpec};
use crate::tlsh::cells::{cell_index, cell_table};
use crate::tlsh::ivf::{
    DEFAULT_COALESCE, IvfBuildOptions, TlshIvf, build_tlsh_ivf, merge_tlsh_ivf,
};
use crate::tlsh::{CELL_HINT_TAG, DIGEST_LENGTH as TLSH_LENGTH};

/// A binary set operation (C `SFHASH_HSET_OP_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOp {
    Union,
    Intersect,
    /// Left minus right.
    Subtract,
}

impl SetOp {
    /// The operation's noun: "union", "intersection" or "difference".
    pub fn name(self) -> &'static str {
        match self {
            SetOp::Union => "union",
            SetOp::Intersect => "intersection",
            SetOp::Subtract => "difference",
        }
    }
}

/// Whether a merge writes the `TIVF` index of a TLSH section
/// ([`MergeOptions::tlsh_index`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlshIndexPolicy {
    /// Write it iff every input that has the TLSH section has an index
    /// (C `SFHASH_HSET_TLSH_INHERIT`).
    #[default]
    Inherit,
    /// Always write it (C `SFHASH_HSET_TLSH_INDEX`).
    Write,
    /// Never write it (C `tlsh_options` 0).
    Omit,
}

impl TlshIndexPolicy {
    /// The policy of the C `tlsh_options` bits (`SFHASH_HSET_TLSH_*`, as
    /// `sfhash_hashset_merge` and `hsetop`'s `HSET_TLSH_OPTIONS` take
    /// them):
    ///
    /// * `4` (`INHERIT`): [`Inherit`](Self::Inherit), whatever else is set
    ///   (`write_merged_hset` tests it before `INDEX`);
    /// * else `2` (`INDEX`): [`Write`](Self::Write);
    /// * else [`Omit`](Self::Omit). Bit `1` (once `VECTORS`, now reserved)
    ///   is ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] when bit `8` (`INDEX_KMEANS`, the k-means index
    /// build, which is not ported; controller ruling 4) or any unknown bit
    /// is set. C++ honours `8` when it rebuilds an index (and ignores it
    /// under `INHERIT`) and ignores unknown bits.
    pub fn from_tlsh_options(bits: u32) -> Result<Self> {
        if bits & TLSH_OPTION_INDEX_KMEANS != 0 {
            return Err(Error::input(
                "TLSH option 8 (INDEX_KMEANS, the k-means index build) is not supported",
            ));
        }
        let unknown = bits & !(1 | TLSH_OPTION_INDEX | TLSH_OPTION_INHERIT);
        if unknown != 0 {
            return Err(Error::input(format!(
                "unknown TLSH option bits 0x{unknown:x} in {bits}"
            )));
        }
        Ok(if bits & TLSH_OPTION_INHERIT != 0 {
            TlshIndexPolicy::Inherit
        } else if bits & TLSH_OPTION_INDEX != 0 {
            TlshIndexPolicy::Write
        } else {
            TlshIndexPolicy::Omit
        })
    }
}

/// Options of [`merge`] (C++ `MergeOptions` plus the name, description
/// and hints that `write_merged_hset` takes or fixes).
#[derive(Debug, Clone, PartialEq)]
pub struct MergeOptions {
    /// The output's name (FHDR).
    pub name: String,
    /// The output's description (FHDR).
    pub desc: String,
    /// ISO-8601 UTC timestamp of the output; `None` means "now".
    pub timestamp: Option<String>,
    /// Write the record table (`RHDR`, `RDAT`, and an `RIDX` per section)
    /// when both inputs have one.
    pub write_records: bool,
    /// Write the hash sections when the inputs have them.
    pub write_hashsets: bool,
    /// The hint of each digest section, as [`BuildOptions::hint`]: the
    /// default sizes hull hints by `bits_policy`; [`HintSpec::LEGACY`]
    /// writes the `0x6208` block hint C++ writes. A TLSH section always
    /// gets its `0x7400` cell index, recomputed from the merged rows.
    ///
    /// [`BuildOptions::hint`]: crate::BuildOptions::hint
    pub hint: HintSpec,
    /// Sizes automatic hints, as [`BuildOptions::bits_policy`](crate::BuildOptions::bits_policy).
    pub bits_policy: BitsPolicy,
    /// Whether TLSH sections get a `TIVF` index (default
    /// [`TlshIndexPolicy::Inherit`]).
    pub tlsh_index: TlshIndexPolicy,
    /// The coalescing threshold `C` of [`merge_tlsh_ivf`] (default
    /// [`DEFAULT_COALESCE`], 64; 0 disables coalescing). C++'s
    /// `SFHASH_HSET_COALESCE_DEFAULT` sentinel has no counterpart: pass
    /// the value.
    pub coalesce_threshold: u32,
    /// The BISECT build of an index made from scratch because an input
    /// lacks one (default [`IvfBuildOptions::default`], C++'s).
    pub ivf_build: IvfBuildOptions,
}

impl MergeOptions {
    /// Both write flags set, hull hints sized automatically, the index
    /// inherited, the default coalescing threshold and index build.
    pub fn new(name: impl Into<String>, desc: impl Into<String>) -> Self {
        MergeOptions {
            name: name.into(),
            desc: desc.into(),
            timestamp: None,
            write_records: true,
            write_hashsets: true,
            hint: HintSpec::Hull { bits: u8::MAX },
            bits_policy: BitsPolicy::default(),
            tlsh_index: TlshIndexPolicy::Inherit,
            coalesce_threshold: DEFAULT_COALESCE,
            ivf_build: IvfBuildOptions::default(),
        }
    }
}

/// The union, intersection or difference (`left` minus `right`) of two
/// loaded files, as a complete file image (C++ `write_merged_hset`, C
/// `sfhash_hashset_merge` and the builder-shaped set operations).
///
/// * **Records.** When both inputs have records, the operation is applied
///   to them ([`merge_records`]: widened to left's fields then right's
///   extras, merged, identical records once), whether or not the table is
///   written. Rows then follow their records: a row is emitted iff its
///   record is, equal rows of different records stay duplicates, and
///   `RIDX` is remapped through the record map. A hashsets-only output
///   (`write_records` false) has each such row once.
/// * **Sections.** With records on both sides, one section per output
///   record field, named as the field; otherwise one per type of either
///   input, left's in left's order then right's extras, with the first
///   side's name. A type on one side only is merged against an empty run,
///   rows as sets: equal rows once, the left copy.
/// * **TLSH.** The cell hint is recomputed from the merged rows. The
///   `TIVF` is written as [`MergeOptions::tlsh_index`] says; it is carried
///   through the merge by [`merge_tlsh_ivf`] when every input with the
///   section has one, else built from the merged rows by
///   [`build_tlsh_ivf`].
/// * **Layout** as [`format::encode()`] writes it: HDAT on a 4096-byte
///   boundary, an exact FTOC, the SHA-256 over the file from offset 40.
///
/// # Errors
///
/// [`Error::Input`], with C++'s messages, when exactly one input has hash
/// sections ("cannot merge a records-only hashset with one that has hash
/// sections"), neither records nor sections are on both sides, the write
/// flags leave nothing to write, a field has two lengths, a section's
/// hash length is not its output field's, or in a record merge a side has
/// a field without its section or a section without `RIDX`; also for a
/// name or description over 65535 bytes. [`Error::Format`] when the merge
/// carries an input `TIVF` and reads it out of bounds, and
/// [`Error::Input`] when such an index's mapped ids are not increasing
/// within a list ([`merge_tlsh_ivf`]); the input index is not otherwise
/// checked, as in C++.
///
/// # Differences from the C++ library
///
/// * Index policy: one Rust default, [`TlshIndexPolicy::Inherit`]
///   (`sfhash_hashset_merge`'s and `hsetop`'s); the C++ builder-shaped set
///   operations default to writing the index (controller ruling 7).
///   `INDEX_KMEANS` is not supported ([`TlshIndexPolicy::from_tlsh_options`]).
/// * Hints: C++ writes the `0x6208` block hint on every section but SIZE;
///   Rust writes [`MergeOptions::hint`] on digest sections only, as the
///   builder does (none on SIZE or ENTROPY), and the cell index only on a
///   36-byte TLSH section (a TLSH section of another length is opaque).
/// * An input index is not validated before it is merged (C++ trusts it
///   too), but every read of it is bounds-checked: one out of bounds is an
///   error, never a panic or undefined behaviour.
/// * The output is returned, not written to a file, and its timestamp is
///   [`MergeOptions::timestamp`] when given.
pub fn merge(
    op: SetOp,
    left: &Hashset<'_>,
    right: &Hashset<'_>,
    opts: &MergeOptions,
) -> Result<Vec<u8>> {
    for (s, what) in [(&opts.name, "name"), (&opts.desc, "desc")] {
        if s.len() > usize::from(u16::MAX) {
            return Err(Error::input(format!(
                "{what} is too long, maximum length is 65535 bytes"
            )));
        }
    }
    let (lf, rf) = (left.file(), right.file());
    // the operation is applied to the records when both sides have them
    let (lrec, rrec) = (records_of(lf), records_of(rf));
    let record_merge = lrec.is_some() && rrec.is_some();
    if lf.sections.is_empty() != rf.sections.is_empty() {
        return Err(Error::input(
            "cannot merge a records-only hashset with one that has hash sections",
        ));
    }
    if !record_merge && lf.sections.is_empty() {
        return Err(Error::input(
            "the inputs have neither records nor hash sections in common",
        ));
    }
    let with_records = record_merge && opts.write_records;
    let with_hashsets = !lf.sections.is_empty() && opts.write_hashsets;
    if !with_records && !with_hashsets {
        return Err(Error::input(
            "neither records nor hash sections are to be written",
        ));
    }

    let rm = match (lrec, rrec) {
        (Some((lh, ld)), Some((rh, rd))) => Some(merge_records(op, lh, ld, rh, rd)?),
        _ => None,
    };
    let ofields = match (&rm, with_hashsets) {
        (_, false) => Vec::new(),
        (Some(m), true) => m.fields.clone(),
        (None, true) => section_fields(lf, rf),
    };
    let ctx = SectionMerge {
        op,
        left,
        right,
        records: rm.as_ref(),
        with_records,
        opts,
    };
    let mut secs = Vec::with_capacity(ofields.len());
    for f in &ofields {
        secs.push(ctx.section(f)?);
    }
    let time = match &opts.timestamp {
        Some(t) => t.clone(),
        None => now_utc(),
    };
    format::encode(&Document {
        version: FORMAT_VERSION,
        name: &opts.name,
        desc: &opts.desc,
        time: &time,
        records: rm.as_ref().filter(|_| with_records).map(|m| RecordsIn {
            fields: &m.fields,
            record_length: m.record_length as usize,
            data: &m.rdat,
        }),
        hashsets: secs.iter().map(OutSection::input).collect(),
    })
}

/// The record table of `f`, if it has one with fields (C++ `has_records`).
fn records_of<'f, 'a>(f: &'f HsetFile<'a>) -> Option<(&'f RecordHeader, &'a [u8])> {
    let rhdr = f.rhdr.as_ref().filter(|h| !h.fields.is_empty())?;
    Some((rhdr, f.rdat.unwrap_or(&[])))
}

/// The output fields of a merge without records: left's section types,
/// then right's extras, each with the first side's name and length.
fn section_fields(lf: &HsetFile<'_>, rf: &HsetFile<'_>) -> Vec<FieldDescriptor> {
    let mut fields: Vec<FieldDescriptor> = Vec::new();
    for s in lf.sections.iter().chain(&rf.sections) {
        if !fields.iter().any(|f| f.htype == s.header.htype) {
            fields.push(FieldDescriptor {
                htype: s.header.htype,
                name: s.header.name.clone(),
                length: s.header.hash_length,
            });
        }
    }
    fields
}

/// What every output section of one merge shares.
struct SectionMerge<'m, 'l, 'r> {
    op: SetOp,
    left: &'m Hashset<'l>,
    right: &'m Hashset<'r>,
    /// The record merge, when both inputs have records.
    records: Option<&'m RecordMerge>,
    /// Whether the output has the record table (and so `RIDX` chunks).
    with_records: bool,
    opts: &'m MergeOptions,
}

/// One output hash section of a merge, ready to encode.
struct OutSection {
    field: FieldDescriptor,
    data: Vec<u8>,
    hint: Option<(u16, Vec<u8>)>,
    ridx: Option<Vec<u8>>,
    tivf: Option<Vec<u8>>,
}

impl SectionMerge<'_, '_, '_> {
    /// The section of field `f`: the merge of the inputs' sections of its
    /// type (an absent one is an empty run).
    fn section(&self, f: &FieldDescriptor) -> Result<OutSection> {
        let len = usize::try_from(f.length)
            .map_err(|_| Error::input(format!("{} hashes are too long", f.name)))?;
        let ls = self.side(self.left, f, "left")?;
        let rs = self.side(self.right, f, "right")?;
        let (lrows, rrows) = (
            ls.map_or(&[][..], |s| s.data),
            rs.map_or(&[][..], |s| s.data),
        );
        let owners = self.records.map(|m| {
            (
                RowOwners {
                    ridx: ls.and_then(|s| s.ridx).unwrap_or(&[]),
                    recmap: &m.lmap,
                },
                RowOwners {
                    ridx: rs.and_then(|s| s.ridx).unwrap_or(&[]),
                    recmap: &m.rmap,
                },
            )
        });
        let mode = match owners {
            None => RowMode::Set(self.op),
            Some((left, right)) => RowMode::Records {
                left,
                right,
                // a hashsets-only output has each row once
                collapse_equal: !self.with_records,
            },
        };
        let m = merge_rows(lrows, rrows, len, mode)?;
        let data = m.gather_rows(lrows, rrows, len)?;
        let ridx = match owners {
            Some((l, r)) if self.with_records => Some(m.gather_ridx(l, r)?),
            _ => None,
        };
        let opts = self.opts;
        let mut tivf = None;
        let hint = if f.htype == HashType::Tlsh && len == TLSH_LENGTH {
            // the cell index is recomputed from the merged rows
            let (rows, _) = data.as_chunks::<TLSH_LENGTH>();
            tivf = self
                .tlsh_index(f.htype, &m, rows)?
                .map(|ivf| ivf.to_bytes());
            Some((CELL_HINT_TAG, cell_table(&cell_index(rows)?)))
        } else if f.htype.is_digest() {
            let spec = lookup::resolve_bits(opts.hint, data.len() / len, len, &opts.bits_policy);
            lookup::build_hint(len, &data, spec)?
        } else {
            None
        };
        Ok(OutSection {
            field: f.clone(),
            data,
            hint,
            ridx,
            tivf,
        })
    }

    /// The `TIVF` index of the merged TLSH section of type `t` (its rows
    /// `rows`, merged by `m`), if the policy writes one: carried through
    /// the merge ([`merge_tlsh_ivf`]) when every input that has the
    /// section has an index, else built over `rows` ([`build_tlsh_ivf`]).
    fn tlsh_index(
        &self,
        t: HashType,
        m: &RowMerge,
        rows: &[[u8; TLSH_LENGTH]],
    ) -> Result<Option<TlshIvf>> {
        let (li, ri) = (self.left.index_for_type(t), self.right.index_for_type(t));
        let indexed =
            |hs: &Hashset<'_>, i: Option<usize>| i.is_none_or(|i| hs.section(i).tivf.is_some());
        let all_indexed = indexed(self.left, li) && indexed(self.right, ri);
        let write = match self.opts.tlsh_index {
            TlshIndexPolicy::Inherit => all_indexed,
            TlshIndexPolicy::Write => true,
            TlshIndexPolicy::Omit => false,
        };
        if !write {
            return Ok(None);
        }
        if !all_indexed {
            return build_tlsh_ivf(rows, &self.opts.ivf_build).map(Some);
        }
        let lv = li.map(|i| self.left.tlsh_index(i)).transpose()?.flatten();
        let rv = ri.map(|i| self.right.tlsh_index(i)).transpose()?.flatten();
        merge_tlsh_ivf(
            lv.as_ref().map(|v| (v, &m.lmap[..])),
            rv.as_ref().map(|v| (v, &m.rmap[..])),
            rows,
            self.opts.coalesce_threshold,
        )
        .map(Some)
    }
}

impl SectionMerge<'_, '_, '_> {
    /// `hs`'s section for the output field `f`, if it has one, checked
    /// against the field: its hashes have the field's length and, in a
    /// record merge, it has a record index, and a side with the field in
    /// its records has the section (`side` names the side in errors).
    fn side<'s, 'a>(
        &self,
        hs: &'s Hashset<'a>,
        f: &FieldDescriptor,
        side: &str,
    ) -> Result<Option<&'s Section<'a>>> {
        let record_merge = self.records.is_some();
        let Some(i) = hs.index_for_type(f.htype) else {
            let has_field = hs
                .record_header()
                .is_some_and(|h| h.fields.iter().any(|x| x.htype == f.htype));
            if record_merge && has_field {
                return Err(Error::input(format!(
                    "{side} has a {0} field but no {0} hashset",
                    f.name
                )));
            }
            return Ok(None);
        };
        let s = hs.section(i);
        if s.header.hash_length != f.length {
            return Err(Error::input(format!(
                "{side} {} hashset has hash length {}, expected {}",
                f.name, s.header.hash_length, f.length
            )));
        }
        if record_merge && s.ridx.is_none() {
            return Err(Error::input(format!(
                "{side} {} hashset has no record index",
                f.name
            )));
        }
        Ok(Some(s))
    }
}

impl OutSection {
    fn input(&self) -> HashsetIn<'_> {
        HashsetIn {
            htype: self.field.htype,
            name: &self.field.name,
            hash_length: self.field.length as usize,
            data: &self.data,
            hint: self.hint.as_ref().map(|(t, b)| (*t, b.as_slice())),
            ridx: self.ridx.as_deref(),
            tivf: self.tivf.as_deref(),
        }
    }
}

/// The output fields of merging two record tables: the left fields followed
/// by the right fields the left lacks (fields are matched by type). A field
/// with different lengths on the two sides is an input error; a header that
/// lists a type twice ([`RecordHeader::repeated_type`]) is a format error.
pub fn merged_record_fields(
    left: &RecordHeader,
    right: &RecordHeader,
) -> Result<Vec<FieldDescriptor>> {
    for (hdr, side) in [(left, "left"), (right, "right")] {
        if let Some(t) = hdr.repeated_type() {
            return Err(Error::format(format!(
                "the {side} RHDR lists the {} field twice",
                t.name()
            )));
        }
    }
    let mut fields = left.fields.clone();
    for f in &right.fields {
        match fields.iter().find(|o| o.htype == f.htype) {
            None => fields.push(f.clone()),
            Some(o) if o.length != f.length => {
                return Err(Error::input(format!(
                    "field {} has length {} on the left and {} on the right",
                    f.name, o.length, f.length
                )));
            }
            Some(_) => {}
        }
    }
    Ok(fields)
}

/// The result of [`merge_records`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordMerge {
    /// The output fields ([`merged_record_fields`]).
    pub fields: Vec<FieldDescriptor>,
    /// Bytes per output record.
    pub record_length: u64,
    /// The output records (an `RDAT` payload), sorted and unique.
    pub rdat: Vec<u8>,
    /// Output record of each left record, or [`RECORD_DROPPED`].
    pub lmap: Vec<u64>,
    /// Output record of each right record, or [`RECORD_DROPPED`].
    pub rmap: Vec<u64>,
}

impl RecordMerge {
    /// Number of output records.
    pub fn record_count(&self) -> u64 {
        (self.rdat.len() as u64)
            .checked_div(self.record_length)
            .unwrap_or(0)
    }

    /// The `RHDR` of the output.
    pub fn header(&self) -> RecordHeader {
        RecordHeader {
            record_length: self.record_length,
            record_count: self.record_count(),
            fields: self.fields.clone(),
        }
    }
}

/// Merges two record tables (`ldat` and `rdat` hold the records their
/// headers describe). The output fields are [`merged_record_fields`];
/// records are widened to them (an absent field is a zero presence byte and
/// a zero value) and merged in sorted order, identical records collapsing to
/// the left copy. For intersection and difference only left records are
/// emitted, so `rmap` is all [`RECORD_DROPPED`].
pub fn merge_records(
    op: SetOp,
    lhdr: &RecordHeader,
    ldat: &[u8],
    rhdr: &RecordHeader,
    rdat: &[u8],
) -> Result<RecordMerge> {
    let fields = merged_record_fields(lhdr, rhdr)?;
    let len: usize = fields.iter().map(FieldDescriptor::stride).sum();
    let l = Widened::new(lhdr, ldat, &fields, len, "left")?;
    let r = Widened::new(rhdr, rdat, &fields, len, "right")?;

    let rcap = if op == SetOp::Union { r.data.len() } else { 0 };
    let mut m = RecordMerge {
        fields,
        record_length: len as u64,
        rdat: Vec::with_capacity(l.data.len() + rcap),
        lmap: vec![RECORD_DROPPED; l.n],
        rmap: vec![RECORD_DROPPED; r.n],
    };
    let mut out = 0u64;
    let mut emit = |w: &Widened, k: usize, map: &mut [u64], rdat: &mut Vec<u8>| {
        map[k] = out;
        out += 1;
        rdat.extend_from_slice(w.get(k));
    };
    let (mut i, mut j) = (0, 0);
    while i < l.n || j < r.n {
        let c = if i < l.n && j < r.n {
            l.sorted(i).cmp(r.sorted(j))
        } else if i < l.n {
            Ordering::Less
        } else {
            Ordering::Greater
        };
        match c {
            Ordering::Less => {
                if op != SetOp::Intersect {
                    emit(&l, l.order[i], &mut m.lmap, &mut m.rdat);
                }
                i += 1;
            }
            Ordering::Greater => {
                if op == SetOp::Union {
                    emit(&r, r.order[j], &mut m.rmap, &mut m.rdat);
                }
                j += 1;
            }
            Ordering::Equal => {
                // identical records: the left copy stands for both, so the
                // right record (and its rows) is dropped whatever the operation
                if op != SetOp::Subtract {
                    emit(&l, l.order[i], &mut m.lmap, &mut m.rdat);
                }
                i += 1;
                j += 1;
            }
        }
    }
    Ok(m)
}

/// One side's records rewritten to the output fields, with their sorted order.
struct Widened {
    data: Vec<u8>,
    len: usize,
    n: usize,
    /// Record indices in ascending record order.
    order: Vec<usize>,
}

impl Widened {
    /// The records `data` of `hdr` rewritten to the output `fields` (`len`
    /// bytes each); a field the input lacks is a zero presence byte and value.
    fn new(
        hdr: &RecordHeader,
        data: &[u8],
        fields: &[FieldDescriptor],
        len: usize,
        side: &str,
    ) -> Result<Self> {
        let ilen = hdr.computed_record_length();
        if hdr.record_length != ilen as u64 {
            return Err(Error::format(format!(
                "the {side} record length {} disagrees with its fields ({ilen} bytes)",
                hdr.record_length
            )));
        }
        let n = usize::try_from(hdr.record_count)
            .ok()
            .filter(|n| n.checked_mul(ilen) == Some(data.len()))
            .ok_or_else(|| {
                Error::format(format!(
                    "the {side} record data has {} bytes, not {} records of {ilen}",
                    data.len(),
                    hdr.record_count
                ))
            })?;
        // (output offset, input offset, bytes) of every field the input has
        let mut moves = Vec::new();
        let mut ooff = 0;
        for f in fields {
            if let Some(ioff) = hdr.field_offset(f.htype) {
                // merged_record_fields guarantees this; a mismatch would read
                // past the input record or misplace its bytes
                let ilen = hdr.fields.iter().find(|g| g.htype == f.htype);
                if ilen.map(|g| g.length) != Some(f.length) {
                    return Err(Error::format(format!(
                        "the {side} {} field is not {} bytes long",
                        f.htype.name(),
                        f.length
                    )));
                }
                moves.push((ooff, ioff, f.stride()));
            }
            ooff += f.stride();
        }
        let mut out = vec![0u8; n * len];
        if ilen > 0 && len > 0 {
            for (src, dst) in data.chunks_exact(ilen).zip(out.chunks_exact_mut(len)) {
                for &(o, i, b) in &moves {
                    dst[o..o + b].copy_from_slice(&src[i..i + b]);
                }
            }
        }
        let mut w = Widened {
            data: out,
            len,
            n,
            order: (0..n).collect(),
        };
        // the identity when the records are already sorted, which they are
        // unless widening reordered the fields
        if !w.order.is_sorted_by_key(|&k| w.get(k)) {
            let mut order = std::mem::take(&mut w.order);
            order.sort_by(|&a, &b| w.get(a).cmp(w.get(b)));
            w.order = order;
        }
        Ok(w)
    }

    /// Record `k` in input order.
    fn get(&self, k: usize) -> &[u8] {
        &self.data[k * self.len..(k + 1) * self.len]
    }

    /// Record `i` in sorted order.
    fn sorted(&self, i: usize) -> &[u8] {
        self.get(self.order[i])
    }
}

/// A row that the merge does not emit (the same value as the TLSH index's
/// dropped-row marker).
pub const DROPPED: u32 = u32::MAX;

/// A record that the merge does not emit.
pub const RECORD_DROPPED: u64 = u64::MAX;

/// How [`merge_rows`] decides which rows to emit.
#[derive(Debug, Clone, Copy)]
pub enum RowMode<'a> {
    /// The rows are sets: equal rows, within a side or across the sides, are
    /// emitted once (the left copy for rows on both sides), subject to the
    /// operation.
    Set(SetOp),
    /// The rows belong to records and the operation has already been applied
    /// to the records: a row is emitted iff its record is. On ties left rows
    /// precede right rows.
    Records {
        left: RowOwners<'a>,
        right: RowOwners<'a>,
        /// Emit a row equal to the previously emitted row only once (for a
        /// hashsets-only output of a record-level operation).
        collapse_equal: bool,
    },
}

/// The records owning the rows of one side of a record-mode row merge.
#[derive(Debug, Clone, Copy)]
pub struct RowOwners<'a> {
    /// The record of each row: one little-endian `u64` per row, the layout of
    /// an `RIDX` chunk.
    pub ridx: &'a [u8],
    /// Each input record's output record, or [`RECORD_DROPPED`].
    pub recmap: &'a [u64],
}

/// The result of [`merge_rows`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RowMerge {
    /// Number of output rows.
    pub n: u64,
    /// Output row of each left row, or [`DROPPED`].
    pub lmap: Vec<u32>,
    /// Output row of each right row, or [`DROPPED`].
    pub rmap: Vec<u32>,
}

impl RowMerge {
    /// The output rows (an `HDAT` payload): every emitted input row of the
    /// merged `left` and `right` at its output position.
    pub fn gather_rows(&self, left: &[u8], right: &[u8], len: usize) -> Result<Vec<u8>> {
        let (l, r) = (
            Rows::new(left, len, "left")?,
            Rows::new(right, len, "right")?,
        );
        let mut out = vec![0u8; self.out_len(len)?];
        self.scatter(l.n, r.n, |from_left, i, k| {
            let src = if from_left { l.get(i) } else { r.get(i) };
            out[k * len..(k + 1) * len].copy_from_slice(src);
            Ok(())
        })?;
        Ok(out)
    }

    /// The output record index (an `RIDX` payload): for every output row, the
    /// output record of the record owning its input row.
    pub fn gather_ridx(&self, left: RowOwners<'_>, right: RowOwners<'_>) -> Result<Vec<u8>> {
        let lrecs = left.output_records(self.lmap.len(), "left")?;
        let rrecs = right.output_records(self.rmap.len(), "right")?;
        let mut out = vec![0u8; self.out_len(8)?];
        self.scatter(lrecs.len(), rrecs.len(), |from_left, i, k| {
            let rec = if from_left { lrecs[i] } else { rrecs[i] };
            if rec == RECORD_DROPPED {
                return Err(Error::input(format!(
                    "output row {k} comes from a dropped record"
                )));
            }
            out[k * 8..k * 8 + 8].copy_from_slice(&rec.to_le_bytes());
            Ok(())
        })?;
        Ok(out)
    }

    /// Bytes of `n` output rows of `len` bytes.
    fn out_len(&self, len: usize) -> Result<usize> {
        usize::try_from(self.n)
            .ok()
            .and_then(|n| n.checked_mul(len))
            .ok_or_else(|| Error::input("merged rows do not fit in memory"))
    }

    /// Calls `put(from_left, input row, output row)` for every emitted row, after
    /// checking that the sides have `ln` and `rn` rows.
    fn scatter(
        &self,
        ln: usize,
        rn: usize,
        mut put: impl FnMut(bool, usize, usize) -> Result<()>,
    ) -> Result<()> {
        if ln != self.lmap.len() || rn != self.rmap.len() {
            return Err(Error::input(format!(
                "the merge has {} left and {} right rows, not {ln} and {rn}",
                self.lmap.len(),
                self.rmap.len()
            )));
        }
        let sides = [(&self.lmap, true), (&self.rmap, false)];
        for (map, from_left) in sides {
            for (i, &k) in map.iter().enumerate() {
                if k == DROPPED {
                    continue;
                }
                if u64::from(k) >= self.n {
                    return Err(Error::input(format!(
                        "output row {k} is past the {} merged rows",
                        self.n
                    )));
                }
                put(from_left, i, k as usize)?;
            }
        }
        Ok(())
    }
}

/// Merges two sorted runs of `len`-byte rows (`left` and `right` hold the
/// rows back to back). Output row `k` is the input row mapped to `k`.
pub fn merge_rows(left: &[u8], right: &[u8], len: usize, mode: RowMode<'_>) -> Result<RowMerge> {
    let (l, r) = (
        Rows::new(left, len, "left")?,
        Rows::new(right, len, "right")?,
    );
    let mut m = RowMerge {
        n: 0,
        lmap: vec![DROPPED; l.n],
        rmap: vec![DROPPED; r.n],
    };
    match mode {
        RowMode::Set(op) => merge_sets(op, l, r, &mut m)?,
        RowMode::Records {
            left,
            right,
            collapse_equal,
        } => {
            let lkept = left.kept(l.n, "left")?;
            let rkept = right.kept(r.n, "right")?;
            merge_owned(l, &lkept, r, &rkept, collapse_equal, &mut m)?;
        }
    }
    Ok(m)
}

impl RowOwners<'_> {
    /// Whether each of the side's `n` rows belongs to an emitted record.
    fn kept(&self, n: usize, side: &str) -> Result<Vec<bool>> {
        let recs = self.output_records(n, side)?;
        Ok(recs.into_iter().map(|r| r != RECORD_DROPPED).collect())
    }

    /// The output record of each of the side's `n` rows, or [`RECORD_DROPPED`].
    fn output_records(&self, n: usize, side: &str) -> Result<Vec<u64>> {
        let (entries, tail) = self.ridx.as_chunks::<8>();
        if entries.len() != n || !tail.is_empty() {
            return Err(Error::input(format!(
                "the {side} record index has {} bytes for {n} rows",
                self.ridx.len()
            )));
        }
        entries
            .iter()
            .enumerate()
            .map(|(k, &b)| {
                let rec = u64::from_le_bytes(b);
                usize::try_from(rec)
                    .ok()
                    .and_then(|rec| self.recmap.get(rec).copied())
                    .ok_or_else(|| {
                        Error::format(format!(
                            "{side} row {k} names record {rec}, but there are {} records",
                            self.recmap.len()
                        ))
                    })
            })
            .collect()
    }
}

/// Fixed-length rows stored back to back.
#[derive(Clone, Copy)]
struct Rows<'a> {
    data: &'a [u8],
    len: usize,
    n: usize,
}

impl<'a> Rows<'a> {
    fn new(data: &'a [u8], len: usize, side: &str) -> Result<Self> {
        if len == 0 {
            return Err(Error::input("zero-length rows"));
        }
        if !data.len().is_multiple_of(len) {
            return Err(Error::input(format!(
                "the {side} rows have {} bytes, not a multiple of the row length {len}",
                data.len()
            )));
        }
        Ok(Rows {
            data,
            len,
            n: data.len() / len,
        })
    }

    fn get(&self, i: usize) -> &'a [u8] {
        &self.data[i * self.len..(i + 1) * self.len]
    }

    /// The index after the run of rows equal to row `k`.
    fn skip_run(&self, k: usize) -> usize {
        let v = self.get(k);
        let mut k = k + 1;
        while k < self.n && self.get(k) == v {
            k += 1;
        }
        k
    }
}

/// Order of the next left row against the next right row, an exhausted side
/// sorting last.
fn next_order(l: &Rows<'_>, i: usize, r: &Rows<'_>, j: usize) -> Ordering {
    if i < l.n && j < r.n {
        l.get(i).cmp(r.get(j))
    } else if i < l.n {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// An input row of one side.
#[derive(Clone, Copy)]
enum Side {
    Left(usize),
    Right(usize),
}

/// Maps `row` to the next output row.
fn emit(m: &mut RowMerge, row: Side) -> Result<()> {
    // C++ refuses once the count reaches MERGE_DROPPED: the last row index
    // is DROPPED - 2
    let k = u32::try_from(m.n)
        .ok()
        .filter(|&k| k < DROPPED - 1)
        .ok_or_else(|| Error::input("too many rows in merged hashset"))?;
    match row {
        Side::Left(i) => m.lmap[i] = k,
        Side::Right(j) => m.rmap[j] = k,
    }
    m.n += 1;
    Ok(())
}

fn merge_owned(
    l: Rows<'_>,
    lkept: &[bool],
    r: Rows<'_>,
    rkept: &[bool],
    collapse_equal: bool,
    m: &mut RowMerge,
) -> Result<()> {
    let (mut i, mut j) = (0, 0);
    let mut last: Option<&[u8]> = None; // the previous emitted row
    loop {
        while i < l.n && !lkept[i] {
            i += 1;
        }
        while j < r.n && !rkept[j] {
            j += 1;
        }
        if i == l.n && j == r.n {
            return Ok(());
        }
        // ties go left
        let (row, next) = if next_order(&l, i, &r, j) != Ordering::Greater {
            i += 1;
            (l.get(i - 1), Side::Left(i - 1))
        } else {
            j += 1;
            (r.get(j - 1), Side::Right(j - 1))
        };
        if collapse_equal && last == Some(row) {
            continue;
        }
        last = Some(row);
        emit(m, next)?;
    }
}

fn merge_sets(op: SetOp, l: Rows<'_>, r: Rows<'_>, m: &mut RowMerge) -> Result<()> {
    let emit_left_only = op != SetOp::Intersect;
    let emit_right_only = op == SetOp::Union;
    let emit_both = op != SetOp::Subtract;
    let (mut i, mut j) = (0, 0);
    while i < l.n || j < r.n {
        match next_order(&l, i, &r, j) {
            Ordering::Less => {
                if emit_left_only {
                    emit(m, Side::Left(i))?;
                }
                i = l.skip_run(i);
            }
            Ordering::Greater => {
                if emit_right_only {
                    emit(m, Side::Right(j))?;
                }
                j = r.skip_run(j);
            }
            Ordering::Equal => {
                if emit_both {
                    emit(m, Side::Left(i))?;
                }
                i = l.skip_run(i);
                j = r.skip_run(j);
            }
        }
    }
    Ok(())
}
