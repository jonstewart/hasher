//! The document model ([`Doc`]) and its format oracle ([`Expected`]).
//!
//! [`Doc::expected`] derives the decoded file from the format rules with
//! plain `Vec` sorting and dedup, independently of `hset::builder`.

use std::collections::BTreeSet;

use hset::builder::format_value;
use hset::format::{FieldDescriptor, Hint, HsetFile, hint_tag_block, hint_tag_hull};
use hset::lookup::resolve_bits;
use hset::merge::MergeOptions;
use hset::{BitsPolicy, BuildOptions, Builder, HashType, HintSpec, SetOp};

use crate::oracle::set_op_model;

/// Every type that can be stored in a hash set: `HashType::ALL` minus `Fuzzy`,
/// and minus `Tlsh`, whose values must be canonical TLSH digests and whose
/// sections carry a cell index rather than a block or hull hint.
pub const STORABLE_TYPES: [HashType; 14] = [
    HashType::Md5,
    HashType::Sha1,
    HashType::Sha2_224,
    HashType::Sha2_256,
    HashType::Sha2_384,
    HashType::Sha2_512,
    HashType::Sha3_224,
    HashType::Sha3_256,
    HashType::Sha3_384,
    HashType::Sha3_512,
    HashType::Blake3,
    HashType::Entropy,
    HashType::Size,
    HashType::QuickMd5,
];

/// One field of a document's records.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub htype: HashType,
    pub name: String,
}

impl Field {
    /// The field with the type's canonical name.
    pub fn canonical(htype: HashType) -> Field {
        Field {
            htype,
            name: htype.field_name().to_string(),
        }
    }

    /// Value length in bytes. Panics for a non-storable type.
    pub fn length(&self) -> usize {
        self.htype.length().unwrap()
    }

    pub fn descriptor(&self) -> FieldDescriptor {
        FieldDescriptor {
            htype: self.htype,
            name: self.name.clone(),
            length: self.length() as u64,
        }
    }
}

/// Build options of a document, with the timestamp always fixed.
#[derive(Debug, Clone, PartialEq)]
pub struct Opts {
    pub name: String,
    pub desc: String,
    pub timestamp: String,
    pub with_records: bool,
    pub with_hashsets: bool,
    pub hint: HintSpec,
    pub bits_policy: BitsPolicy,
}

impl Opts {
    /// Records and hash sets with automatically sized hull hints.
    pub fn default_for_tests() -> Opts {
        Opts {
            name: "t".to_string(),
            desc: "t".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            with_records: true,
            with_hashsets: true,
            hint: HintSpec::Hull { bits: u8::MAX },
            bits_policy: BitsPolicy::default(),
        }
    }

    pub fn build_options(&self) -> BuildOptions {
        BuildOptions::new(self.name.clone(), self.desc.clone())
            .timestamp(self.timestamp.clone())
            .records(self.with_records)
            .hashsets(self.with_hashsets)
            .hint(self.hint)
            .bits_policy(self.bits_policy)
    }
}

/// An input document: fields, records in input order (one optional value per
/// field), and build options.
#[derive(Debug, Clone, PartialEq)]
pub struct Doc {
    pub fields: Vec<Field>,
    pub records: Vec<Vec<Option<Vec<u8>>>>,
    pub opts: Opts,
}

/// One record laid out per the format: per field a presence byte, then the
/// value or zeros when absent.
fn layout_row(fields: &[Field], record: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut row = Vec::new();
    for (f, v) in fields.iter().zip(record) {
        match v {
            Some(v) => {
                row.push(1);
                row.extend_from_slice(v);
            }
            None => row.resize(row.len() + 1 + f.length(), 0),
        }
    }
    row
}

impl Doc {
    pub fn descriptors(&self) -> Vec<FieldDescriptor> {
        self.fields.iter().map(Field::descriptor).collect()
    }

    pub fn record_length(&self) -> usize {
        self.fields.iter().map(|f| 1 + f.length()).sum()
    }

    /// A builder holding every record, in input order.
    pub fn builder(&self) -> hset::Result<Builder> {
        let mut b = Builder::with_fields(self.descriptors());
        for r in &self.records {
            let values: Vec<Option<&[u8]>> = r.iter().map(|v| v.as_deref()).collect();
            b.add_record(&values)?;
        }
        Ok(b)
    }

    pub fn build(&self) -> hset::Result<Vec<u8>> {
        self.builder()?.build(&self.opts.build_options())
    }

    /// Sorted, deduplicated record rows.
    fn sorted_records(&self) -> Vec<Vec<u8>> {
        let mut rows: Vec<Vec<u8>> = self
            .records
            .iter()
            .map(|r| layout_row(&self.fields, r))
            .collect();
        rows.sort();
        rows.dedup();
        rows
    }

    /// The decoded file `build` must produce, derived from the format rules.
    pub fn expected(&self) -> Expected {
        let opts = &self.opts;
        let rows = self.sorted_records();
        let mut sections = Vec::new();
        if opts.with_hashsets {
            let mut off = 0;
            for f in &self.fields {
                let hlen = f.length();
                let mut present: Vec<(Vec<u8>, u64)> = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r[off] == 1)
                    .map(|(i, r)| (r[off + 1..off + 1 + hlen].to_vec(), i as u64))
                    .collect();
                // By hash, equal hashes by descending record index (the
                // C++ encoder's HashRecordProxy::cmp, record_iterator.h).
                present.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
                if !opts.with_records {
                    present.dedup_by(|a, b| a.0 == b.0);
                }
                let hint_tag = hint_tag(f.htype, present.len(), hlen, opts.hint, &opts.bits_policy);
                sections.push(ExpectedSection {
                    htype: f.htype,
                    name: f.name.clone(),
                    hash_length: hlen,
                    ridx: opts
                        .with_records
                        .then(|| present.iter().map(|p| p.1).collect()),
                    hashes: present.into_iter().map(|p| p.0).collect(),
                    hint_tag,
                });
                off += 1 + hlen;
            }
        }
        Expected {
            name: opts.name.clone(),
            desc: opts.desc.clone(),
            time: opts.timestamp.clone(),
            fields: self.descriptors(),
            record_length: self.record_length(),
            records: opts.with_records.then_some(rows),
            sections,
        }
    }

    /// The distinct records in the order the built file stores them (sorted
    /// by their layout row): record `k` of the file is element `k`.
    fn distinct_records(&self) -> Vec<&[Option<Vec<u8>>]> {
        let mut recs: Vec<_> = self
            .records
            .iter()
            .map(|r| (layout_row(&self.fields, r), r.as_slice()))
            .collect();
        recs.sort();
        recs.dedup_by(|x, y| x.0 == y.0);
        recs.into_iter().map(|(_, r)| r).collect()
    }

    /// Record `r`'s value of the field of type `t`, if the document has the
    /// field and the record a value for it.
    fn value_of<'r>(&self, r: &'r [Option<Vec<u8>>], t: HashType) -> Option<&'r Vec<u8>> {
        let i = self.fields.iter().position(|f| f.htype == t)?;
        r[i].as_ref()
    }

    /// The distinct present values of the field of type `t` (none when the
    /// document lacks the field): the rows of its built section as a set.
    fn values(&self, t: HashType) -> BTreeSet<Vec<u8>> {
        self.records
            .iter()
            .filter_map(|r| self.value_of(r, t).cloned())
            .collect()
    }

    /// The records as `hset make` text: one line per record in input order,
    /// columns separated by a space, an absent value as an empty column.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for r in &self.records {
            let cols: Vec<String> = self
                .fields
                .iter()
                .zip(r)
                .map(|(f, v)| {
                    v.as_ref()
                        .map_or_else(String::new, |v| format_value(&f.descriptor(), v))
                })
                .collect();
            out.push_str(&cols.join(" "));
            out.push('\n');
        }
        out
    }

    /// Field names joined by `,`, for `hset make -t`.
    pub fn type_list(&self) -> String {
        self.fields
            .iter()
            .map(|f| f.htype.field_name())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The tag of the hint a section of `n` rows of type `htype` gets under
/// `hint` and `policy`: none for a non-digest type.
fn hint_tag(
    htype: HashType,
    n: usize,
    hlen: usize,
    hint: HintSpec,
    policy: &BitsPolicy,
) -> Option<u16> {
    if !htype.is_digest() {
        return None;
    }
    match resolve_bits(hint, n, hlen, policy) {
        HintSpec::None => None,
        HintSpec::Block { bits } => Some(hint_tag_block(bits)),
        HintSpec::Hull { bits } => Some(hint_tag_hull(bits)),
    }
}

/// `merge`'s error when exactly one input has hash sections (a substring of
/// its message, as are the other refusals).
pub const REFUSE_RECORDS_ONLY: &str =
    "cannot merge a records-only hashset with one that has hash sections";
/// `merge`'s error when the write flags leave nothing to write.
pub const REFUSE_NOTHING_TO_WRITE: &str = "neither records nor hash sections are to be written";

impl Opts {
    /// The merge options of an output built with these options: the same
    /// metadata, hint and bits policy, `with_records` and `with_hashsets`
    /// as the write flags, and the default TLSH index policy.
    pub fn merge_options(&self) -> MergeOptions {
        let mut o = MergeOptions::new(self.name.clone(), self.desc.clone());
        o.timestamp = Some(self.timestamp.clone());
        o.write_records = self.with_records;
        o.write_hashsets = self.with_hashsets;
        o.hint = self.hint;
        o.bits_policy = self.bits_policy;
        o
    }
}

/// The decoded file `hset::merge::merge(op, a, b, &out.merge_options())`
/// must write, from the C++ merge semantics (HASHSET_FORMAT "Set
/// operations"), or the refusal it must fail with
/// ([`REFUSE_RECORDS_ONLY`], [`REFUSE_NOTHING_TO_WRITE`]).
///
/// * Exactly one input with hash sections is refused.
/// * **Both inputs have records**: the output fields are `a`'s, then
///   `b`'s of the types `a` lacks; each side's distinct records, widened to
///   them (an absent field is a zero presence byte and zero value), are
///   combined as sets ([`set_op_model`]) and sorted. A section per output
///   field holds the value of every output record that has one; on equal
///   values `a`'s rows come first, each side's in its own file's order
///   (descending input record), and `RIDX` names the output record. An
///   output without records (`out.with_records` off) has each value once.
/// * **Otherwise** the output has no records and a section per type of
///   either input (`a`'s first, named by the first side that has it),
///   holding the set operation on the two sides' distinct values (a side
///   without the type contributes nothing).
/// * Digest sections get `out`'s hint as the builder sizes it.
///
/// Inputs that have neither records nor sections in common, which C++
/// also refuses, cannot be expressed: a [`Doc`] always has records or
/// sections and so falls under the first rule.
pub fn set_op_expected(op: SetOp, a: &Doc, b: &Doc, out: &Opts) -> Result<Expected, &'static str> {
    if a.opts.with_hashsets != b.opts.with_hashsets {
        return Err(REFUSE_RECORDS_ONLY);
    }
    let record_merge = a.opts.with_records && b.opts.with_records;
    let with_records = record_merge && out.with_records;
    let with_hashsets = a.opts.with_hashsets && out.with_hashsets;
    if !with_records && !with_hashsets {
        return Err(REFUSE_NOTHING_TO_WRITE);
    }
    let mut fields: Vec<Field> = a.fields.clone();
    for f in &b.fields {
        if !fields.iter().any(|x| x.htype == f.htype) {
            fields.push(f.clone());
        }
    }
    let section = |f: &Field, hashes: Vec<Vec<u8>>, ridx: Option<Vec<u64>>| ExpectedSection {
        htype: f.htype,
        name: f.name.clone(),
        hash_length: f.length(),
        hint_tag: hint_tag(
            f.htype,
            hashes.len(),
            f.length(),
            out.hint,
            &out.bits_policy,
        ),
        hashes,
        ridx,
    };
    let mut expected = Expected {
        name: out.name.clone(),
        desc: out.desc.clone(),
        time: out.timestamp.clone(),
        fields: fields.iter().map(Field::descriptor).collect(),
        record_length: fields.iter().map(|f| 1 + f.length()).sum(),
        records: None,
        sections: Vec::new(),
    };
    if !record_merge {
        if with_hashsets {
            for f in &fields {
                let rows = set_op_model(op, &a.values(f.htype), &b.values(f.htype));
                expected
                    .sections
                    .push(section(f, rows.into_iter().collect(), None));
            }
        }
        return Ok(expected);
    }

    // every distinct record of a side, in its file's order, widened
    let widen = |d: &Doc, r: &[Option<Vec<u8>>]| -> Vec<u8> {
        let values: Vec<Option<Vec<u8>>> = fields
            .iter()
            .map(|f| d.value_of(r, f.htype).cloned())
            .collect();
        layout_row(&fields, &values)
    };
    let (ar, br) = (a.distinct_records(), b.distinct_records());
    let aw: Vec<Vec<u8>> = ar.iter().map(|r| widen(a, r)).collect();
    let bw: Vec<Vec<u8>> = br.iter().map(|r| widen(b, r)).collect();
    let (aset, bset): (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>) =
        (aw.iter().cloned().collect(), bw.iter().cloned().collect());
    let out_records: Vec<Vec<u8>> = set_op_model(op, &aset, &bset).into_iter().collect();
    let out_index = |w: &Vec<u8>| out_records.binary_search(w).ok().map(|k| k as u64);
    // a record identical on both sides is emitted as the left copy
    let emitted = |side: usize, k: usize| -> Option<u64> {
        match side {
            0 => out_index(&aw[k]),
            _ if op == SetOp::Union && !aset.contains(&bw[k]) => out_index(&bw[k]),
            _ => None,
        }
    };
    if with_hashsets {
        for f in &fields {
            // (value, side, descending input record, output record)
            let mut rows: Vec<(Vec<u8>, usize, std::cmp::Reverse<usize>, u64)> = Vec::new();
            for (side, d, recs) in [(0, a, &ar), (1, b, &br)] {
                for (k, r) in recs.iter().enumerate() {
                    if let (Some(v), Some(o)) = (d.value_of(r, f.htype), emitted(side, k)) {
                        rows.push((v.clone(), side, std::cmp::Reverse(k), o));
                    }
                }
            }
            rows.sort();
            if !with_records {
                rows.dedup_by(|x, y| x.0 == y.0);
            }
            let ridx = with_records.then(|| rows.iter().map(|r| r.3).collect());
            expected
                .sections
                .push(section(f, rows.into_iter().map(|r| r.0).collect(), ridx));
        }
    }
    expected.records = with_records.then_some(out_records);
    Ok(expected)
}

/// The decoded contents a built document must have.
#[derive(Debug, Clone, PartialEq)]
pub struct Expected {
    pub name: String,
    pub desc: String,
    pub time: String,
    pub fields: Vec<FieldDescriptor>,
    pub record_length: usize,
    /// Sorted, deduplicated rows; `None` when the file has no records.
    pub records: Option<Vec<Vec<u8>>>,
    /// One per field, or none when the file has no hash sets.
    pub sections: Vec<ExpectedSection>,
}

/// One expected hash section.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedSection {
    pub htype: HashType,
    pub name: String,
    pub hash_length: usize,
    pub hashes: Vec<Vec<u8>>,
    pub ridx: Option<Vec<u64>>,
    pub hint_tag: Option<u16>,
}

impl Expected {
    /// Panics with a message naming the first mismatch.
    pub fn assert_matches(&self, file: &HsetFile<'_>) {
        assert_eq!(file.fhdr.version, 2, "fhdr.version");
        assert_eq!(file.fhdr.name, self.name, "fhdr.name");
        assert_eq!(file.fhdr.desc, self.desc, "fhdr.desc");
        assert_eq!(file.fhdr.time, self.time, "fhdr.time");
        assert_eq!(file.rhdr.is_some(), self.records.is_some(), "rhdr presence");
        if let (Some(rhdr), Some(records)) = (&file.rhdr, &self.records) {
            assert_eq!(rhdr.fields, self.fields, "rhdr.fields");
            assert_eq!(
                rhdr.record_length, self.record_length as u64,
                "rhdr.record_length"
            );
            assert_eq!(rhdr.record_count, records.len() as u64, "rhdr.record_count");
            let rdat = file.rdat.expect("rdat missing");
            assert_eq!(rdat, records.concat().as_slice(), "rdat rows");
        }
        assert_eq!(file.sections.len(), self.sections.len(), "sections.len()");
        for (i, (s, e)) in file.sections.iter().zip(&self.sections).enumerate() {
            let h = &s.header;
            assert_eq!(h.htype, e.htype, "section {i} htype");
            assert_eq!(h.name, e.name, "section {i} name");
            assert_eq!(
                h.hash_length, e.hash_length as u64,
                "section {i} hash_length"
            );
            assert_eq!(
                h.hash_count,
                e.hashes.len() as u64,
                "section {i} hash_count"
            );
            assert_eq!(s.data, e.hashes.concat().as_slice(), "section {i} data");
            let ridx: Option<Vec<u64>> = s.ridx.map(|r| {
                let (words, rest) = r.as_chunks::<8>();
                assert!(rest.is_empty(), "section {i} ridx is not whole u64s");
                words.iter().map(|w| u64::from_le_bytes(*w)).collect()
            });
            assert_eq!(ridx, e.ridx, "section {i} ridx");
            assert!(
                !matches!(s.hint, Some(Hint::Unknown { .. })),
                "section {i} has an unknown hint {:?}",
                s.hint.map(|h| h.tag())
            );
            assert_eq!(s.hint.map(|h| h.tag()), e.hint_tag, "section {i} hint tag");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hset::format::decode;

    const MD5: [u8; 16] = [0x11; 16];

    fn size(v: u64) -> Option<Vec<u8>> {
        Some(v.to_le_bytes().to_vec())
    }

    /// Fields md5 and sizes; r3 duplicates r0 and r4 is all absent.
    pub(crate) fn two_field_doc() -> Doc {
        Doc {
            fields: vec![
                Field::canonical(HashType::Md5),
                Field::canonical(HashType::Size),
            ],
            records: vec![
                vec![Some(MD5.to_vec()), size(10)],
                vec![Some(MD5.to_vec()), size(20)],
                vec![None, size(7)],
                vec![Some(MD5.to_vec()), size(10)],
                vec![None, None],
            ],
            opts: Opts::default_for_tests(),
        }
    }

    fn row(md5: Option<[u8; 16]>, sz: Option<u64>) -> Vec<u8> {
        let mut r = Vec::new();
        match md5 {
            Some(m) => {
                r.push(1);
                r.extend_from_slice(&m);
            }
            None => r.extend_from_slice(&[0; 17]),
        }
        match sz {
            Some(s) => {
                r.push(1);
                r.extend_from_slice(&s.to_le_bytes());
            }
            None => r.extend_from_slice(&[0; 9]),
        }
        r
    }

    fn le(v: u64) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    #[test]
    fn expected_dedups_and_sorts_records() {
        let e = two_field_doc().expected();
        assert_eq!(e.record_length, 26);
        assert_eq!(
            e.records,
            Some(vec![
                row(None, None),
                row(None, Some(7)),
                row(Some(MD5), Some(10)),
                row(Some(MD5), Some(20)),
            ])
        );
    }

    #[test]
    fn expected_hash_section_with_records_keeps_duplicates() {
        let e = two_field_doc().expected();
        assert_eq!(e.sections.len(), 2);
        let md5 = &e.sections[0];
        assert_eq!(md5.htype, HashType::Md5);
        assert_eq!(md5.name, "md5");
        assert_eq!(md5.hash_length, 16);
        assert_eq!(md5.hashes, vec![MD5.to_vec(), MD5.to_vec()]);
        // Equal hashes list their records in descending order.
        assert_eq!(md5.ridx, Some(vec![3, 2]));
        let sizes = &e.sections[1];
        assert_eq!(sizes.htype, HashType::Size);
        assert_eq!(sizes.name, "sizes");
        assert_eq!(sizes.hash_length, 8);
        assert_eq!(sizes.hashes, vec![le(7), le(10), le(20)]);
        assert_eq!(sizes.ridx, Some(vec![1, 2, 3]));
        assert_eq!(sizes.hint_tag, None);
    }

    #[test]
    fn expected_hash_section_without_records_dedups() {
        let mut doc = two_field_doc();
        doc.opts.with_records = false;
        let e = doc.expected();
        assert_eq!(e.records, None);
        assert_eq!(e.sections[0].hashes, vec![MD5.to_vec()]);
        assert_eq!(e.sections[0].ridx, None);
        assert_eq!(e.sections[1].ridx, None);
    }

    #[test]
    fn expected_hint_tag_follows_resolve_bits() {
        let tag = |hint: HintSpec| {
            let mut doc = two_field_doc();
            doc.opts.hint = hint;
            doc.expected().sections[0].hint_tag
        };
        assert_eq!(tag(HintSpec::Hull { bits: 3 }), Some(0x6803));
        assert_eq!(tag(HintSpec::Block { bits: 8 }), Some(0x6208));
        assert_eq!(tag(HintSpec::None), None);
        assert_eq!(
            tag(HintSpec::Hull { bits: u8::MAX }),
            Some(hint_tag_hull(BitsPolicy::default().choose(2, 16, 12)))
        );
    }

    #[test]
    fn all_absent_record_is_a_row() {
        let doc = two_field_doc();
        let bytes = doc.build().unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.record_count(), 4);
        assert!(f.record(0).unwrap().iter().all(|&b| b == 0));
        let sizes = &f.sections[f.section_for(HashType::Size).unwrap()];
        assert_eq!(sizes.len(), 3);
        assert_eq!(
            (0..3).map(|i| sizes.record_index(i)).collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)]
        );
        let md5 = &f.sections[f.section_for(HashType::Md5).unwrap()];
        assert_eq!(md5.len(), 2);
        // Equal hashes list their records in descending order.
        assert_eq!(md5.record_index(0), Some(3));
        assert_eq!(md5.record_index(1), Some(2));
    }

    #[test]
    fn empty_doc_builds() {
        let mut doc = two_field_doc();
        doc.records = vec![];
        let bytes = doc.build().unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.record_count(), 0);
        assert_eq!(f.sections.len(), 2);
        assert!(f.sections.iter().all(|s| s.is_empty()));
        let md5 = &f.sections[f.section_for(HashType::Md5).unwrap()];
        assert!(md5.hint.is_some());
        doc.expected().assert_matches(&f);
    }

    #[test]
    fn build_matches_expected_on_the_sample() {
        for with_records in [true, false] {
            let mut doc = two_field_doc();
            doc.opts.with_records = with_records;
            let bytes = doc.build().unwrap();
            doc.expected().assert_matches(&decode(&bytes).unwrap());
        }
    }

    #[test]
    fn to_text_renders_absent_as_empty() {
        let doc = two_field_doc();
        let text = doc.to_text();
        let lines: Vec<&str> = text.split_terminator('\n').collect();
        assert!(text.ends_with('\n'));
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "11111111111111111111111111111111 10");
        assert_eq!(lines[2], " 7");
        assert_eq!(lines[4], " ");
        assert_eq!(doc.type_list(), "md5,sizes");
    }

    // set operations: hand-derived expectations of the merge model

    const M: [u8; 16] = [0x22; 16];
    const X: [u8; 16] = [0x01; 16];
    const Y: [u8; 16] = [0x02; 16];
    const SHA: [u8; 20] = [0x33; 20];

    fn doc_of(fields: &[HashType], records: Vec<Vec<Option<Vec<u8>>>>) -> Doc {
        Doc {
            fields: fields.iter().map(|&t| Field::canonical(t)).collect(),
            records,
            opts: Opts::default_for_tests(),
        }
    }

    fn out_opts(with_records: bool, with_hashsets: bool) -> Opts {
        Opts {
            name: "out".to_string(),
            with_records,
            with_hashsets,
            ..Opts::default_for_tests()
        }
    }

    type SectionRows = (HashType, Vec<Vec<u8>>, Option<Vec<u64>>);

    fn hashes_and_ridx(e: &Expected) -> Vec<SectionRows> {
        e.sections
            .iter()
            .map(|s| (s.htype, s.hashes.clone(), s.ridx.clone()))
            .collect()
    }

    #[test]
    fn set_op_model_widens_records_to_the_left_fields_then_the_right_extras() {
        let a = doc_of(
            &[HashType::Md5],
            vec![vec![Some(Y.to_vec())], vec![Some(X.to_vec())]],
        );
        let b = doc_of(&[HashType::Size], vec![vec![size(5)]]);
        let e = set_op_expected(SetOp::Union, &a, &b, &out_opts(true, true)).unwrap();
        assert_eq!(e.name, "out");
        let names: Vec<&str> = e.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["md5", "sizes"]);
        assert_eq!(e.record_length, 17 + 9);
        // an absent field is a zero presence byte, so b's record sorts first
        assert_eq!(
            e.records,
            Some(vec![
                row(None, Some(5)),
                row(Some(X), None),
                row(Some(Y), None)
            ])
        );
        assert_eq!(
            hashes_and_ridx(&e),
            [
                (
                    HashType::Md5,
                    vec![X.to_vec(), Y.to_vec()],
                    Some(vec![1, 2])
                ),
                (HashType::Size, vec![le(5)], Some(vec![0])),
            ]
        );
    }

    /// a: (M,20) (M,10); b in the other field order: (30,M) and (10,M),
    /// the same record as one of a's.
    fn tie_pair() -> (Doc, Doc) {
        let a = doc_of(
            &[HashType::Md5, HashType::Size],
            vec![
                vec![Some(M.to_vec()), size(20)],
                vec![Some(M.to_vec()), size(10)],
            ],
        );
        let b = doc_of(
            &[HashType::Size, HashType::Md5],
            vec![
                vec![size(30), Some(M.to_vec())],
                vec![size(10), Some(M.to_vec())],
            ],
        );
        (a, b)
    }

    #[test]
    fn set_op_model_orders_equal_rows_left_first_each_side_by_descending_record() {
        let (a, b) = tie_pair();
        let e = set_op_expected(SetOp::Union, &a, &b, &out_opts(true, true)).unwrap();
        assert_eq!(
            e.records,
            Some(vec![
                row(Some(M), Some(10)),
                row(Some(M), Some(20)),
                row(Some(M), Some(30)),
            ])
        );
        // left rows: records 1 then 0 (descending); then right's (M,30),
        // record 2; right's (M,10) is the left copy's and is dropped
        assert_eq!(
            hashes_and_ridx(&e),
            [
                (HashType::Md5, vec![M.to_vec(); 3], Some(vec![1, 0, 2])),
                (
                    HashType::Size,
                    vec![le(10), le(20), le(30)],
                    Some(vec![0, 1, 2])
                ),
            ]
        );
        let ho = set_op_expected(SetOp::Union, &a, &b, &out_opts(false, true)).unwrap();
        assert_eq!(ho.records, None);
        assert_eq!(
            hashes_and_ridx(&ho),
            [
                (HashType::Md5, vec![M.to_vec()], None),
                (HashType::Size, vec![le(10), le(20), le(30)], None),
            ]
        );
        let i = set_op_expected(SetOp::Intersect, &a, &b, &out_opts(true, true)).unwrap();
        assert_eq!(i.records, Some(vec![row(Some(M), Some(10))]));
        assert_eq!(i.sections[0].ridx, Some(vec![0]));
        let d = set_op_expected(SetOp::Subtract, &a, &b, &out_opts(true, true)).unwrap();
        assert_eq!(d.records, Some(vec![row(Some(M), Some(20))]));
        let d = set_op_expected(SetOp::Subtract, &b, &a, &out_opts(true, true)).unwrap();
        assert_eq!(d.records.as_ref().map(Vec::len), Some(1));
        assert_eq!(hashes_and_ridx(&d)[0].1, vec![le(30)], "b's fields lead");
    }

    #[test]
    fn set_op_model_without_records_on_both_sides_merges_section_values_as_sets() {
        let mut a = doc_of(
            &[HashType::Md5],
            vec![vec![Some(X.to_vec())], vec![Some(Y.to_vec())]],
        );
        a.opts.with_records = false;
        a.fields[0].name = "left md5".to_string();
        let b = doc_of(
            &[HashType::Sha1, HashType::Md5],
            vec![
                vec![Some(SHA.to_vec()), Some(X.to_vec())],
                vec![None, Some(X.to_vec())],
            ],
        );
        let u = set_op_expected(SetOp::Union, &a, &b, &out_opts(true, true)).unwrap();
        assert_eq!(u.records, None, "records only when both sides have them");
        let names: Vec<&str> = u.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["left md5", "sha1"]);
        assert_eq!(
            hashes_and_ridx(&u),
            [
                (HashType::Md5, vec![X.to_vec(), Y.to_vec()], None),
                (HashType::Sha1, vec![SHA.to_vec()], None),
            ]
        );
        let i = set_op_expected(SetOp::Intersect, &a, &b, &out_opts(true, true)).unwrap();
        assert_eq!(
            hashes_and_ridx(&i),
            [
                (HashType::Md5, vec![X.to_vec()], None),
                (HashType::Sha1, vec![], None)
            ]
        );
        let d = set_op_expected(SetOp::Subtract, &b, &a, &out_opts(true, true)).unwrap();
        assert_eq!(
            hashes_and_ridx(&d),
            [
                (HashType::Sha1, vec![SHA.to_vec()], None),
                (HashType::Md5, vec![], None)
            ]
        );
        assert_eq!(
            set_op_expected(SetOp::Union, &a, &b, &out_opts(true, false)),
            Err(REFUSE_NOTHING_TO_WRITE)
        );
    }

    #[test]
    fn set_op_model_refusals_and_records_only_outputs() {
        let (a, b) = tie_pair();
        let mut ro = a.clone();
        ro.opts.with_hashsets = false;
        assert_eq!(
            set_op_expected(SetOp::Union, &ro, &b, &out_opts(true, true)),
            Err(REFUSE_RECORDS_ONLY)
        );
        assert_eq!(
            set_op_expected(SetOp::Union, &a, &ro, &out_opts(true, true)),
            Err(REFUSE_RECORDS_ONLY)
        );
        assert_eq!(
            set_op_expected(SetOp::Union, &a, &b, &out_opts(false, false)),
            Err(REFUSE_NOTHING_TO_WRITE)
        );
        let mut ro2 = b.clone();
        ro2.opts.with_hashsets = false;
        assert_eq!(
            set_op_expected(SetOp::Union, &ro, &ro2, &out_opts(false, true)),
            Err(REFUSE_NOTHING_TO_WRITE)
        );
        let e = set_op_expected(SetOp::Union, &ro, &ro2, &out_opts(true, true)).unwrap();
        assert_eq!(e.records.as_ref().map(Vec::len), Some(3));
        assert!(e.sections.is_empty());
    }
}
