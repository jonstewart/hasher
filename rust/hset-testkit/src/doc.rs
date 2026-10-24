//! The document model ([`Doc`]) and its format oracle ([`Expected`]).
//!
//! [`Doc::expected`] derives the decoded file from the format rules with
//! plain `Vec` sorting and dedup, independently of `hset::builder`.

use std::collections::BTreeSet;

use hset::builder::format_value;
use hset::format::{FieldDescriptor, Hint, HsetFile, hint_tag_block, hint_tag_hull};
use hset::lookup::resolve_bits;
use hset::{BitsPolicy, BuildOptions, Builder, HashType, HintSpec};

/// Every type that can be stored in a hash set: `HashType::ALL` minus `Fuzzy`.
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
                present.sort();
                if !opts.with_records {
                    present.dedup_by(|a, b| a.0 == b.0);
                }
                let hint_tag = if f.htype.is_digest() {
                    match resolve_bits(opts.hint, present.len(), hlen, &opts.bits_policy) {
                        HintSpec::None => None,
                        HintSpec::Block { bits } => Some(hint_tag_block(bits)),
                        HintSpec::Hull { bits } => Some(hint_tag_hull(bits)),
                    }
                } else {
                    None
                };
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

    /// Rows relaid to `layout` (fields matched by type, zeros when the
    /// document lacks the field): the deduplicated records when the
    /// document has records, else the present values of its single field
    /// as `[1] ++ value` rows.
    pub fn op_rows(&self, layout: &[FieldDescriptor]) -> BTreeSet<Vec<u8>> {
        let records: Vec<Vec<Option<Vec<u8>>>> = if self.opts.with_records {
            self.records.clone()
        } else {
            assert_eq!(
                self.fields.len(),
                1,
                "a hashes-only document has a single field"
            );
            self.records
                .iter()
                .filter(|r| r[0].is_some())
                .cloned()
                .collect()
        };
        records
            .iter()
            .map(|r| {
                let mut row = Vec::new();
                for d in layout {
                    let v = self
                        .fields
                        .iter()
                        .position(|f| f.htype == d.htype)
                        .and_then(|i| r[i].as_ref());
                    match v {
                        Some(v) => {
                            row.push(1);
                            row.extend_from_slice(v);
                        }
                        None => row.resize(row.len() + d.stride(), 0),
                    }
                }
                row
            })
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
        assert_eq!(md5.ridx, Some(vec![2, 3]));
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
        assert_eq!(md5.record_index(0), Some(2));
        assert_eq!(md5.record_index(1), Some(3));
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
    fn op_rows_relayout_and_wrap() {
        let doc = two_field_doc();
        let size_d = Field::canonical(HashType::Size).descriptor();
        let md5_d = Field::canonical(HashType::Md5).descriptor();
        let rows = doc.op_rows(&[size_d, md5_d]);
        assert_eq!(rows.len(), 4);
        let relaid = |m: Option<[u8; 16]>, s: Option<u64>| {
            let r = row(m, s);
            [&r[17..], &r[..17]].concat()
        };
        let want: BTreeSet<Vec<u8>> = [
            relaid(None, None),
            relaid(None, Some(7)),
            relaid(Some(MD5), Some(10)),
            relaid(Some(MD5), Some(20)),
        ]
        .into_iter()
        .collect();
        assert!(rows.iter().all(|r| r.len() == 9 + 17));
        assert_eq!(rows, want);

        let a = vec![0xaa; 20];
        let b = vec![0x01; 20];
        let mut opts = Opts::default_for_tests();
        opts.with_records = false;
        let one = Doc {
            fields: vec![Field::canonical(HashType::Sha1)],
            records: vec![
                vec![Some(a.clone())],
                vec![None],
                vec![Some(b.clone())],
                vec![Some(a.clone())],
            ],
            opts,
        };
        let layout = one.descriptors();
        let want: BTreeSet<Vec<u8>> = [[&[1][..], &a].concat(), [&[1][..], &b].concat()]
            .into_iter()
            .collect();
        assert_eq!(one.op_rows(&layout), want);
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
}
