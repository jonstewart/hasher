//! A loaded `.hset`: decoded structure plus lookup strategies.

use std::ops::Range;

use crate::error::Result;
use crate::format::{self, FieldDescriptor, HsetFile, RecordHeader, Section};
use crate::hash_type::HashType;
use crate::lookup::{self, Lookup, SearchConfig};

/// A decoded hash set file ready for queries. Borrows the file bytes.
pub struct Hashset<'a> {
    raw: &'a [u8],
    file: HsetFile<'a>,
    lookups: Vec<Box<dyn Lookup + 'a>>,
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
        Ok(Hashset {
            raw: buf,
            file,
            lookups,
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

    /// Check structural invariants: digest, sortedness, hint soundness.
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
}
