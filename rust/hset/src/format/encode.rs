//! Writing an `.hset` file from already-sorted, already-indexed inputs.
//!
//! This is the low-level layer; [`crate::Builder`] prepares the inputs.

use sha2::{Digest, Sha256};

use super::chunk::{self, Out};
use super::structs::*;
use crate::error::{Error, Result};
use crate::hash_type::HashType;

/// Sorted, de-duplicated records to write as `RHDR` + `RDAT`.
#[derive(Debug, Clone, Copy)]
pub struct RecordsIn<'a> {
    pub fields: &'a [FieldDescriptor],
    pub record_length: usize,
    /// `record_count * record_length` bytes.
    pub data: &'a [u8],
}

/// One hash set section to write.
#[derive(Debug, Clone, Copy)]
pub struct HashsetIn<'a> {
    pub htype: HashType,
    pub name: &'a str,
    pub hash_length: usize,
    /// `hash_count * hash_length` bytes, sorted.
    pub data: &'a [u8],
    /// `(hint tag, table bytes)`.
    pub hint: Option<(u16, &'a [u8])>,
    /// `hash_count` little-endian `u64` record indices.
    pub ridx: Option<&'a [u8]>,
}

/// Everything needed to write a file.
#[derive(Debug, Clone)]
pub struct Document<'a> {
    pub version: u64,
    pub name: &'a str,
    pub desc: &'a str,
    /// ISO-8601 UTC timestamp, e.g. `2023-01-09T17:02:18Z`.
    pub time: &'a str,
    pub records: Option<RecordsIn<'a>>,
    pub hashsets: Vec<HashsetIn<'a>>,
}

fn check_pstring(s: &str, what: &str) -> Result<()> {
    if s.len() > usize::from(u16::MAX) {
        return Err(Error::input(format!(
            "{what} is too long, maximum length is 65535 bytes"
        )));
    }
    Ok(())
}

/// Serialize `doc` into a complete `.hset` file image, digest included.
pub fn encode(doc: &Document<'_>) -> Result<Vec<u8>> {
    check_pstring(doc.name, "hash set name")?;
    check_pstring(doc.desc, "hash set description")?;
    check_pstring(doc.time, "timestamp")?;

    if let Some(r) = &doc.records {
        if r.record_length == 0 || r.data.len() % r.record_length != 0 {
            return Err(Error::input("record data is not a whole number of records"));
        }
        for f in r.fields {
            check_pstring(&f.name, "field name")?;
        }
    }
    for h in &doc.hashsets {
        check_pstring(h.name, "hash set field name")?;
        if h.hash_length == 0 || h.data.len() % h.hash_length != 0 {
            return Err(Error::input(format!(
                "{} hash data is not a whole number of hashes",
                h.htype
            )));
        }
        if let Some(r) = h.ridx
            && r.len() != (h.data.len() / h.hash_length) * 8
        {
            return Err(Error::input(format!(
                "{} record index does not match hash count",
                h.htype
            )));
        }
    }

    let chunk_count = 1 // FTOC
        + 1 // FHDR
        + if doc.records.is_some() { 2 } else { 0 }
        + doc
            .hashsets
            .iter()
            .map(|h| 2 + usize::from(h.hint.is_some()) + usize::from(h.ridx.is_some()))
            .sum::<usize>()
        + 1; // FEND

    let data_bytes: usize = doc.records.map_or(0, |r| r.data.len())
        + doc
            .hashsets
            .iter()
            .map(|h| {
                h.data.len() + h.ridx.map_or(0, <[u8]>::len) + h.hint.map_or(0, |(_, t)| t.len())
            })
            .sum::<usize>();
    let mut out =
        Out::with_capacity(data_bytes + chunk::HDAT_ALIGN * (doc.hashsets.len() + 1) + 4096);
    let mut toc: Vec<(u64, u32)> = Vec::with_capacity(chunk_count);

    out.bytes(chunk::MAGIC);
    out.zeros(32); // digest, patched below

    // FTOC placeholder, patched at the end.
    let ftoc_off = out.chunk(chunk::FTOC, |w| w.zeros(12 * chunk_count));
    toc.push((ftoc_off as u64, chunk::FTOC));

    let off = out.chunk(chunk::FHDR, |w| {
        w.le_u64(doc.version);
        w.pstring(doc.name);
        w.pstring(doc.time);
        w.pstring(doc.desc);
    });
    toc.push((off as u64, chunk::FHDR));

    if let Some(r) = &doc.records {
        let count = (r.data.len() / r.record_length) as u64;
        let off = out.chunk(chunk::RHDR, |w| {
            w.le_u64(r.record_length as u64);
            w.le_u64(count);
            for f in r.fields {
                w.le_u16(f.htype.log2());
                w.pstring(&f.name);
                w.le_u64(f.length);
            }
        });
        toc.push((off as u64, chunk::RHDR));
        let off = out.chunk(chunk::RDAT, |w| w.bytes(r.data));
        toc.push((off as u64, chunk::RDAT));
    }

    for h in &doc.hashsets {
        let count = (h.data.len() / h.hash_length) as u64;
        let tag = chunk::HHDR | u32::from(h.htype.log2());
        let off = out.chunk(tag, |w| {
            w.pstring(h.name);
            w.le_u64(h.hash_length as u64);
            w.le_u64(count);
        });
        toc.push((off as u64, tag));

        if let Some((hint_tag, table)) = h.hint {
            let off = out.chunk(chunk::HINT, |w| {
                w.be_u16(hint_tag);
                w.bytes(table);
            });
            toc.push((off as u64, chunk::HINT));
        }

        out.align(chunk::HDAT_ALIGN);
        let off = out.chunk(chunk::HDAT, |w| w.bytes(h.data));
        toc.push((off as u64, chunk::HDAT));

        if let Some(r) = h.ridx {
            let off = out.chunk(chunk::RIDX, |w| w.bytes(r));
            toc.push((off as u64, chunk::RIDX));
        }
    }

    let off = out.chunk(chunk::FEND, |_| {});
    toc.push((off as u64, chunk::FEND));
    debug_assert_eq!(toc.len(), chunk_count);

    // Patch the FTOC.
    let mut p = ftoc_off + chunk::CHUNK_HEADER_LEN;
    for &(o, t) in &toc {
        out.buf[p..p + 8].copy_from_slice(&o.to_le_bytes());
        out.buf[p + 8..p + 12].copy_from_slice(&t.to_be_bytes());
        p += 12;
    }

    // Digest everything after the digest field.
    let digest = Sha256::digest(&out.buf[chunk::FIRST_CHUNK_OFFSET..]);
    out.buf[chunk::SHA_OFFSET..chunk::FIRST_CHUNK_OFFSET].copy_from_slice(&digest);

    Ok(out.buf)
}

/// Compute the digest a file's header should carry.
pub fn file_digest(buf: &[u8]) -> Option<[u8; 32]> {
    let body = buf.get(chunk::FIRST_CHUNK_OFFSET..)?;
    Some(Sha256::digest(body).into())
}

#[cfg(test)]
mod tests {
    use super::super::decode;
    use super::*;

    #[test]
    fn minimal_roundtrip() {
        let hashes: Vec<u8> = (0u8..40).collect(); // two 20-byte "hashes"
        let doc = Document {
            version: FORMAT_VERSION,
            name: "n",
            desc: "d",
            time: "2020-01-01T00:00:00Z",
            records: None,
            hashsets: vec![HashsetIn {
                htype: HashType::Sha1,
                name: "sha1",
                hash_length: 20,
                data: &hashes,
                hint: None,
                ridx: None,
            }],
        };
        let bytes = encode(&doc).unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.fhdr.name, "n");
        assert_eq!(f.fhdr.desc, "d");
        assert_eq!(f.fhdr.time, "2020-01-01T00:00:00Z");
        assert_eq!(f.fhdr.version, FORMAT_VERSION);
        assert_eq!(f.fhdr.sha2_256, file_digest(&bytes).unwrap());
        assert_eq!(f.sections.len(), 1);
        assert_eq!(f.sections[0].len(), 2);
        assert_eq!(f.sections[0].hash(1), &hashes[20..]);
        assert!(f.rhdr.is_none());
        // HDAT chunk header is page aligned
        let hdat = f.toc.iter().find(|(_, t)| *t == chunk::HDAT).unwrap();
        assert_eq!(hdat.0 % chunk::HDAT_ALIGN as u64, 0);
    }

    #[test]
    fn rejects_overlong_strings() {
        let long = "x".repeat(65536);
        let doc = Document {
            version: 2,
            name: &long,
            desc: "",
            time: "",
            records: None,
            hashsets: vec![],
        };
        assert!(matches!(encode(&doc), Err(Error::Input(_))));
    }

    #[test]
    fn rejects_ragged_data() {
        let doc = Document {
            version: 2,
            name: "",
            desc: "",
            time: "",
            records: None,
            hashsets: vec![HashsetIn {
                htype: HashType::Md5,
                name: "md5",
                hash_length: 16,
                data: &[0u8; 17],
                hint: None,
                ridx: None,
            }],
        };
        assert!(encode(&doc).is_err());
    }

    #[test]
    fn rejects_ragged_or_zero_length_records() {
        let fields = [FieldDescriptor::for_type(HashType::Md5).unwrap()];
        for (record_length, data) in [(17, &[0u8; 18][..]), (0, &[][..])] {
            let doc = Document {
                version: 2,
                name: "",
                desc: "",
                time: "",
                records: Some(RecordsIn {
                    fields: &fields,
                    record_length,
                    data,
                }),
                hashsets: vec![],
            };
            assert!(
                matches!(encode(&doc), Err(Error::Input(_))),
                "record length {record_length}"
            );
        }
    }
}
