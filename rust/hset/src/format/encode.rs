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
    /// The payload of a TLSH section's `TIVF` index, written after
    /// `RIDX` (see [`crate::tlsh::ivf`]).
    pub tivf: Option<&'a [u8]>,
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
        // Refuse what the decoder would reject.
        if h.tivf.is_some() && h.htype != HashType::Tlsh {
            return Err(Error::input(format!(
                "the {} hash set cannot have a TIVF index; only TLSH sections can",
                h.htype
            )));
        }
        if let Some((HINT_TLSH_CELLS, table)) = h.hint {
            let header = HashsetHeader {
                htype: h.htype,
                name: h.name.to_string(),
                hash_length: h.hash_length as u64,
                hash_count: (h.data.len() / h.hash_length) as u64,
            };
            super::decode::check_cell_hint(&header, table).map_err(Error::Input)?;
        }
    }

    let chunk_count = 1 // FTOC
        + 1 // FHDR
        + if doc.records.is_some() { 2 } else { 0 }
        + doc
            .hashsets
            .iter()
            .map(|h| {
                2 + usize::from(h.hint.is_some())
                    + usize::from(h.ridx.is_some())
                    + usize::from(h.tivf.is_some())
            })
            .sum::<usize>()
        + 1; // FEND

    let data_bytes: usize = doc.records.map_or(0, |r| r.data.len())
        + doc
            .hashsets
            .iter()
            .map(|h| {
                h.data.len()
                    + h.ridx.map_or(0, <[u8]>::len)
                    + h.tivf.map_or(0, <[u8]>::len)
                    + h.hint.map_or(0, |(_, t)| t.len())
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

        // HDAT [RIDX] [TIVF], unpadded, as hset_encoder.cpp lays them out.
        if let Some(t) = h.tivf {
            let off = out.chunk(chunk::TIVF, |w| w.bytes(t));
            toc.push((off as u64, chunk::TIVF));
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
                tivf: None,
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
                tivf: None,
            }],
        };
        assert!(encode(&doc).is_err());
    }

    #[test]
    fn short_hashes_with_a_record_index_encode() {
        // A 4-byte hash has a larger record index (8 bytes) than hash data.
        let doc = Document {
            version: 2,
            name: "",
            desc: "",
            time: "",
            records: None,
            hashsets: vec![HashsetIn {
                htype: HashType::Md5,
                name: "short",
                hash_length: 4,
                data: &[1, 2, 3, 4],
                hint: None,
                ridx: Some(&[0; 8]),
                tivf: None,
            }],
        };
        let bytes = encode(&doc).unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.sections.len(), 1);
        assert_eq!(f.sections[0].hash_length(), 4);
        assert_eq!(f.sections[0].hash(0), &[1, 2, 3, 4]);
        assert_eq!(f.sections[0].record_index(0), Some(0));
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

    /// Five sorted TLSH rows in cells 0x0000, 0x0000, 0x0102, 0x0102, 0xFFFF.
    fn tlsh_rows() -> Vec<u8> {
        let mut rows = vec![0u8; 5 * 36];
        rows[36 * 2..36 * 2 + 2].copy_from_slice(&[1, 2]);
        rows[36 * 3..36 * 3 + 2].copy_from_slice(&[1, 2]);
        rows[36 * 3 + 34] = 1;
        rows[36 * 4..36 * 4 + 2].copy_from_slice(&[0xff, 0xff]);
        rows
    }

    fn tlsh_cell_table(rows: &[u8]) -> Vec<u8> {
        use crate::tlsh::cells::{cell_index, cell_table};
        cell_table(&cell_index(rows.as_chunks::<36>().0).unwrap())
    }

    fn tlsh_doc<'a>(
        rows: &'a [u8],
        table: &'a [u8],
        ridx: Option<&'a [u8]>,
        tivf: Option<&'a [u8]>,
    ) -> Document<'a> {
        Document {
            version: FORMAT_VERSION,
            name: "",
            desc: "",
            time: "",
            records: None,
            hashsets: vec![HashsetIn {
                htype: HashType::Tlsh,
                name: "tlsh",
                hash_length: 36,
                data: rows,
                hint: Some((0x7400, table)),
                ridx,
                tivf,
            }],
        }
    }

    fn tags(f: &HsetFile<'_>) -> Vec<u32> {
        f.toc.iter().map(|&(_, t)| t).collect()
    }

    #[test]
    fn a_tlsh_section_round_trips_its_cell_hint_record_index_and_tivf() {
        let rows = tlsh_rows();
        let table = tlsh_cell_table(&rows);
        let ridx: Vec<u8> = (0..5u64).rev().flat_map(u64::to_le_bytes).collect();
        let tivf = b"thirteen byte";
        let bytes = encode(&tlsh_doc(&rows, &table, Some(&ridx), Some(tivf))).unwrap();
        let f = decode(&bytes).unwrap();
        let s = &f.sections[0];
        assert_eq!(s.header.htype, HashType::Tlsh);
        assert_eq!(s.data, &rows[..]);
        assert!(matches!(s.hint, Some(Hint::TlshCells { table: t }) if t == &table[..]));
        assert_eq!(s.ridx, Some(&ridx[..]));
        assert_eq!(s.tivf, Some(&tivf[..]));
        use chunk::*;
        assert_eq!(
            tags(&f),
            [FTOC, FHDR, HHDR | 15, HINT, HDAT, RIDX, TIVF, FEND]
        );
        // The HINT is the tag and 65,537 offsets (test_hset_tlsh.cpp
        // `length_hint_tlsh`: 2 + 65537 * 8 data bytes).
        let hint = read_chunk(&bytes, f.toc[3].0 as usize).unwrap();
        assert_eq!(hint.data.len(), 524298);
        assert_eq!(&hint.data[..2], &[0x74, 0x00]);
        // TIVF follows RIDX with no padding.
        let (ridx_off, tivf_off) = (f.toc[5].0, f.toc[6].0);
        assert_eq!(tivf_off, ridx_off + 12 + 40);
        assert_eq!(read_chunk(&bytes, tivf_off as usize).unwrap().data, tivf);
    }

    #[test]
    fn without_a_record_index_tivf_follows_hdat() {
        let rows = tlsh_rows();
        let table = tlsh_cell_table(&rows);
        let tivf = [7u8; 4];
        let bytes = encode(&tlsh_doc(&rows, &table, None, Some(&tivf))).unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.sections[0].tivf, Some(&tivf[..]));
        assert_eq!(f.sections[0].ridx, None);
        use chunk::*;
        assert_eq!(tags(&f), [FTOC, FHDR, HHDR | 15, HINT, HDAT, TIVF, FEND]);
        assert_eq!(f.toc[5].0, f.toc[4].0 + 12 + rows.len() as u64);
    }

    fn input_err(doc: &Document<'_>) -> String {
        match encode(doc) {
            Err(e @ Error::Input(_)) => e.to_string(),
            other => panic!("expected an input error, got {:?}", other.map(|b| b.len())),
        }
    }

    #[test]
    fn tivf_outside_a_tlsh_section_is_refused() {
        let mut doc = tlsh_doc(&[0; 16], &[], None, Some(b"x"));
        doc.hashsets[0].htype = HashType::Md5;
        doc.hashsets[0].hash_length = 16;
        doc.hashsets[0].hint = None;
        let e = input_err(&doc);
        assert!(e.contains("MD5 hash set cannot have a TIVF index"), "{e}");
    }

    #[test]
    fn a_cell_hint_outside_a_36_byte_tlsh_section_is_refused() {
        let rows = [0u8; 32];
        let table = tlsh_cell_table(&[0; 36 * 2]);
        let mut doc = tlsh_doc(&rows, &table, None, None);
        doc.hashsets[0].htype = HashType::Md5;
        doc.hashsets[0].hash_length = 16;
        let e = input_err(&doc);
        assert!(
            e.contains("TLSH cell index hint on the MD5 hash set"),
            "{e}"
        );
    }

    #[test]
    fn a_cell_hint_that_does_not_index_the_rows_is_refused() {
        let rows = tlsh_rows();
        let table = tlsh_cell_table(&rows[..36 * 4]);
        let e = input_err(&tlsh_doc(&rows, &table, None, None));
        assert!(e.contains("last offset is 4, expected 5"), "{e}");
    }
}
